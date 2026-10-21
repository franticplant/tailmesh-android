// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.multiproxy

import android.content.Intent
import android.os.Build
import com.tailscale.ipn.IPNService
import com.tailscale.ipn.MultiProxySession
import com.tailscale.ipn.multiproxy.db.ProvisioningState
import com.tailscale.ipn.multiproxy.db.Upstream
import com.tailscale.ipn.multiproxy.db.UpstreamKind
import com.tailscale.ipn.ui.viewModel.ExitNodeCandidate
import com.tailscale.ipn.ui.viewModel.RoutableUpstream
import com.tailscale.ipn.util.TSLog
import java.util.UUID
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import libtailscale.Libtailscale
import org.json.JSONArray
import org.json.JSONObject

/** A user-facing validation failure: the message is meant to be shown as-is. */
class ControlException(message: String) : IllegalArgumentException(message)

/**
 * The Multi-Tailnet configuration actions, independent of any screen.
 *
 * The upstream, routing and listener screens and the remote-control API (see
 * [com.tailscale.ipn.remote.RemoteMethods]) both call these, so a change made remotely goes through
 * exactly the path the same tap in the UI does - same validation, same persistence order, same live
 * apply - and the two can never disagree. Each action either completes or throws [ControlException]
 * with a message fit for the user.
 */
class MultiProxyControls(private val session: MultiProxySession) {
  private val upstreamRepository = session.upstreamRepository
  private val bindingRepository = session.appBindingRepository
  private val secrets = session.upstreamSecretStore
  private val settings = session.routingSettings

  // ---------------------------------------------------------------------------
  // upstreams
  // ---------------------------------------------------------------------------

  /**
   * Saves a SOCKS5 upstream; [id] null creates one. Returns its id.
   *
   * The address is checked here rather than only in Go, so a typo is reported while the user is
   * still looking at the field they typed it into.
   */
  suspend fun saveSocks5(
      id: String?,
      label: String,
      address: String,
      username: String,
      password: String,
      via: String,
  ): String {
    if (!isHostPort(address)) {
      throw ControlException("Address must be host:port, for example 127.0.0.1:10808")
    }
    val config =
        JSONObject()
            .put("address", address.trim())
            .put("username", username)
            .put("password", password)
            .toString()
    return save(id, UpstreamKind.SOCKS5, label, via, config)
  }

  /**
   * Saves a WireGuard upstream; [id] null creates one. Returns its id.
   *
   * The text may be either a wg-quick `.conf`, which is what a provider hands out, or the JSON form
   * directly. Which one it is is decided by looking at it rather than by asking, because a user
   * pasting a config should not have to know or care that the two forms exist.
   */
  suspend fun saveWireGuard(id: String?, label: String, config: String, via: String): String {
    val text = config.trim()
    if (text.isEmpty()) throw ControlException("A WireGuard configuration is required")

    val json =
        if (text.startsWith("{")) {
          try {
            JSONObject(text)
            text
          } catch (e: Exception) {
            throw ControlException("That is not valid JSON: ${e.message}")
          }
        } else {
          try {
            Libtailscale.multiProxyWireGuardConfigFromQuick(text)
          } catch (e: Exception) {
            throw ControlException(e.message ?: "That is not a usable WireGuard configuration")
          }
        }
    return save(id, UpstreamKind.WIREGUARD, label, via, json)
  }

  /**
   * Adds an exit-node upstream: a dedicated node identity, logged into [sourceTailnetId] with its
   * own [authKey], pinned to route through [peerAddr] (a peer from [exitNodeCandidates] for that
   * tailnet). This costs a real device slot in that tailnet's admin console - it is not a free
   * operation the way picking a tailnet's own exit node in place is (see [setTailnetExitNode]).
   *
   * Only adding is supported, not editing: the peer and the node identity are set together at
   * creation, and changing either is a new upstream (delete and re-add) rather than a mutation of a
   * live node identity. Returns the new id.
   */
  suspend fun saveExitNode(
      label: String,
      sourceTailnetId: String,
      authKey: String,
      peerAddr: String,
  ): String {
    if (sourceTailnetId.isBlank()) {
      throw ControlException("Choose which tailnet to pick an exit node from")
    }
    if (peerAddr.isBlank()) throw ControlException("Choose an exit node peer")
    if (authKey.isBlank()) {
      throw ControlException("An auth key is required for the exit node's own device identity")
    }
    // Checked here, not just left to the engine's own maxExitNodeUpstreams
    // rejection (upstream_exitnode.go): UpstreamPolicyApplier.register()
    // only logs an engine-side registration failure, so without this check
    // hitting the cap would silently save a row that can never come up.
    val exitNodeCount =
        upstreamRepository.upstreams.value.count { it.kind == UpstreamKind.EXITNODE }
    if (exitNodeCount >= MAX_EXIT_NODE_UPSTREAMS) {
      throw ControlException(
          "At most $MAX_EXIT_NODE_UPSTREAMS exit-node upstreams may be configured at once " +
              "(each is its own device identity). Delete one to add another.")
    }
    val upstreamId = "upstream-${UUID.randomUUID()}"
    val config = JSONObject().put("authKey", authKey).toString()
    withContext(Dispatchers.IO) { secrets.saveConfig(upstreamId, config) }
    upstreamRepository.save(
        Upstream(
            id = upstreamId,
            kind = UpstreamKind.EXITNODE,
            label = label.ifBlank { upstreamId },
            sourceTailnetId = sourceTailnetId,
            peerAddr = peerAddr,
        ))
    applyNow()
    return upstreamId
  }

  private suspend fun save(
      id: String?,
      kind: UpstreamKind,
      label: String,
      via: String,
      configJson: String,
  ): String {
    val upstreamId = id ?: "upstream-${UUID.randomUUID()}"
    if (via == upstreamId) throw ControlException("An upstream cannot be chained through itself")
    // The config is written first: a row with no configuration is skipped at
    // registration with a complaint, whereas an orphaned config is harmless.
    withContext(Dispatchers.IO) { secrets.saveConfig(upstreamId, configJson) }
    // saveConfig (not save) so enabled/createdAt are preserved via a fresh DB read
    // inside its own transaction, not a stale in-memory snapshot - see its doc
    // comment for why that matters when a setUpstreamEnabled() call races this edit.
    upstreamRepository.saveConfig(upstreamId, kind, label, via)
    applyNow()
    return upstreamId
  }

  suspend fun setUpstreamEnabled(id: String, enabled: Boolean) {
    requireUpstream(id)
    upstreamRepository.setEnabled(id, enabled)
    applyNow()
  }

  suspend fun deleteUpstream(id: String) {
    requireUpstream(id)
    upstreamRepository.delete(id)
    withContext(Dispatchers.IO) { secrets.deleteConfig(id) }
    if (settings.defaultUpstreamId == id) settings.defaultUpstreamId = ""
    if (settings.defaultDNSUpstreamId == id) settings.defaultDNSUpstreamId = ""
    applyNow()
  }

  private fun requireUpstream(id: String) {
    if (upstreamRepository.upstreams.value.none { it.id == id }) {
      throw ControlException("No upstream with id $id")
    }
  }

  /** The stored configuration of an upstream, for prefilling an edit form. Contains secrets. */
  fun configFor(id: String): String? = secrets.getConfig(id)

  /**
   * Lists the peers of an already-running tailnet that offer to be an exit node. Empty if the
   * tailnet is not configured or not currently connected.
   */
  fun exitNodeCandidates(tailnetId: String): List<ExitNodeCandidate> {
    val json =
        try {
          session.engine?.getExitNodeCandidatesJSON(tailnetId) ?: "[]"
        } catch (e: Exception) {
          TSLog.e(TAG, "could not fetch exit node candidates: $e")
          "[]"
        }
    return try {
      val arr = JSONArray(json)
      (0 until arr.length()).map { i ->
        val o = arr.getJSONObject(i)
        ExitNodeCandidate(
            id = o.optString("id"),
            hostname = o.optString("hostname"),
            dnsName = o.optString("dnsName"),
            ip = o.optString("ip"),
        )
      }
    } catch (e: Exception) {
      emptyList()
    }
  }

  /**
   * Points an already-running tailnet's own general internet traffic at one of its peers, using
   * that tailnet's existing node identity - no extra auth, no extra device slot. An empty
   * [peerAddr] clears it.
   */
  suspend fun setTailnetExitNode(tailnetId: String, peerAddr: String) {
    val engine = session.engine ?: throw ControlException("Multi-Tailnet mode is not running")
    withContext(Dispatchers.IO) {
      try {
        engine.setTailnetExitNode(tailnetId, peerAddr)
      } catch (e: Exception) {
        throw ControlException(e.message ?: "Could not set exit node")
      }
    }
  }

  // ---------------------------------------------------------------------------
  // routing choices
  // ---------------------------------------------------------------------------

  /**
   * Everything a rule can route to: ready Tailnets, configured upstreams, and the direct bypass.
   */
  fun routableUpstreams(): List<RoutableUpstream> = buildList {
    add(RoutableUpstream(DIRECT_UPSTREAM_ID, "Direct (bypass the VPN)", "direct", true))
    session.profileRepository.profiles.value
        .filter { it.provisioningState == ProvisioningState.READY }
        .forEach { add(RoutableUpstream(it.id, it.displayName, "tailnet", it.enabled)) }
    upstreamRepository.upstreams.value.forEach {
      add(RoutableUpstream(it.id, it.label, it.kind.name.lowercase(), it.enabled))
    }
  }

  /** The upstream for apps with no binding of their own; empty leaves them on today's route. */
  suspend fun setDefaultUpstream(id: String) {
    settings.defaultUpstreamId = id
    applyNow()
  }

  /**
   * Splits where default-route DNS goes from where default-route data goes. A policy-only change,
   * like [setLanExclusionEnabled] - takes effect with no VPN restart.
   */
  suspend fun setDefaultDNSUpstream(id: String) {
    settings.defaultDNSUpstreamId = id
    applyNow()
  }

  /**
   * Turns broad VPN capture on or off. This changes what the VPN's TUN itself captures
   * (IPNService.kt's rebuildMultiProxyTunLocked), so it restarts the VPN when it is running.
   */
  fun setBroadCaptureEnabled(enabled: Boolean) {
    settings.broadCaptureEnabled = enabled
    if (session.engine != null) restartVpn()
  }

  /**
   * Turns the LAN-stays-direct default rule on or off. With broad capture on Android 13+ it is also
   * a set of excluded VPN routes (IPNService.kt's rebuildMultiProxyTunLocked), so then the VPN
   * restarts to apply it; otherwise it is a policy change applied live.
   */
  suspend fun setLanExclusionEnabled(enabled: Boolean) {
    val changed = settings.lanExclusionEnabled != enabled
    settings.lanExclusionEnabled = enabled
    applyNow()
    if (changed &&
        settings.broadCaptureEnabled &&
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
        session.engine != null) {
      restartVpn()
    }
  }

  suspend fun bindApp(packageName: String, upstreamId: String) {
    bindingRepository.bind(packageName, upstreamId)
    applyNow()
  }

  suspend fun unbindApp(packageName: String) {
    bindingRepository.unbind(packageName)
    applyNow()
  }

  /**
   * Sets (or, with an empty id, clears) one app's DNS override, independent of its data route. Only
   * takes effect once the app also has a non-empty upstream binding - see
   * AppBindingRepository.setDNSUpstream's doc comment.
   */
  suspend fun setAppDNSUpstream(packageName: String, dnsUpstreamId: String) {
    bindingRepository.setDNSUpstream(packageName, dnsUpstreamId)
    applyNow()
  }

  /**
   * Sets whether this app's LAN-destined traffic keeps following its own data route even while
   * "Keep LAN traffic direct" is on globally. Only takes effect once the app also has a non-empty
   * upstream binding.
   */
  suspend fun setAppTunnelLAN(packageName: String, tunnelLan: Boolean) {
    bindingRepository.setTunnelLAN(packageName, tunnelLan)
    applyNow()
  }

  // ---------------------------------------------------------------------------
  // SOCKS5 listeners
  // ---------------------------------------------------------------------------

  /**
   * Saves an inbound SOCKS5 listener; [id] null creates one. Empty [username]/[password] means no
   * RFC 1929 auth is required to connect to it. Returns its id.
   */
  suspend fun saveSocks5Listener(
      id: String?,
      bindAddr: String,
      port: String,
      upstream: String,
      username: String,
      password: String,
  ): String {
    val trimmedBindAddr = bindAddr.trim().ifEmpty { "127.0.0.1" }
    val portNum = port.trim().toIntOrNull()
    if (portNum == null || portNum !in 1..65535) {
      throw ControlException("Port must be a number from 1 to 65535")
    }
    if (upstream.isBlank()) throw ControlException("Choose which upstream this listener hands out")
    val listenerId = id ?: "listener-${UUID.randomUUID()}"
    val hasAuth = username.isNotEmpty() || password.isNotEmpty()
    withContext(Dispatchers.IO) {
      if (hasAuth) {
        val auth = JSONObject().put("username", username).put("password", password).toString()
        secrets.saveListenerAuth(listenerId, auth)
      } else {
        secrets.deleteListenerAuth(listenerId)
      }
    }
    session.socks5ListenerRepository.saveConfig(
        listenerId,
        trimmedBindAddr,
        portNum,
        upstream,
        hasAuth,
    )
    applyNow()
    return listenerId
  }

  suspend fun setSocks5ListenerEnabled(id: String, enabled: Boolean) {
    session.socks5ListenerRepository.setEnabled(id, enabled)
    applyNow()
  }

  suspend fun deleteSocks5Listener(id: String) {
    session.socks5ListenerRepository.delete(id)
    withContext(Dispatchers.IO) { secrets.deleteListenerAuth(id) }
    applyNow()
  }

  /** The stored username/password of a SOCKS5 listener, or null if it has none. */
  fun socks5ListenerAuth(id: String): Pair<String, String>? {
    val json = secrets.getListenerAuth(id) ?: return null
    return try {
      val obj = JSONObject(json)
      Pair(obj.optString("username"), obj.optString("password"))
    } catch (e: Exception) {
      null
    }
  }

  // ---------------------------------------------------------------------------
  // Tailnet-facing inbound listeners
  // ---------------------------------------------------------------------------

  /** Saves a tailnet-facing inbound listener; [id] null creates one. Returns its id. */
  suspend fun saveInboundListener(
      id: String?,
      upstream: String,
      listenPort: String,
      localTarget: String,
      proxyProtocol: Boolean,
  ): String {
    val portNum =
        InboundListenerRules.parseListenPort(listenPort)
            ?: throw ControlException("Port must be a number from 1 to 65535")
    if (upstream.isBlank()) throw ControlException("Choose which tailnet this listener accepts on")
    val target =
        InboundListenerRules.parseLocalTarget(localTarget)
            ?: throw ControlException("Local target must be host:port, e.g. 127.0.0.1:22")
    val listenerId = id ?: "inbound-${UUID.randomUUID()}"
    session.inboundListenerRepository.saveConfig(
        listenerId,
        upstream,
        portNum,
        target,
        proxyProtocol,
    )
    applyNow()
    return listenerId
  }

  suspend fun setInboundListenerEnabled(id: String, enabled: Boolean) {
    session.inboundListenerRepository.setEnabled(id, enabled)
    applyNow()
  }

  suspend fun deleteInboundListener(id: String) {
    session.inboundListenerRepository.delete(id)
    applyNow()
  }

  // ---------------------------------------------------------------------------

  /** Restarts the VPN so a TUN-level setting takes effect. */
  fun restartVpn() {
    val intent =
        Intent(session.app, IPNService::class.java).setAction(IPNService.ACTION_RESTART_VPN)
    session.app.startService(intent)
  }

  /**
   * Pushes the current configuration into the running engine, if there is one.
   *
   * Upstream registration and policy are both designed to be replaced live, so a routing change
   * takes effect on the next flow rather than needing the VPN restarted. With no engine running
   * this does nothing and the configuration is applied at the next VPN build instead.
   */
  suspend fun applyNow() {
    val engine = session.engine ?: return
    withContext(Dispatchers.IO) {
      try {
        session.upstreamPolicyApplier.apply(engine)
      } catch (e: Exception) {
        TSLog.e(TAG, "could not apply routing configuration: $e")
      }
    }
  }

  private fun isHostPort(value: String): Boolean {
    val trimmed = value.trim()
    val port = trimmed.substringAfterLast(':', "")
    val host = trimmed.substringBeforeLast(':', "")
    return host.isNotEmpty() && (port.toIntOrNull() ?: 0) in 1..65535
  }

  companion object {
    private const val TAG = "MultiProxyControls"

    /** Matches multiproxy.DirectUpstreamID. */
    const val DIRECT_UPSTREAM_ID = "@direct"

    /** Matches multiproxy.maxExitNodeUpstreams (upstream_exitnode.go). */
    const val MAX_EXIT_NODE_UPSTREAMS = 8
  }
}
