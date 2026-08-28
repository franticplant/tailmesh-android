// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.viewModel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.tailscale.ipn.App
import com.tailscale.ipn.multiproxy.db.AppBinding
import com.tailscale.ipn.multiproxy.db.ProvisioningState
import com.tailscale.ipn.multiproxy.db.Upstream
import com.tailscale.ipn.multiproxy.db.UpstreamKind
import com.tailscale.ipn.util.TSLog
import java.util.UUID
import libtailscale.Libtailscale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * One entry a routing choice can point at.
 *
 * The three sources are deliberately flattened into one list, because to the user they are the same
 * kind of decision - "where does this app's traffic go" - even though a Tailnet, a proxy, and the
 * direct bypass have nothing in common underneath.
 */
data class RoutableUpstream(
    val id: String,
    val label: String,
    /** One of `tailnet`, `socks5`, `wireguard`, `exitnode`, `direct`. */
    val kind: String,
    val enabled: Boolean,
)

/** One peer of some tailnet that offers to be an exit node. See [UpstreamRoutingViewModel.fetchExitNodeCandidates]. */
data class ExitNodeCandidate(
    val id: String,
    val hostname: String,
    val dnsName: String,
    val ip: String,
)

/**
 * Backs both the upstream list and the per-app routing screens.
 *
 * They share every repository and would otherwise have to keep two copies of the same state in sync,
 * which is exactly the bug this avoids: a picker offering an upstream the list has just deleted.
 */
class UpstreamRoutingViewModel : ViewModel() {
  private val session = App.get().multiProxySession

  private val upstreamRepository = session.upstreamRepository
  private val bindingRepository = session.appBindingRepository
  private val secrets = session.upstreamSecretStore
  private val settings = session.routingSettings

  /** The user's configured non-Tailnet upstreams. */
  val upstreams: StateFlow<List<Upstream>> = upstreamRepository.upstreams

  /** Package name to its full binding (upstream id and DNS override), for bound apps. */
  val bindings: StateFlow<Map<String, AppBinding>> = bindingRepository.bindings

  val defaultUpstreamId: MutableStateFlow<String> = MutableStateFlow(settings.defaultUpstreamId)

  /** Where DNS goes for apps with no route of their own; empty means "same as the data path". */
  val defaultDNSUpstreamId: MutableStateFlow<String> =
      MutableStateFlow(settings.defaultDNSUpstreamId)

  /** Whether the Multi-Tailnet VPN captures ordinary internet and LAN traffic. Off by default. */
  val broadCaptureEnabled: MutableStateFlow<Boolean> = MutableStateFlow(settings.broadCaptureEnabled)

  /** Whether LAN-destination traffic stays direct regardless of routing. On by default. */
  val lanExclusionEnabled: MutableStateFlow<Boolean> = MutableStateFlow(settings.lanExclusionEnabled)

  /** Surfaces a failed save to the screen that asked for it. */
  val errorMessage: MutableStateFlow<String?> = MutableStateFlow(null)

  /**
   * Everything a rule can route to: ready Tailnets, configured upstreams, and the direct bypass.
   *
   * A disabled entry is still listed, marked not enabled, so the UI can show that an app is bound to
   * something currently switched off. Hiding it would make the binding look lost.
   */
  val routableUpstreams: StateFlow<List<RoutableUpstream>> =
      combine(session.profileRepository.profiles, upstreamRepository.upstreams) {
              profiles,
              configured ->
            buildList {
              add(
                  RoutableUpstream(
                      id = DIRECT_UPSTREAM_ID,
                      label = "Direct (bypass the VPN)",
                      kind = "direct",
                      enabled = true,
                  ))
              profiles
                  .filter { it.provisioningState == ProvisioningState.READY }
                  .forEach {
                    add(
                        RoutableUpstream(
                            id = it.id,
                            label = it.displayName,
                            kind = "tailnet",
                            enabled = it.enabled,
                        ))
                  }
              configured.forEach {
                add(
                    RoutableUpstream(
                        id = it.id,
                        label = it.label,
                        kind = it.kind.name.lowercase(),
                        enabled = it.enabled,
                    ))
              }
            }
          }
          .stateIn(
              scope = viewModelScope,
              started = SharingStarted.WhileSubscribed(5000),
              initialValue = emptyList(),
          )

  // -------------------------------------------------------------------------
  // upstreams
  // -------------------------------------------------------------------------

  /**
   * Saves a SOCKS5 upstream. Pass the id of an existing one to edit it, or null to create.
   *
   * The address is checked here rather than only in Go, so a typo is reported while the user is
   * still looking at the field they typed it into.
   */
  fun saveSocks5(
      id: String?,
      label: String,
      address: String,
      username: String,
      password: String,
      via: String,
  ) {
    if (!isHostPort(address)) {
      errorMessage.value = "Address must be host:port, for example 127.0.0.1:10808"
      return
    }
    val config =
        JSONObject()
            .put("address", address.trim())
            .put("username", username)
            .put("password", password)
            .toString()
    save(id, UpstreamKind.SOCKS5, label, via, config)
  }

  /**
   * Saves a WireGuard upstream.
   *
   * The text may be either a wg-quick `.conf`, which is what a provider hands out, or the JSON form
   * directly. Which one it is is decided by looking at it rather than by asking, because a user
   * pasting a config should not have to know or care that the two forms exist.
   */
  fun saveWireGuard(id: String?, label: String, config: String, via: String) {
    val text = config.trim()
    if (text.isEmpty()) {
      errorMessage.value = "A WireGuard configuration is required"
      return
    }

    val json =
        if (text.startsWith("{")) {
          try {
            JSONObject(text)
            text
          } catch (e: Exception) {
            errorMessage.value = "That is not valid JSON: ${e.message}"
            return
          }
        } else {
          try {
            Libtailscale.multiProxyWireGuardConfigFromQuick(text)
          } catch (e: Exception) {
            errorMessage.value = e.message ?: "That is not a usable WireGuard configuration"
            return
          }
        }

    save(id, UpstreamKind.WIREGUARD, label, via, json)
  }

  /**
   * Adds an exit-node upstream: a dedicated node identity, logged into `sourceTailnetId` with its
   * own `authKey`, pinned to route through `peerAddr` (a peer from
   * [fetchExitNodeCandidates]'s result for that tailnet). This costs a real device slot in that
   * tailnet's admin console - it is not a free operation the way picking a tailnet's own exit node
   * in place is (see [setTailnetExitNode]).
   *
   * Only adding is supported, not editing: the peer and the node identity are set together at
   * creation, and changing either is a new upstream (delete and re-add) rather than a mutation of a
   * live node identity.
   */
  fun saveExitNode(label: String, sourceTailnetId: String, authKey: String, peerAddr: String) {
    if (sourceTailnetId.isBlank()) {
      errorMessage.value = "Choose which tailnet to pick an exit node from"
      return
    }
    if (peerAddr.isBlank()) {
      errorMessage.value = "Choose an exit node peer"
      return
    }
    if (authKey.isBlank()) {
      errorMessage.value = "An auth key is required for the exit node's own device identity"
      return
    }
    // Checked here, not just left to the engine's own maxExitNodeUpstreams
    // rejection (upstream_exitnode.go): UpstreamPolicyApplier.register()
    // only logs an engine-side registration failure, it never reaches
    // errorMessage, so without this check hitting the cap would silently
    // save a row that can never actually come up.
    val exitNodeCount = upstreams.value.count { it.kind == UpstreamKind.EXITNODE }
    if (exitNodeCount >= MAX_EXIT_NODE_UPSTREAMS) {
      errorMessage.value =
          "At most $MAX_EXIT_NODE_UPSTREAMS exit-node upstreams may be configured at once " +
              "(each is its own device identity). Delete one to add another."
      return
    }
    val upstreamId = "upstream-${UUID.randomUUID()}"
    val config = JSONObject().put("authKey", authKey).toString()
    viewModelScope.launch {
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
    }
  }

  /**
   * Lists the peers of an already-running tailnet that offer to be an exit node. Empty if the
   * tailnet named by tailnetId is not configured or not currently connected.
   */
  fun fetchExitNodeCandidates(tailnetId: String): List<ExitNodeCandidate> {
    val json =
        try {
          session.engine?.getExitNodeCandidatesJSON(tailnetId) ?: "[]"
        } catch (e: Exception) {
          TSLog.e("UpstreamRoutingViewModel", "could not fetch exit node candidates: $e")
          "[]"
        }
    return try {
      val arr = org.json.JSONArray(json)
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
   * that tailnet's existing node identity - no extra auth, no extra device slot. Pass an empty
   * peerAddr to clear it. Only one exit node can be active per tailnet this way; for a second,
   * simultaneously-active exit node from the same tailnet, use [saveExitNode] instead.
   */
  fun setTailnetExitNode(tailnetId: String, peerAddr: String) {
    viewModelScope.launch(Dispatchers.IO) {
      try {
        session.engine?.setTailnetExitNode(tailnetId, peerAddr)
      } catch (e: Exception) {
        errorMessage.value = e.message ?: "Could not set exit node"
      }
    }
  }

  private fun save(
      id: String?,
      kind: UpstreamKind,
      label: String,
      via: String,
      configJson: String,
  ) {
    val upstreamId = id ?: "upstream-${UUID.randomUUID()}"
    if (via == upstreamId) {
      errorMessage.value = "An upstream cannot be chained through itself"
      return
    }
    viewModelScope.launch {
      // The config is written first: a row with no configuration is skipped at
      // registration with a complaint, whereas an orphaned config is harmless.
      withContext(Dispatchers.IO) { secrets.saveConfig(upstreamId, configJson) }
      // saveConfig (not save) so enabled/createdAt are preserved via a fresh DB read
      // inside its own transaction, not this stale in-memory snapshot - see its doc
      // comment for why that matters when a setUpstreamEnabled() call races this edit.
      upstreamRepository.saveConfig(upstreamId, kind, label, via)
      applyNow()
    }
  }

  fun setUpstreamEnabled(id: String, enabled: Boolean) {
    viewModelScope.launch {
      upstreamRepository.setEnabled(id, enabled)
      applyNow()
    }
  }

  fun deleteUpstream(id: String) {
    viewModelScope.launch {
      upstreamRepository.delete(id)
      withContext(Dispatchers.IO) { secrets.deleteConfig(id) }
      if (defaultUpstreamId.value == id) setDefaultUpstream("")
      if (defaultDNSUpstreamId.value == id) setDefaultDNSUpstream("")
      applyNow()
    }
  }

  /** Reads back the stored configuration so an edit form can be prefilled. */
  fun configFor(id: String): String? = secrets.getConfig(id)

  // -------------------------------------------------------------------------
  // routing choices
  // -------------------------------------------------------------------------

  /** The upstream for apps with no binding of their own; empty leaves them on today's route. */
  fun setDefaultUpstream(id: String) {
    settings.defaultUpstreamId = id
    defaultUpstreamId.value = id
    viewModelScope.launch { applyNow() }
  }

  /**
   * Splits where default-route DNS goes from where default-route data goes. A policy-only
   * change, like [setLanExclusionEnabled] - takes effect on [applyNow] with no VPN restart.
   */
  fun setDefaultDNSUpstream(id: String) {
    settings.defaultDNSUpstreamId = id
    defaultDNSUpstreamId.value = id
    viewModelScope.launch { applyNow() }
  }

  /**
   * Turns broad VPN capture on or off.
   *
   * Unlike [setDefaultUpstream], this changes what the VPN's TUN device itself captures
   * (IPNService.kt's rebuildMultiProxyTunLocked), not just the policy applied over a live engine -
   * so it only takes effect on the next VPN (re)build, not immediately.
   */
  fun setBroadCaptureEnabled(enabled: Boolean) {
    settings.broadCaptureEnabled = enabled
    broadCaptureEnabled.value = enabled
    if (session.engine != null) {
      val intent = android.content.Intent(session.app, com.tailscale.ipn.IPNService::class.java)
          .setAction(com.tailscale.ipn.IPNService.ACTION_RESTART_VPN)
      session.app.startService(intent)
    }
  }

  /**
   * Turns the LAN-stays-direct default rule on or off.
   *
   * Unlike [setBroadCaptureEnabled], this is a policy change the live engine picks up immediately
   * via [applyNow] - it does not touch what the TUN captures, only where captured LAN traffic goes.
   */
  fun setLanExclusionEnabled(enabled: Boolean) {
    settings.lanExclusionEnabled = enabled
    lanExclusionEnabled.value = enabled
    viewModelScope.launch { applyNow() }
  }

  fun bindApp(packageName: String, upstreamId: String) {
    viewModelScope.launch {
      bindingRepository.bind(packageName, upstreamId)
      applyNow()
    }
  }

  fun unbindApp(packageName: String) {
    viewModelScope.launch {
      bindingRepository.unbind(packageName)
      applyNow()
    }
  }

  /**
   * Sets (or, with an empty id, clears) one app's DNS override, independent of its data route.
   * Only takes effect once the app also has a non-empty upstream binding - see
   * AppBindingRepository.setDNSUpstream's doc comment.
   */
  fun setAppDNSUpstream(packageName: String, dnsUpstreamId: String) {
    viewModelScope.launch {
      bindingRepository.setDNSUpstream(packageName, dnsUpstreamId)
      applyNow()
    }
  }

  /**
   * Sets whether this app's LAN-destined traffic should keep following its own data route even
   * while "Keep LAN traffic direct" is on globally. Only takes effect once the app also has a
   * non-empty upstream binding - see AppBindingRepository.setTunnelLAN's doc comment.
   */
  fun setAppTunnelLAN(packageName: String, tunnelLan: Boolean) {
    viewModelScope.launch {
      bindingRepository.setTunnelLAN(packageName, tunnelLan)
      applyNow()
    }
  }

  fun bindingFor(packageName: String): AppBinding? = bindingRepository.getAllImmediate()[packageName]

  /**
   * Pushes the current configuration into the running engine, if there is one.
   *
   * Upstream registration and policy are both designed to be replaced live, so a routing change
   * takes effect on the next flow rather than needing the VPN restarted. With no engine running this
   * does nothing and the configuration is applied at the next VPN build instead.
   */
  private suspend fun applyNow() {
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
    private const val TAG = "UpstreamRoutingViewModel"

    /** Matches multiproxy.DirectUpstreamID. */
    const val DIRECT_UPSTREAM_ID = "@direct"

    /** Matches multiproxy.maxExitNodeUpstreams (upstream_exitnode.go). */
    private const val MAX_EXIT_NODE_UPSTREAMS = 8
  }
}
