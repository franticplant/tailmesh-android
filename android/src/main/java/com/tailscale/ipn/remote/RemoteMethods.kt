// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.remote

import com.tailscale.ipn.App
import com.tailscale.ipn.BuildConfig
import com.tailscale.ipn.IPNService
import com.tailscale.ipn.MultiProxySessionCoordinator
import com.tailscale.ipn.UninitializedApp
import com.tailscale.ipn.multiproxy.ControlException
import com.tailscale.ipn.multiproxy.MultiProxyControls
import com.tailscale.ipn.multiproxy.PacketCaptures
import com.tailscale.ipn.ui.notifier.Notifier
import com.tailscale.ipn.ui.util.InputStreamAdapter
import com.tailscale.ipn.ui.util.InstalledAppsManager
import com.tailscale.ipn.ui.viewModel.DNSSettingsViewModel
import com.tailscale.ipn.ui.viewModel.SettingsViewModel
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import libtailscale.Libtailscale
import org.json.JSONArray
import org.json.JSONObject

/**
 * The remote-control method catalog: everything the app's own screens can do, by name.
 *
 * Every mutating method goes through the same code the matching control in the UI
 * uses - [MultiProxyControls], [MultiProxySessionCoordinator], [PacketCaptures], the same
 * preference keys
 * - so a remote change behaves exactly like the tap it replaces, and the screens show it.
 *
 * Deliberately absent: anything about remote control itself (its settings, sessions, approvals or
 * access log). Those are reachable only from the Remote control screen, so a client can never widen
 * its own access, extend its lifetime, or hide what it did. See docs/features/04-remote-control.md.
 */
object RemoteMethods {
  private class Method(
      val name: String,
      val mutating: Boolean,
      val description: String,
      val params: Map<String, String> = emptyMap(),
      val run: suspend (Args) -> Any?,
  )

  /** Argument access with errors a remote caller can act on. */
  class Args(private val o: JSONObject) {
    fun str(name: String): String =
        if (o.has(name) && !o.isNull(name)) o.get(name).toString()
        else throw ControlException("missing argument \"$name\"")

    fun optStr(name: String, default: String = ""): String =
        if (o.has(name) && !o.isNull(name)) o.get(name).toString() else default

    fun bool(name: String): Boolean =
        if (o.has(name)) o.optBoolean(name)
        else throw ControlException("missing argument \"$name\"")

    fun optBool(name: String, default: Boolean): Boolean = o.optBoolean(name, default)

    fun optLong(name: String, default: Long): Long = o.optLong(name, default)

    fun strList(name: String): List<String> {
      val arr = o.optJSONArray(name) ?: return emptyList()
      return (0 until arr.length()).map { arr.getString(it) }
    }
  }

  /** An engine JSON string passed through without re-encoding. */
  private class RawJson(val json: String)

  private val session
    get() = App.get().multiProxySession

  private val controls
    get() = MultiProxyControls(session)

  private fun engine() =
      session.engine ?: throw ControlException("Multi-Tailnet mode is not running")

  private val ok = JSONObject().put("done", true)

  private val methods: List<Method> = buildList {
    // -------------------------------------------------------------------
    // overview
    // -------------------------------------------------------------------
    add(
        Method("app.status", false, "App version, VPN mode and engine state.") {
          JSONObject()
              .put("version", BuildConfig.VERSION_NAME)
              .put("runtimeMode", IPNService.runtimeMode.value.name)
              .put("standardState", Notifier.state.value.name)
              .put("multiTailnetEngineRunning", session.engine != null)
              .put("proxyOnly", App.get().isProxyOnlyMode())
              .put("captureActive", PacketCaptures.active.value)
        })
    add(
        Method(
            "app.update",
            true,
            "Install the APK uploaded with POST /v1/app/update (tailmesh-ctl update). Needs " +
                "\"Allow remote updates\" on the phone; refuses another package, another signing " +
                "key or an older version, since getting past those wipes the app's data.",
            mapOf("path" to "the uploaded APK, as POST /v1/app/update passes it"),
        ) {
          withContext(Dispatchers.IO) { AppUpdater.install(it.str("path")) }
        })
    add(
        Method("multitailnet.start", true, "Start Multi-Tailnet mode (the same as its toggle).") {
          MultiProxySessionCoordinator.startMultiProxyMode(session)
          ok
        })
    add(
        Method("multitailnet.stop", true, "Stop Multi-Tailnet mode.") {
          MultiProxySessionCoordinator.stopMultiProxyMode(session)
          ok
        })
    add(
        Method("vpn.restart", true, "Rebuild the VPN interface, e.g. after a capture change.") {
          controls.restartVpn()
          ok
        })
    add(
        Method("standard.connect", true, "Connect in standard (single tailnet) mode.") {
          UninitializedApp.get().startVPN()
          ok
        })
    add(
        Method("standard.disconnect", true, "Disconnect standard mode.") {
          UninitializedApp.get().stopVPN()
          ok
        })

    // -------------------------------------------------------------------
    // tailnets
    // -------------------------------------------------------------------
    add(
        Method(
            "tailnets.list",
            false,
            "Configured tailnets with runtime state, machine name, last error and exit node.",
        ) {
          val states = MultiProxySessionCoordinator.runtimeStates.value
          val names = MultiProxySessionCoordinator.machineNames.value
          val errors = MultiProxySessionCoordinator.lastErrors.value
          val exits = MultiProxySessionCoordinator.exitNodeIps.value
          JSONArray(
              session.profileRepository.profiles.value.map { p ->
                JSONObject()
                    .put("id", p.id)
                    .put("displayName", p.displayName)
                    .put("enabled", p.enabled)
                    .put("provisioningState", p.provisioningState.name)
                    .put(
                        "runtimeState",
                        states[p.id] ?: if (p.enabled) "NOT_LOADED" else "STOPPED",
                    )
                    .put("machineName", names[p.id].orEmpty())
                    .put("lastError", errors[p.id])
                    .put("exitNodeIp", exits[p.id].orEmpty())
              })
        })
    add(
        Method(
            "tailnets.add",
            true,
            "Add a tailnet with an auth key.",
            mapOf("name" to "display name", "authKey" to "tskey-auth-..."),
        ) {
          MultiProxySessionCoordinator.provision(session, it.str("name"), it.str("authKey"))
          JSONObject().put("accepted", true).put("hint", "poll tailnets.list for progress")
        })
    add(
        Method(
            "tailnets.importRegular",
            true,
            "Import a standard-mode login profile as a tailnet.",
            mapOf("profileId" to "LoginProfile ID", "name" to "display name"),
        ) {
          MultiProxySessionCoordinator.importRegularProfile(
              session,
              it.str("profileId"),
              it.str("name"),
          )
          JSONObject().put("accepted", true)
        })
    add(
        Method(
            "tailnets.setEnabled",
            true,
            "Turn one tailnet on or off.",
            mapOf("id" to "tailnet id", "enabled" to "bool"),
        ) {
          MultiProxySessionCoordinator.setEnabled(session, it.str("id"), it.bool("enabled"))
          JSONObject().put("accepted", true)
        })
    add(
        Method(
            "tailnets.rename",
            true,
            "Rename a tailnet.",
            mapOf("id" to "tailnet id", "name" to "new display name"),
        ) {
          MultiProxySessionCoordinator.rename(session, it.str("id"), it.str("name"))
          ok
        })
    add(
        Method(
            "tailnets.forget",
            true,
            "Remove a tailnet and its state.",
            mapOf("id" to "tailnet id"),
        ) {
          MultiProxySessionCoordinator.forget(session, it.str("id"))
          JSONObject().put("accepted", true)
        })
    add(
        Method("tailnets.peers", false, "Every known peer with its synthetic name and addresses.") {
          RawJson(engine().getTargetsJSONV2())
        })
    add(
        Method(
            "tailnets.addressConflicts",
            false,
            "Real Tailscale addresses claimed by more than one tailnet.",
        ) {
          RawJson(engine().getAddressConflictsJSON())
        })
    add(
        Method("tailnets.states", false, "Raw per-tailnet engine state.") {
          RawJson(engine().getTailnetStatesJSON())
        })
    add(
        Method(
            "tailnets.exitNodeCandidates",
            false,
            "Peers of a running tailnet that offer to be an exit node.",
            mapOf("tailnetId" to "tailnet id"),
        ) {
          JSONArray(
              controls.exitNodeCandidates(it.str("tailnetId")).map { c ->
                JSONObject()
                    .put("id", c.id)
                    .put("hostname", c.hostname)
                    .put("dnsName", c.dnsName)
                    .put("ip", c.ip)
              })
        })
    add(
        Method(
            "tailnets.setExitNode",
            true,
            "Point a tailnet's own internet traffic at one of its peers; empty peerAddr clears it.",
            mapOf("tailnetId" to "tailnet id", "peerAddr" to "peer IP, or empty"),
        ) {
          controls.setTailnetExitNode(it.str("tailnetId"), it.optStr("peerAddr"))
          ok
        })

    // -------------------------------------------------------------------
    // upstreams
    // -------------------------------------------------------------------
    add(
        Method(
            "upstreams.list",
            false,
            "Configured upstreams (secrets omitted) with their live stats.",
        ) {
          val stats = MultiProxySessionCoordinator.upstreamStats.value
          JSONArray(
              session.upstreamRepository.upstreams.value.map { u ->
                JSONObject()
                    .put("id", u.id)
                    .put("kind", u.kind.name.lowercase())
                    .put("label", u.label)
                    .put("via", u.via)
                    .put("enabled", u.enabled)
                    .put("sourceTailnetId", u.sourceTailnetId)
                    .put("peerAddr", u.peerAddr)
                    .put("config", redactedConfig(controls.configFor(u.id)))
                    .put("stats", stats[u.id]?.let { s -> statsJson(s) })
              })
        })
    add(
        Method(
            "upstreams.routable",
            false,
            "Everything a route can point at: direct, ready tailnets, configured upstreams.",
        ) {
          JSONArray(
              controls.routableUpstreams().map { r ->
                JSONObject()
                    .put("id", r.id)
                    .put("label", r.label)
                    .put("kind", r.kind)
                    .put("enabled", r.enabled)
              })
        })
    add(
        Method("upstreams.stats", false, "Raw per-upstream dataplane stats from the engine.") {
          RawJson(engine().getUpstreamStatsJSON())
        })
    add(
        Method("upstreams.exitNodeStates", false, "Raw exit-node upstream state.") {
          RawJson(engine().getExitNodeStatesJSON())
        })
    add(
        Method(
            "upstreams.saveSocks5",
            true,
            "Create or edit a SOCKS5 upstream. Returns its id.",
            mapOf(
                "id" to "existing id to edit, omit to create",
                "label" to "name",
                "address" to "host:port",
                "username" to "optional",
                "password" to "optional",
                "via" to "optional upstream id to chain through",
            ),
        ) {
          JSONObject()
              .put(
                  "id",
                  controls.saveSocks5(
                      it.optStr("id").ifEmpty { null },
                      it.optStr("label"),
                      it.str("address"),
                      it.optStr("username"),
                      it.optStr("password"),
                      it.optStr("via"),
                  ),
              )
        })
    add(
        Method(
            "upstreams.saveWireGuard",
            true,
            "Create or edit a WireGuard upstream from a wg-quick .conf or JSON. Returns its id.",
            mapOf(
                "id" to "existing id to edit, omit to create",
                "label" to "name",
                "config" to "wg-quick text or JSON",
                "via" to "optional upstream id to chain through",
            ),
        ) {
          JSONObject()
              .put(
                  "id",
                  controls.saveWireGuard(
                      it.optStr("id").ifEmpty { null },
                      it.optStr("label"),
                      it.str("config"),
                      it.optStr("via"),
                  ),
              )
        })
    add(
        Method(
            "upstreams.saveExitNode",
            true,
            "Add an exit-node upstream (its own device identity). Returns its id.",
            mapOf(
                "label" to "name",
                "sourceTailnetId" to "tailnet to pick from",
                "authKey" to "auth key for the new identity",
                "peerAddr" to "exit node peer IP",
            ),
        ) {
          JSONObject()
              .put(
                  "id",
                  controls.saveExitNode(
                      it.optStr("label"),
                      it.str("sourceTailnetId"),
                      it.str("authKey"),
                      it.str("peerAddr"),
                  ),
              )
        })
    add(
        Method(
            "upstreams.setEnabled",
            true,
            "Turn an upstream on or off.",
            mapOf("id" to "upstream id", "enabled" to "bool"),
        ) {
          controls.setUpstreamEnabled(it.str("id"), it.bool("enabled"))
          ok
        })
    add(
        Method("upstreams.delete", true, "Delete an upstream.", mapOf("id" to "upstream id")) {
          controls.deleteUpstream(it.str("id"))
          ok
        })

    // -------------------------------------------------------------------
    // routing
    // -------------------------------------------------------------------
    add(
        Method("routing.get", false, "Default routes, capture settings and every app binding.") {
          val settings = session.routingSettings
          JSONObject()
              .put("defaultUpstreamId", settings.defaultUpstreamId)
              .put("defaultDNSUpstreamId", settings.defaultDNSUpstreamId)
              .put("broadCaptureEnabled", settings.broadCaptureEnabled)
              .put("lanExclusionEnabled", settings.lanExclusionEnabled)
              .put(
                  "bindings",
                  JSONArray(
                      session.appBindingRepository.bindings.value.values.map { b ->
                        JSONObject()
                            .put("packageName", b.packageName)
                            .put("upstreamId", b.upstreamId)
                            .put("dnsUpstreamId", b.dnsUpstreamId)
                            .put("tunnelLan", b.tunnelLan)
                      }),
              )
        })
    add(
        Method(
            "routing.setDefaultUpstream",
            true,
            "Upstream for apps with no binding; empty keeps today's route.",
            mapOf("id" to "upstream id or empty"),
        ) {
          controls.setDefaultUpstream(it.optStr("id"))
          ok
        })
    add(
        Method(
            "routing.setDefaultDNSUpstream",
            true,
            "Where default-route DNS goes; empty follows the data path.",
            mapOf("id" to "upstream id or empty"),
        ) {
          controls.setDefaultDNSUpstream(it.optStr("id"))
          ok
        })
    add(
        Method(
            "routing.setBroadCapture",
            true,
            "Capture all internet traffic in the VPN (restarts the VPN).",
            mapOf("enabled" to "bool"),
        ) {
          controls.setBroadCaptureEnabled(it.bool("enabled"))
          ok
        })
    add(
        Method(
            "routing.setLanExclusion",
            true,
            "Keep LAN traffic direct regardless of routing.",
            mapOf("enabled" to "bool"),
        ) {
          controls.setLanExclusionEnabled(it.bool("enabled"))
          ok
        })

    // -------------------------------------------------------------------
    // apps
    // -------------------------------------------------------------------
    add(
        Method(
            "apps.list",
            false,
            "Installed apps with UID and current binding.",
            mapOf(
                "query" to "optional substring of name or package",
                "includeSystem" to "bool, default false",
            ),
        ) { args ->
          val query = args.optStr("query")
          val includeSystem = args.optBool("includeSystem", false)
          val bindings = session.appBindingRepository.bindings.value
          JSONArray(
              withContext(Dispatchers.IO) {
                    InstalledAppsManager(App.get().packageManager).fetchInstalledApps()
                  }
                  .filter { includeSystem || !it.isSystemApp }
                  .filter {
                    query.isEmpty() ||
                        it.name.contains(query, ignoreCase = true) ||
                        it.packageName.contains(query, ignoreCase = true)
                  }
                  .map { a ->
                    val b = bindings[a.packageName]
                    JSONObject()
                        .put("packageName", a.packageName)
                        .put("name", a.name)
                        .put("uid", PacketCaptures.uidFor(a.packageName))
                        .put("system", a.isSystemApp)
                        .put("upstreamId", b?.upstreamId)
                        .put("dnsUpstreamId", b?.dnsUpstreamId)
                        .put("tunnelLan", b?.tunnelLan)
                  })
        })
    add(
        Method(
            "apps.bind",
            true,
            "Route an app through an upstream.",
            mapOf("packageName" to "app package", "upstreamId" to "upstream id"),
        ) {
          controls.bindApp(it.str("packageName"), it.str("upstreamId"))
          ok
        })
    add(
        Method(
            "apps.unbind",
            true,
            "Remove an app's binding.",
            mapOf("packageName" to "app package"),
        ) {
          controls.unbindApp(it.str("packageName"))
          ok
        })
    add(
        Method(
            "apps.setDNSUpstream",
            true,
            "Override where an app's DNS goes; empty follows its data path.",
            mapOf("packageName" to "app package", "dnsUpstreamId" to "upstream id or empty"),
        ) {
          controls.setAppDNSUpstream(it.str("packageName"), it.optStr("dnsUpstreamId"))
          ok
        })
    add(
        Method(
            "apps.setTunnelLAN",
            true,
            "Let an app's LAN traffic follow its route even with LAN exclusion on.",
            mapOf("packageName" to "app package", "tunnelLan" to "bool"),
        ) {
          controls.setAppTunnelLAN(it.str("packageName"), it.bool("tunnelLan"))
          ok
        })

    // -------------------------------------------------------------------
    // listeners
    // -------------------------------------------------------------------
    add(
        Method(
            "listeners.socks5.list",
            false,
            "Inbound SOCKS5 listeners and whether each is live.",
        ) {
          val live = liveIds(session.engine?.getSOCKS5ListenersJSON())
          JSONArray(
              session.socks5ListenerRepository.listeners.value.map { l ->
                JSONObject()
                    .put("id", l.id)
                    .put("bindAddr", l.bindAddr)
                    .put("port", l.port)
                    .put("upstream", l.upstream)
                    .put("hasAuth", l.hasAuth)
                    .put("enabled", l.enabled)
                    .put("registered", l.id in live)
              })
        })
    add(
        Method(
            "listeners.socks5.save",
            true,
            "Create or edit an inbound SOCKS5 listener. Returns its id.",
            mapOf(
                "id" to "existing id to edit, omit to create",
                "bindAddr" to "default 127.0.0.1",
                "port" to "1-65535",
                "upstream" to "upstream id",
                "username" to "optional",
                "password" to "optional",
            ),
        ) {
          JSONObject()
              .put(
                  "id",
                  controls.saveSocks5Listener(
                      it.optStr("id").ifEmpty { null },
                      it.optStr("bindAddr"),
                      it.str("port"),
                      it.str("upstream"),
                      it.optStr("username"),
                      it.optStr("password"),
                  ),
              )
        })
    add(
        Method(
            "listeners.socks5.setEnabled",
            true,
            "Turn a SOCKS5 listener on or off.",
            mapOf("id" to "listener id", "enabled" to "bool"),
        ) {
          controls.setSocks5ListenerEnabled(it.str("id"), it.bool("enabled"))
          ok
        })
    add(
        Method(
            "listeners.socks5.delete",
            true,
            "Delete a SOCKS5 listener.",
            mapOf("id" to "listener id"),
        ) {
          controls.deleteSocks5Listener(it.str("id"))
          ok
        })
    add(
        Method(
            "listeners.inbound.list",
            false,
            "Tailnet-facing inbound listeners and whether each is live.",
        ) {
          val live = liveIds(session.engine?.getInboundListenersJSON())
          JSONArray(
              session.inboundListenerRepository.listeners.value.map { l ->
                JSONObject()
                    .put("id", l.id)
                    .put("upstream", l.upstream)
                    .put("listenPort", l.listenPort)
                    .put("localTarget", l.localTarget)
                    .put("proxyProtocol", l.proxyProtocol)
                    .put("enabled", l.enabled)
                    .put("registered", l.id in live)
              })
        })
    add(
        Method(
            "listeners.inbound.save",
            true,
            "Create or edit a tailnet-facing listener. Returns its id.",
            mapOf(
                "id" to "existing id to edit, omit to create",
                "upstream" to "tailnet id",
                "listenPort" to "port on the tailnet node",
                "localTarget" to "host:port on the device",
                "proxyProtocol" to "bool",
            ),
        ) {
          JSONObject()
              .put(
                  "id",
                  controls.saveInboundListener(
                      it.optStr("id").ifEmpty { null },
                      it.str("upstream"),
                      it.str("listenPort"),
                      it.str("localTarget"),
                      it.optBool("proxyProtocol", false),
                  ),
              )
        })
    add(
        Method(
            "listeners.inbound.setEnabled",
            true,
            "Turn a tailnet-facing listener on or off.",
            mapOf("id" to "listener id", "enabled" to "bool"),
        ) {
          controls.setInboundListenerEnabled(it.str("id"), it.bool("enabled"))
          ok
        })
    add(
        Method(
            "listeners.inbound.delete",
            true,
            "Delete a tailnet-facing listener.",
            mapOf("id" to "listener id"),
        ) {
          controls.deleteInboundListener(it.str("id"))
          ok
        })

    // -------------------------------------------------------------------
    // diagnostics
    // -------------------------------------------------------------------
    add(
        Method(
            "diagnostics.snapshot",
            false,
            "Process, dataplane and per-app counters (the Diagnostics screen's numbers).",
        ) {
          RawJson(engine().observabilitySnapshotJSON)
        })
    add(
        Method(
            "diagnostics.events",
            false,
            "Recorded observability events, newest last.",
            mapOf(
                "sinceMinutes" to "default 15",
                "type" to
                    "optional event type, e.g. DNS_QUERY, ROUTE_DECISION, UPSTREAM_HEALTH, " +
                        "NETWORK_SOURCE_CHANGED",
                "limit" to "default 500",
            ),
        ) {
          val since = System.currentTimeMillis() - it.optLong("sinceMinutes", 15) * 60_000
          val type = it.optStr("type")
          val limit = it.optLong("limit", 500).toInt()
          JSONArray(
              MultiProxySessionCoordinator.observabilityEventsSince(since)
                  .filter { e -> type.isEmpty() || e.eventType == type }
                  .takeLast(limit)
                  .map { e ->
                    JSONObject()
                        .put("ts", e.ts)
                        .put("eventType", e.eventType)
                        .put("upstreamId", e.upstreamId)
                        .put("appUid", e.appUid)
                        .put("networkSource", e.networkSource)
                        .put("prevState", e.prevState)
                        .put("newState", e.newState)
                        .put("meta", e.meta)
                  })
        })
    add(
        Method(
            "diagnostics.dnsLog",
            false,
            "DNS query log (needs diagnostics.setDNSQueryLog on): name, type, app, upstream, outcome.",
            mapOf("sinceMinutes" to "default 15", "grep" to "optional name substring"),
        ) {
          val since = System.currentTimeMillis() - it.optLong("sinceMinutes", 15) * 60_000
          val grep = it.optStr("grep")
          JSONArray(
              MultiProxySessionCoordinator.observabilityEventsSince(since)
                  .filter { e -> e.eventType == "DNS_QUERY" }
                  .filter { e -> grep.isEmpty() || e.prevState.contains(grep, true) }
                  .map { e ->
                    JSONObject()
                        .put("ts", e.ts)
                        .put("name", e.prevState)
                        .put("type", e.networkSource)
                        .put("appUid", e.appUid)
                        .put("upstreamId", e.upstreamId)
                        .put("outcome", e.newState)
                  })
        })
    add(
        Method(
            "diagnostics.routeDecisions",
            false,
            "Per-flow routing decisions: app, family, upstream, outcome, error and trace.",
            mapOf(
                "sinceMinutes" to "default 15",
                "outcome" to "optional, e.g. dial-error, no-route, success",
            ),
        ) {
          val since = System.currentTimeMillis() - it.optLong("sinceMinutes", 15) * 60_000
          val outcome = it.optStr("outcome")
          JSONArray(
              MultiProxySessionCoordinator.observabilityEventsSince(since)
                  .filter { e -> e.eventType == "ROUTE_DECISION" }
                  .filter { e -> outcome.isEmpty() || e.prevState == outcome }
                  .map { e ->
                    JSONObject()
                        .put("ts", e.ts)
                        .put("appUid", e.appUid)
                        .put("family", e.networkSource)
                        .put("upstreamId", e.upstreamId)
                        .put("outcome", e.prevState)
                        .put("error", e.newState)
                        .put("meta", e.meta.takeIf { m -> m.isNotEmpty() }?.let(::JSONObject))
                  })
        })
    add(
        Method(
            "diagnostics.setDNSQueryLog",
            true,
            "Turn the per-query DNS log on or off.",
            mapOf("enabled" to "bool"),
        ) {
          engine().setDNSQueryLogEnabled(it.bool("enabled"))
          ok
        })
    add(
        Method(
            "diagnostics.setAdvanced",
            true,
            "Turn advanced (heavier) diagnostics on or off.",
            mapOf("enabled" to "bool"),
        ) {
          engine().setAdvancedDiagnostics(it.bool("enabled"))
          ok
        })
    add(
        Method(
            "diagnostics.setSampleInterval",
            true,
            "Engine sampling interval in seconds (the Diagnostics screen uses 1 while open).",
            mapOf("seconds" to "1-3600"),
        ) {
          val secs = it.optLong("seconds", 60).coerceIn(1, 3600).toInt()
          engine().setObservabilitySampleIntervalSeconds(secs)
          ok
        })
    add(
        Method(
            "diagnostics.reset",
            true,
            "Reset counters and/or history.",
            mapOf(
                "dataplane" to "bool",
                "apps" to "bool",
                "upstreams" to "bool",
                "history" to "bool: also clear recorded history",
            ),
        ) {
          MultiProxySessionCoordinator.resetObservability(
              it.optBool("dataplane", false),
              it.optBool("apps", false),
              it.optBool("upstreams", false),
              null,
              it.optBool("history", false),
          )
          ok
        })
    add(
        Method(
            "diagnostics.exportBundle",
            true,
            "Write a diagnostics bundle (snapshot + history); download it with /v1/files.",
            mapOf("rangeMinutes" to "default 60"),
        ) {
          val file = File(exportsDir(), "diagnostics-${System.currentTimeMillis()}.json")
          withContext(Dispatchers.IO) {
            MultiProxySessionCoordinator.exportDiagnosticsBundle(
                file,
                it.optLong("rangeMinutes", 60) * 60_000,
            )
          }
          JSONObject().put("path", file.absolutePath)
        })
    add(
        Method("diagnostics.exports", false, "Files written by diagnostics.exportBundle.") {
          filesJson(exportsDir().listFiles()?.sortedByDescending { f -> f.lastModified() })
        })

    // -------------------------------------------------------------------
    // packet capture
    // -------------------------------------------------------------------
    add(
        Method(
            "capture.status",
            false,
            "The running capture, if any, and its live size and packet count.",
        ) {
          val s = PacketCaptures.stats()
          JSONObject()
              .put("active", PacketCaptures.active.value)
              .put("bytesWritten", s.bytesWritten)
              .put("packetCount", s.packetCount)
              .put("capacityReached", s.capacityReached)
        })
    add(
        Method(
            "capture.start",
            true,
            "Start a pcapng capture. Returns its path; download with /v1/files once stopped.",
            mapOf(
                "mode" to "all | apps | listeners",
                "packages" to "for apps: list of package names",
                "listenerIds" to "for listeners: list of SOCKS5 listener ids",
                "maxBytes" to "size cap, default 32 MiB",
            ),
        ) {
          val max = it.optLong("maxBytes", PacketCaptures.DEFAULT_MAX_BYTES)
          val path =
              when (val mode = it.optStr("mode", "all")) {
                "all" -> PacketCaptures.startAll(max)
                "apps" -> PacketCaptures.startApps(it.strList("packages"), max)
                "listeners" -> PacketCaptures.startListeners(it.strList("listenerIds"), max)
                else -> throw ControlException("unknown capture mode \"$mode\"")
              }
          JSONObject().put("path", path)
        })
    add(
        Method("capture.stop", true, "Stop the running capture. Returns its path and size.") {
          val path = PacketCaptures.stop()
          val s = PacketCaptures.stats()
          JSONObject()
              .put("path", path)
              .put("bytesWritten", s.bytesWritten)
              .put("packetCount", s.packetCount)
              .put("capacityReached", s.capacityReached)
        })
    add(
        Method("capture.list", false, "Capture files on the device, newest first.") {
          filesJson(withContext(Dispatchers.IO) { PacketCaptures.purgeExpiredAndList() })
        })
    add(
        Method("capture.delete", true, "Delete a capture file.", mapOf("path" to "file path")) {
          PacketCaptures.delete(it.str("path"))
          ok
        })

    // -------------------------------------------------------------------
    // settings
    // -------------------------------------------------------------------
    add(
        Method("settings.get", false, "DNS, debug-logging and Proxy-Only settings.") {
          val app = App.get()
          JSONObject()
              .put("publicDoHURL", app.decryptFromPref(DNSSettingsViewModel.PUBLIC_DOH_URL_KEY))
              .put(
                  "publicDoHOverrideExitNode",
                  app.decryptFromPref(DNSSettingsViewModel.PUBLIC_DOH_OVERRIDE_EXIT_NODE_KEY),
              )
              .put(
                  "publicDoHRouteThroughTailscale",
                  app.decryptFromPref(DNSSettingsViewModel.PUBLIC_DOH_ROUTE_THROUGH_TAILSCALE_KEY),
              )
              .put(
                  "debugHTTPProxyLogging",
                  app.decryptFromPref(SettingsViewModel.DEBUG_HTTP_PROXY_LOGGING_KEY),
              )
              .put(
                  "debugDNSConfigLogging",
                  app.decryptFromPref(SettingsViewModel.DEBUG_DNS_CONFIG_LOGGING_KEY),
              )
              .put(
                  "debugDNSQueryLogging",
                  app.decryptFromPref(SettingsViewModel.DEBUG_DNS_QUERY_LOGGING_KEY),
              )
              .put("proxyOnly", app.isProxyOnlyMode())
        })
    add(
        Method(
            "settings.setPublicDoH",
            true,
            "Set the public DoH resolver (empty uses the network's DNS) and its options.",
            mapOf(
                "url" to "https://... or empty",
                "overrideExitNode" to "optional bool",
                "routeThroughTailscale" to "optional bool",
            ),
        ) {
          val app = App.get()
          app.encryptToPref(DNSSettingsViewModel.PUBLIC_DOH_URL_KEY, it.optStr("url"))
          if (it.has("overrideExitNode")) {
            app.encryptToPref(
                DNSSettingsViewModel.PUBLIC_DOH_OVERRIDE_EXIT_NODE_KEY,
                it.optBool("overrideExitNode", false).toString(),
            )
          }
          if (it.has("routeThroughTailscale")) {
            app.encryptToPref(
                DNSSettingsViewModel.PUBLIC_DOH_ROUTE_THROUGH_TAILSCALE_KEY,
                it.optBool("routeThroughTailscale", false).toString(),
            )
          }
          Libtailscale.applyDNSSettings()
          MultiProxySessionCoordinator.refreshUpstreamDNS()
          ok
        })
    add(
        Method(
            "settings.setDebugLogging",
            true,
            "Turn standard-mode debug logging on or off.",
            mapOf(
                "httpProxy" to "optional bool",
                "dnsConfig" to "optional bool",
                "dnsQuery" to "optional bool",
            ),
        ) {
          val app = App.get()
          listOf(
                  "httpProxy" to SettingsViewModel.DEBUG_HTTP_PROXY_LOGGING_KEY,
                  "dnsConfig" to SettingsViewModel.DEBUG_DNS_CONFIG_LOGGING_KEY,
                  "dnsQuery" to SettingsViewModel.DEBUG_DNS_QUERY_LOGGING_KEY,
              )
              .filter { (arg, _) -> it.has(arg) }
              .forEach { (arg, key) -> app.encryptToPref(key, it.optBool(arg, false).toString()) }
          Libtailscale.applyDNSSettings()
          ok
        })
    add(
        Method(
            "settings.setProxyOnly",
            true,
            "Proxy-Only mode: no VPN interface, in Standard and Multi-Tailnet mode. A running " +
                "Multi-Tailnet engine restarts to apply it.",
            mapOf("enabled" to "bool"),
        ) {
          App.get().setProxyOnlyMode(it.optBool("enabled", false))
          ok
        })

    // -------------------------------------------------------------------
    // standard-mode Tailscale (everything its screens do goes through this)
    // -------------------------------------------------------------------
    add(
        Method(
            "tailscale.localapi.get",
            false,
            "GET a Tailscale LocalAPI path, e.g. status, prefs, profiles/, netcheck... " +
                "(read-only).",
            mapOf("path" to "path under /localapi/v0/, e.g. \"status\""),
        ) {
          localApi("GET", it.str("path"), null)
        })
    add(
        Method(
            "tailscale.localapi.call",
            true,
            "Any LocalAPI request - editing prefs, switching profiles, exit nodes, login, logout.",
            mapOf(
                "method" to "GET | POST | PATCH | PUT | DELETE",
                "path" to "path under /localapi/v0/",
                "body" to "optional request body (string or JSON)",
            ),
        ) {
          localApi(it.optStr("method", "GET"), it.str("path"), it.optStr("body"))
        })
  }

  private val byName = methods.associateBy { it.name }

  private fun Args.has(name: String): Boolean = optStr(name, "\u0000") != "\u0000"

  /** The catalog in remotectl.Method form, for the server's config. */
  fun catalogJson(): JSONArray =
      JSONArray(
          methods.map { m ->
            JSONObject()
                .put("name", m.name)
                .put("mutating", m.mutating)
                .put("description", m.description)
                .put("params", JSONObject(m.params))
          })

  /** Runs one method. Throws [ControlException] (or anything else) on failure. */
  suspend fun call(name: String, argsJson: String): String {
    val m = byName[name] ?: throw ControlException("unknown method $name")
    val args = Args(if (argsJson.isBlank()) JSONObject() else JSONObject(argsJson))
    return when (val result = m.run(args)) {
      null -> "null"
      is RawJson -> result.json.ifBlank { "null" }
      is JSONObject -> result.toString()
      is JSONArray -> result.toString()
      is String -> JSONObject.quote(result)
      is Number,
      is Boolean -> result.toString()
      else -> JSONObject.quote(result.toString())
    }
  }

  fun exportsDir(): File = File(App.get().filesDir, "remote-control/exports").apply { mkdirs() }

  private fun filesJson(files: List<File>?): JSONArray =
      JSONArray(
          (files ?: emptyList()).map { f ->
            JSONObject()
                .put("path", f.absolutePath)
                .put("name", f.name)
                .put("bytes", f.length())
                .put("modifiedAt", f.lastModified())
          })

  private fun liveIds(json: String?): Set<String> =
      try {
        val arr = JSONArray(json ?: "[]")
        (0 until arr.length()).map { arr.getJSONObject(it).optString("id") }.toSet()
      } catch (e: Exception) {
        emptySet()
      }

  /** An upstream's stored config with every secret-bearing field replaced. */
  private fun redactedConfig(json: String?): JSONObject? {
    val o =
        try {
          JSONObject(json ?: return null)
        } catch (e: Exception) {
          return null
        }
    for (key in listOf("password", "privateKey", "authKey", "presharedKey")) {
      if (o.has(key)) o.put(key, "<redacted>")
    }
    o.optJSONArray("peers")?.let { peers ->
      for (i in 0 until peers.length()) {
        val p = peers.optJSONObject(i) ?: continue
        if (p.has("presharedKey")) p.put("presharedKey", "<redacted>")
      }
    }
    return o
  }

  private fun statsJson(s: com.tailscale.ipn.UpstreamStatSnapshot): JSONObject =
      JSONObject()
          .put("ready", s.ready)
          .put("dialAttempts", s.dialAttempts)
          .put("dialSuccesses", s.dialSuccesses)
          .put("dialFailures", s.dialFailures)
          .put("bytesIn", s.bytesIn)
          .put("bytesOut", s.bytesOut)
          .put("activeTcp", s.activeTcp)
          .put("activeUdp", s.activeUdp)

  private suspend fun localApi(method: String, path: String, body: String?): Any {
    val clean = path.trim().removePrefix("/").removePrefix("localapi/v0/")
    if (clean.contains("..")) throw ControlException("invalid LocalAPI path")
    val verb = method.uppercase()
    if (verb !in setOf("GET", "POST", "PATCH", "PUT", "DELETE")) {
      throw ControlException("unsupported method $method")
    }
    return withContext(Dispatchers.IO) {
      val app = App.get().getLibtailscaleApp()
      val stream =
          body
              ?.takeIf { it.isNotEmpty() }
              ?.let { InputStreamAdapter(it.toByteArray().inputStream()) }
      val resp = app.callLocalAPI(30_000, verb, "/localapi/v0/$clean", stream)
      val text = (resp.bodyBytes() ?: ByteArray(0)).decodeToString()
      val parsed: Any =
          try {
            if (text.trimStart().startsWith("[")) JSONArray(text) else JSONObject(text)
          } catch (e: Exception) {
            text
          }
      JSONObject().put("status", resp.statusCode()).put("body", parsed)
    }
  }
}
