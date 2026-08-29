package com.tailscale.ipn

import android.content.Intent
import com.tailscale.ipn.multiproxy.db.ProvisioningState
import com.tailscale.ipn.util.TSLog
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import libtailscale.Libtailscale

@Serializable
private data class TailnetRuntimeSnapshot(
    val tailnetId: String,
    val enabled: Boolean,
    val state: String,
    val machineName: String = "",
    val exitNodeIp: String = "",
)

/**
 * An exit-node upstream's own dedicated node identity state, decoded from
 * `Engine.GetExitNodeStatesJSON()`. Mirrors [TailnetRuntimeSnapshot] - see
 * that method's doc comment for why this needs to exist as its own poll
 * rather than being inferred from dial stats: EditPrefs succeeds locally
 * regardless of whether this identity is actually approved on its source
 * tailnet, so a stuck NeedsMachineAuth/NeedsLogin state is otherwise
 * invisible.
 */
@Serializable
private data class ExitNodeRuntimeSnapshot(
    val id: String,
    val sourceTailnetId: String = "",
    val peerAddr: String = "",
    val enabled: Boolean,
    val state: String,
    val machineName: String = "",
)

/**
 * Live per-upstream dial/byte counters, decoded from `Engine.GetUpstreamStatsJSON()`.
 *
 * Every count here is a real observation from an actual dial or readiness check made by the
 * running engine - not a sample or an estimate. See libtailscale/multiproxy/stats.go.
 */
@Serializable
data class UpstreamStatSnapshot(
    val id: String,
    val kind: String = "",
    val ready: Boolean = false,
    val via: String = "",
    val dialAttempts: Long = 0,
    val dialSuccesses: Long = 0,
    val dialFailures: Long = 0,
    val notReadyCount: Long = 0,
    val bytesIn: Long = 0,
    val bytesOut: Long = 0,
    val tcpFlowsTotal: Long = 0,
    val udpFlowsTotal: Long = 0,
    val activeTcp: Long = 0,
    val activeUdp: Long = 0,
    val dnsQueriesForwarded: Long = 0,
    val dnsQueriesFailed: Long = 0,
    val lastLatencyMs: Long = 0,
    val peerPath: String = "",
    val lastError: String = "",
    val lastErrorAtMillis: Long = 0,
    val lastSuccessAtMillis: Long = 0,
    val lastAttemptAtMillis: Long = 0,
)

/**
 * Mirrors multiproxy.ProcessSample (observability.go). CPUSeconds is real
 * /proc/self/stat kernel accounting; CPUPercent and CPUSecondsPerGiB are
 * derived from it over the sampler's own interval - see that file's doc
 * comments for exactly what "derived" means here. None of this is wall-clock
 * handler duration mislabeled as CPU time.
 */
@Serializable
data class ProcessSample(
    val atMillis: Long = 0,
    val cpuSeconds: Double = 0.0,
    val cpuPercent: Double = 0.0,
    val goHeapAllocBytes: Long = 0,
    val goHeapSysBytes: Long = 0,
    val goNumGc: Int = 0,
    val goGcPauseTotalNs: Long = 0,
    val goroutineCount: Int = 0,
    val engineUptimeSeconds: Long = 0,
    val vpnUptimeSeconds: Long = -1,
    val cpuSecondsPerGiB: Double = 0.0,
)

/** Mirrors multiproxy.DataplaneSnapshot - all atomic counters, exact, no sampling loss. */
@Serializable
data class DataplaneSnapshot(
    val tunRxBytes: Long = 0,
    val tunTxBytes: Long = 0,
    val tunRxPackets: Long = 0,
    val tunTxPackets: Long = 0,
    val dnsQueries: Long = 0,
    val dnsFailures: Long = 0,
    val vpnRestarts: Long = 0,
    val attributionFailures: Long = 0,
    val dnsAttributionFailClosed: Long = 0,
    val dnsForwardFailures: Long = 0,
)

/**
 * Mirrors multiproxy.UIDStatsInfo - per-app traffic counters, exact (byte/flow
 * counts), NOT a CPU or battery attribution. See docs/multi_tailnet_proxy_app/observability.md
 * for why per-app CPU/battery is deliberately not claimed here.
 */
/** Mirrors multiproxy.UpstreamUsageInfo - one app's counters against one specific upstream. */
@Serializable
data class UpstreamUsageInfo(
    val upstreamId: String = "",
    val bytesIn: Long = 0,
    val bytesOut: Long = 0,
    val tcpFlows: Long = 0,
    val udpFlows: Long = 0,
)

@Serializable
data class UIDStatsInfo(
    val uid: Int = 0,
    val bytesIn: Long = 0,
    val bytesOut: Long = 0,
    val tcpFlows: Long = 0,
    val udpFlows: Long = 0,
    val lastUpstream: String = "",
    val byUpstream: List<UpstreamUsageInfo> = emptyList(),
)

@Serializable
data class ObservabilitySnapshot(
    val process: ProcessSample = ProcessSample(),
    val dataplane: DataplaneSnapshot = DataplaneSnapshot(),
    val apps: List<UIDStatsInfo> = emptyList(),
)

data class ObservabilityEvent(
    val eventType: String,
    val upstreamId: String,
    val appUid: Int,
    val networkSource: String,
    val previousState: String,
    val newState: String,
    val metadataJSON: String,
    val timestampMillis: Long,
)

object MultiProxySessionCoordinator {
    private val mutationMutex = Mutex()
    private val json = Json { ignoreUnknownKeys = true }

    private val _runtimeStates = MutableStateFlow<Map<String, String>>(emptyMap())
    val runtimeStates: StateFlow<Map<String, String>> = _runtimeStates.asStateFlow()

    private val _lastErrors = MutableStateFlow<Map<String, String>>(emptyMap())
    val lastErrors: StateFlow<Map<String, String>> = _lastErrors.asStateFlow()

    private val _machineNames = MutableStateFlow<Map<String, String>>(emptyMap())
    val machineNames: StateFlow<Map<String, String>> = _machineNames.asStateFlow()

    // The peer address SetTailnetExitNode currently has each tailnet pointed
    // at, keyed by tailnet id - empty/absent means no exit node is set. Read
    // back from the same live GetTailnetStatesJSON poll as runtimeStates, so
    // the "Exit node" picker (MultiProxyView.kt) can show what's actually
    // active instead of always opening blank regardless of what was
    // previously selected.
    private val _exitNodeIps = MutableStateFlow<Map<String, String>>(emptyMap())
    val exitNodeIps: StateFlow<Map<String, String>> = _exitNodeIps.asStateFlow()

    // Address crossovers: a real (non-synthetic) Tailscale IP was claimed by
    // more than one active tailnet at once and the engine picked one
    // best-effort. Kept as a small accumulating log (not a keyed map like
    // lastErrors) since more than one distinct crossover can be worth seeing,
    // and it isn't tied to a single profile id the way an error is.
    private val _addressCrossovers = MutableStateFlow<List<AddressCrossover>>(emptyList())
    val addressCrossovers: StateFlow<List<AddressCrossover>> = _addressCrossovers.asStateFlow()

    // Live per-upstream stats, keyed by upstream id. Polled on the same 1s
    // cadence as runtime state, since GetUpstreamStatsJSON is a cheap
    // snapshot read (see stats.go) - no push mechanism is relied on as the
    // source of truth, only as a near-real-time nudge (see
    // recordUpstreamHealthChange below).
    private val _upstreamStats = MutableStateFlow<Map<String, UpstreamStatSnapshot>>(emptyMap())
    val upstreamStats: StateFlow<Map<String, UpstreamStatSnapshot>> = _upstreamStats.asStateFlow()

    // Upstream health transitions: a best-effort, near-real-time log of when an
    // upstream's dial-level readiness flipped, alongside the polled stats above
    // which are the reliable source of truth. Same accumulating-log shape as
    // addressCrossovers, for the same reason: more than one is worth seeing.
    private val _upstreamHealthEvents = MutableStateFlow<List<UpstreamHealthEvent>>(emptyList())
    val upstreamHealthEvents: StateFlow<List<UpstreamHealthEvent>> = _upstreamHealthEvents.asStateFlow()

    // Latest observability snapshot (process/dataplane/per-app counters). This
    // is a cheap read of counters the engine already maintains, not a new
    // measurement - see GetObservabilitySnapshotJSON.
    private val _observabilitySnapshot = MutableStateFlow(ObservabilitySnapshot())
    val observabilitySnapshot: StateFlow<ObservabilitySnapshot> = _observabilitySnapshot.asStateFlow()

    // Bounded in-memory tail of recent observability events, for the
    // diagnostics screen's live event log - the durable copy lives in
    // ObservabilityDatabaseHelper.
    private const val maxObservabilityEventsInMemory = 200
    private val _observabilityEvents = MutableStateFlow<List<ObservabilityEvent>>(emptyList())
    val observabilityEvents: StateFlow<List<ObservabilityEvent>> = _observabilityEvents.asStateFlow()

    private var obsDb: com.tailscale.ipn.multiproxy.db.ObservabilityDatabaseHelper? = null
    private var obsPollJob: Job? = null

    // While the diagnostics screen is visible, sample at ~1s; otherwise fall
    // back to a low, battery-safe cadence. See PHASE 17/battery-safe design
    // in the spec: no 1-second timers while the screen is closed.
    private const val obsIntervalVisibleSeconds = 1
    private const val obsIntervalBackgroundSeconds = 60
    @Volatile private var diagnosticsUiVisible = false
    private var lastPruneAtMillis = 0L

    private var boundSession: MultiProxySession? = null
    private var pollJob: Job? = null

    // Called when the user changes DNS settings (e.g. selects/clears a
    // public DoH resolver) so the active Multi-Tailnet session's DNS
    // fallback picks it up immediately, the same way
    // Libtailscale.applyDNSSettings() does for Standard mode. A no-op if no
    // session is bound or it has no live engine yet.
    fun refreshUpstreamDNS() {
        boundSession?.applyUpstreamDNS()
    }

    fun bind(session: MultiProxySession) {
        if (boundSession === session && pollJob?.isActive == true) return
        boundSession = session
        pollJob?.cancel()
        pollJob = session.app.applicationScope.launch {
            while (true) {
                refreshRuntimeState(session)
                refreshUpstreamStats(session)
                delay(1000)
            }
        }
        if (obsDb == null) {
            obsDb = com.tailscale.ipn.multiproxy.db.ObservabilityDatabaseHelper(session.app)
        }
        obsPollJob?.cancel()
        obsPollJob = session.app.applicationScope.launch {
            while (true) {
                val intervalSeconds =
                    if (diagnosticsUiVisible) obsIntervalVisibleSeconds else obsIntervalBackgroundSeconds
                refreshObservabilitySnapshot(session)
                delay(intervalSeconds * 1000L)
            }
        }
    }

    /**
     * Called by the diagnostics screen on enter/exit. Switches both the
     * Kotlin-side poll cadence and the Go-side sampler cadence
     * (SetObservabilitySampleIntervalSeconds) - the two must move together or
     * either the UI polls faster than the engine actually samples (stale
     * data), or the engine samples faster than anything reads it (wasted
     * work). Coarse cadence, no DB writes at 1s resolution, whenever this is
     * false - see the battery-safe design requirement in the spec.
     */
    fun setDiagnosticsUiVisible(visible: Boolean) {
        diagnosticsUiVisible = visible
        val secs = if (visible) obsIntervalVisibleSeconds else obsIntervalBackgroundSeconds
        boundSession?.engine?.setObservabilitySampleIntervalSeconds(secs)
    }

    private fun refreshObservabilitySnapshot(session: MultiProxySession) {
        val engine = session.engine ?: return
        try {
            val snap = json.decodeFromString<ObservabilitySnapshot>(engine.observabilitySnapshotJSON)
            _observabilitySnapshot.value = snap

            val now = System.currentTimeMillis()
            obsDb?.insertSample(
                com.tailscale.ipn.multiproxy.db.ObservabilityDatabaseHelper.Sample(
                    ts = now,
                    cpuPercent = snap.process.cpuPercent,
                    cpuSeconds = snap.process.cpuSeconds,
                    heapBytes = snap.process.goHeapAllocBytes,
                    goroutines = snap.process.goroutineCount,
                    tunRxBytes = snap.dataplane.tunRxBytes,
                    tunTxBytes = snap.dataplane.tunTxBytes,
                    dnsFailures = snap.dataplane.dnsFailures,
                ))
            if (snap.apps.isNotEmpty()) {
                obsDb?.insertAppSamples(
                    now,
                    snap.apps.map {
                        com.tailscale.ipn.multiproxy.db.ObservabilityDatabaseHelper.AppSample(
                            ts = now,
                            appUid = it.uid,
                            bytesIn = it.bytesIn,
                            bytesOut = it.bytesOut,
                            tcpFlows = it.tcpFlows,
                            udpFlows = it.udpFlows,
                        )
                    })
            }
            val upstreams = _upstreamStats.value
            if (upstreams.isNotEmpty()) {
                obsDb?.insertUpstreamSamples(
                    now,
                    upstreams.values.map {
                        com.tailscale.ipn.multiproxy.db.ObservabilityDatabaseHelper.UpstreamSample(
                            ts = now,
                            upstreamId = it.id,
                            bytesIn = it.bytesIn,
                            bytesOut = it.bytesOut,
                            dialAttempts = it.dialAttempts,
                            dialSuccesses = it.dialSuccesses,
                            dialFailures = it.dialFailures,
                        )
                    })
            }
            // Pruning is cheap (indexed DELETEs) but there is no reason to run
            // it on every tick; once a minute is plenty to keep the tables
            // bounded well ahead of their retention windows.
            if (now - lastPruneAtMillis > 60_000) {
                lastPruneAtMillis = now
                obsDb?.prune(now)
            }
        } catch (e: Exception) {
            TSLog.e("MultiProxySession", "Failed to decode observability snapshot: ${e.message}")
        }
    }

    /** Called from the engine's OnObservabilityEvent callback (IPNService.kt). */
    fun recordObservabilityEvent(
        eventType: String,
        upstreamId: String,
        appUid: Int,
        networkSource: String,
        previousState: String,
        newState: String,
        metadataJSON: String,
    ) {
        val now = System.currentTimeMillis()
        TSLog.d("MultiProxySession", "Observability event: $eventType upstream=$upstreamId $previousState->$newState")
        _observabilityEvents.value =
            (_observabilityEvents.value + ObservabilityEvent(
                eventType = eventType,
                upstreamId = upstreamId,
                appUid = appUid,
                networkSource = networkSource,
                previousState = previousState,
                newState = newState,
                metadataJSON = metadataJSON,
                timestampMillis = now,
            )).takeLast(maxObservabilityEventsInMemory)
        obsDb?.insertEvent(
            com.tailscale.ipn.multiproxy.db.ObservabilityDatabaseHelper.Event(
                ts = now,
                eventType = eventType,
                upstreamId = upstreamId,
                appUid = appUid,
                networkSource = networkSource,
                prevState = previousState,
                newState = newState,
                meta = metadataJSON,
            ))
    }

    /**
     * Records a discrete network-source transition event from
     * NetworkChangeCallback (Wi-Fi/cellular switch, default network lost,
     * etc), through the same store as engine-originated observability events
     * so the diagnostics UI has one unified timeline.
     */
    /** Reads persisted samples for the diagnostics graphs - see ObservabilityDatabaseHelper.samplesSince. */
    fun observabilitySamplesSince(sinceMillis: Long): List<com.tailscale.ipn.multiproxy.db.ObservabilityDatabaseHelper.Sample> =
        obsDb?.samplesSince(sinceMillis) ?: emptyList()

    /** Reads persisted events for the diagnostics event log/overlays - see ObservabilityDatabaseHelper.eventsSince. */
    fun observabilityEventsSince(sinceMillis: Long): List<com.tailscale.ipn.multiproxy.db.ObservabilityDatabaseHelper.Event> =
        obsDb?.eventsSince(sinceMillis) ?: emptyList()

    /** Per-app history for one UID, for the Apps tab's per-app graph. */
    fun appSamplesSince(appUid: Int, sinceMillis: Long): List<com.tailscale.ipn.multiproxy.db.ObservabilityDatabaseHelper.AppSample> =
        obsDb?.appSamplesSince(appUid, sinceMillis) ?: emptyList()

    /** Every app UID with recorded history in range, for the Apps tab's picker. */
    fun appUidsSince(sinceMillis: Long): List<Int> = obsDb?.appUidsSince(sinceMillis) ?: emptyList()

    /** Per-upstream history for one upstream id, for the Tailnets tab's per-upstream graph. */
    fun upstreamSamplesSince(upstreamId: String, sinceMillis: Long): List<com.tailscale.ipn.multiproxy.db.ObservabilityDatabaseHelper.UpstreamSample> =
        obsDb?.upstreamSamplesSince(upstreamId, sinceMillis) ?: emptyList()

    /**
     * Writes a JSON diagnostics bundle (current snapshot + recent samples/app-samples/events) to
     * `outFile`. This is the "local export bundle" scope chosen over live OTel streaming - a
     * point-in-time dump the user pulls off-device, not a continuous exporter. Runs a handful of
     * bounded SQLite reads; call off the main thread.
     */
    fun exportDiagnosticsBundle(outFile: java.io.File, rangeMillis: Long) {
        val since = System.currentTimeMillis() - rangeMillis
        val snap = _observabilitySnapshot.value
        val root = org.json.JSONObject()
        root.put("generatedAtMillis", System.currentTimeMillis())
        root.put(
            "snapshot",
            org.json.JSONObject(json.encodeToString(ObservabilitySnapshot.serializer(), snap)))
        val samplesArr = org.json.JSONArray()
        observabilitySamplesSince(since).forEach {
            samplesArr.put(
                org.json.JSONObject()
                    .put("ts", it.ts)
                    .put("cpuPercent", it.cpuPercent)
                    .put("cpuSeconds", it.cpuSeconds)
                    .put("heapBytes", it.heapBytes)
                    .put("goroutines", it.goroutines)
                    .put("tunRxBytes", it.tunRxBytes)
                    .put("tunTxBytes", it.tunTxBytes)
                    .put("dnsFailures", it.dnsFailures))
        }
        root.put("samples", samplesArr)
        val eventsArr = org.json.JSONArray()
        observabilityEventsSince(since).forEach {
            eventsArr.put(
                org.json.JSONObject()
                    .put("ts", it.ts)
                    .put("eventType", it.eventType)
                    .put("upstreamId", it.upstreamId)
                    .put("appUid", it.appUid)
                    .put("networkSource", it.networkSource)
                    .put("prevState", it.prevState)
                    .put("newState", it.newState)
                    .put("meta", it.meta))
        }
        root.put("events", eventsArr)
        val appsArr = org.json.JSONArray()
        appUidsSince(since).forEach { uid ->
            val uidSamplesArr = org.json.JSONArray()
            appSamplesSince(uid, since).forEach {
                uidSamplesArr.put(
                    org.json.JSONObject()
                        .put("ts", it.ts)
                        .put("bytesIn", it.bytesIn)
                        .put("bytesOut", it.bytesOut)
                        .put("tcpFlows", it.tcpFlows)
                        .put("udpFlows", it.udpFlows))
            }
            appsArr.put(org.json.JSONObject().put("uid", uid).put("samples", uidSamplesArr))
        }
        root.put("appSamples", appsArr)
        outFile.writeText(root.toString(2))
    }

    /**
     * Resets diagnostics state per the "reset stats" action. [resetDataplane]/[resetApps]/
     * [resetUpstreams] zero the corresponding live in-memory counter groups (see
     * Engine.ResetObservabilityCounters - these always reset in full, since cumulative counters
     * have no time axis to scope). [resetHistorySinceMillis] additionally clears persisted
     * history (samples/events/app_samples): null clears all history, otherwise only rows newer
     * than that timestamp are dropped ("reset last X").
     */
    fun resetObservability(
        resetDataplane: Boolean,
        resetApps: Boolean,
        resetUpstreams: Boolean,
        resetHistorySinceMillis: Long?,
        resetHistory: Boolean,
    ) {
        boundSession?.engine?.resetObservabilityCounters(resetDataplane, resetApps, resetUpstreams)
        if (resetHistory) {
            obsDb?.resetHistory(resetHistorySinceMillis)
        }
    }

    fun recordNetworkSourceEvent(networkSource: String, previousState: String, newState: String) {
        recordObservabilityEvent(
            eventType = "NETWORK_SOURCE_CHANGED",
            upstreamId = "",
            appUid = 0,
            networkSource = networkSource,
            previousState = previousState,
            newState = newState,
            metadataJSON = "",
        )
    }

    fun startMultiProxyMode(session: MultiProxySession) {
        bind(session)
        val intent = Intent(session.app, IPNService::class.java)
            .setAction(IPNService.ACTION_START_MULTIPROXY)
        session.app.startForegroundService(intent)
    }

    fun stopMultiProxyMode(session: MultiProxySession) {
        val intent = Intent(session.app, IPNService::class.java)
            .setAction(IPNService.ACTION_STOP_MULTIPROXY)
        session.app.startService(intent)
    }

    fun provision(session: MultiProxySession, displayName: String, authKey: String) {
        bind(session)
        session.app.applicationScope.launch {
            mutationMutex.withLock {
                val profile = session.profileRepository.createProfile(displayName)
                val provisioning = profile.copy(
                    enabled = true,
                    provisioningState = ProvisioningState.PROVISIONING,
                )
                session.profileRepository.updateProfile(provisioning)
                session.credentialStore.saveAuthKey(profile.id, authKey)
                clearError(profile.id)

                try {
                    ensureMultiProxyEngine(session)
                    val engine = session.engine ?: error("MULTIPROXY engine did not start")
                    try {
                        engine.addTailnet(profile.id, authKey, true)
                    } catch (e: Exception) {
                        if (e.message?.contains("already exists", ignoreCase = true) == true) {
                            engine.setTailnetEnabled(profile.id, true)
                        } else {
                            throw e
                        }
                    }
                } catch (e: Exception) {
                    failProvisioning(session, profile.id, e.message ?: "Provisioning failed")
                }
            }
        }
    }

    fun importRegularProfile(session: MultiProxySession, profileId: String, displayName: String) {
        bind(session)
        session.app.applicationScope.launch {
            mutationMutex.withLock {
                try {
                    session.profileRepository.importRegularProfile(profileId, displayName)
                } catch (e: Exception) {
                    TSLog.e("MultiProxySession", "Failed to import regular profile " + profileId + ": " + e.message)
                }
            }
        }
    }

    fun setEnabled(session: MultiProxySession, id: String, enabled: Boolean) {
        bind(session)
        session.app.applicationScope.launch {
            mutationMutex.withLock {
                val profile = session.profileRepository.getProfileImmediate(id) ?: return@withLock
                try {
                    if (session.engine == null) {
                        session.profileRepository.updateProfile(profile.copy(enabled = enabled))
                        clearError(id)
                        return@withLock
                    }
                    if (enabled) {
                        ensureMultiProxyEngine(session)
                        val engine = session.engine ?: error("MULTIPROXY engine did not start")
                        try {
                            engine.setTailnetEnabled(id, true)
                        } catch (e: Exception) {
                            if (e.message?.contains("not found", ignoreCase = true) == true) {
                                // A profile imported from an already-authenticated regular
                                // account (profile.sourceProfileId != null) has no auth key of
                                // its own - its multiproxy identity comes from cloning that
                                // account's persisted tsnet state via prepareRegularProfileForMultiProxy,
                                // which startMultiProxyVPNLocked (IPNService.kt) normally does for
                                // every enabled imported profile when the whole session starts.
                                // Toggling a single profile back on while the session is already
                                // running skips that full-session bootstrap, so redo it here too -
                                // otherwise the tailnet gets re-added with an empty auth key and
                                // gets stuck at NEEDS_LOGIN until the entire session is restarted.
                                val sourceProfileId = profile.sourceProfileId
                                if (sourceProfileId != null) {
                                    Libtailscale.prepareRegularProfileForMultiProxy(
                                        session.app.filesDir.absolutePath, session.app, sourceProfileId, id,
                                    )
                                }
                                val key = session.credentialStore.getAuthKey(id) ?: ""
                                engine.addTailnet(id, key, true)
                            } else {
                                throw e
                            }
                        }
                    } else {
                        session.engine?.let { engine ->
                            try {
                                engine.setTailnetEnabled(id, false)
                            } catch (e: Exception) {
                                if (e.message?.contains("not found", ignoreCase = true) != true) throw e
                            }
                        }
                    }
                    session.profileRepository.updateProfile(profile.copy(enabled = enabled))
                    clearError(id)
                } catch (e: Exception) {
                    setError(id, e.message ?: "Failed to ${if (enabled) "enable" else "disable"} Tailnet")
                }
            }
        }
    }

    fun rename(session: MultiProxySession, id: String, displayName: String) {
        session.app.applicationScope.launch {
            mutationMutex.withLock {
                val profile = session.profileRepository.getProfileImmediate(id) ?: return@withLock
                session.profileRepository.updateProfile(profile.copy(displayName = displayName))
            }
        }
    }

    fun forget(session: MultiProxySession, id: String) {
        bind(session)
        session.app.applicationScope.launch {
            mutationMutex.withLock {
                try {
                    // RemoveTailnet is the canonical full runtime cleanup: it cancels
                    // and waits for the watcher, closes tsnet, clears subnet/exit
                    // routing, and removes peer/DNS snapshots while preserving disk.
                    session.engine?.let { engine ->
                        try {
                            engine.removeTailnet(id)
                        } catch (e: Exception) {
                            if (e.message?.contains("not found", ignoreCase = true) != true) throw e
                        }
                    }
                    // Forgetting, unlike disabling/removing the runtime, also deletes
                    // the deterministic persisted tsnet identity directory.
                    Libtailscale.forgetMultiProxyPersistedState(session.app.filesDir.absolutePath, id)
                    session.credentialStore.deleteAuthKey(id)
                    session.profileRepository.deleteProfile(id)
                    _runtimeStates.value = _runtimeStates.value - id
                    _exitNodeIps.value = _exitNodeIps.value - id
                    clearError(id)
                } catch (e: Exception) {
                    setError(id, e.message ?: "Failed to forget Tailnet")
                }
            }
        }
    }

    private suspend fun ensureMultiProxyEngine(session: MultiProxySession) {
        if (session.engine != null) return
        startMultiProxyMode(session)
        repeat(50) {
            if (session.engine != null) return
            delay(100)
        }
        error("Timed out waiting for MULTIPROXY engine startup")
    }

    private suspend fun refreshRuntimeState(session: MultiProxySession) {
        val engine = session.engine
        if (engine == null) {
            _runtimeStates.value = emptyMap()
            _machineNames.value = emptyMap()
            _exitNodeIps.value = emptyMap()
            return
        }

        val snapshots = try {
            json.decodeFromString<List<TailnetRuntimeSnapshot>>(engine.getTailnetStatesJSON())
        } catch (e: Exception) {
            TSLog.e("MultiProxySession", "Failed to decode runtime state: ${e.message}")
            return
        }

        val exitNodeSnapshots =
            try {
                json.decodeFromString<List<ExitNodeRuntimeSnapshot>>(engine.getExitNodeStatesJSON())
            } catch (e: Exception) {
                TSLog.e("MultiProxySession", "Failed to decode exit node runtime state: ${e.message}")
                emptyList()
            }

        _runtimeStates.value =
            snapshots.associate { it.tailnetId to normalizeRuntimeState(it.state) } +
                exitNodeSnapshots.associate { it.id to normalizeRuntimeState(it.state) }
        _machineNames.value =
            (snapshots.mapNotNull { snapshot ->
                    snapshot.machineName.takeIf { it.isNotBlank() }?.let { snapshot.tailnetId to it }
                } +
                    exitNodeSnapshots.mapNotNull { snapshot ->
                        snapshot.machineName.takeIf { it.isNotBlank() }?.let { snapshot.id to it }
                    })
                .toMap()
        _exitNodeIps.value =
            snapshots.mapNotNull { snapshot ->
                snapshot.exitNodeIp.takeIf { it.isNotBlank() }?.let { snapshot.tailnetId to it }
            }.toMap()

        // Mirrors the tailnet bootstrap-key retirement below, for an exit-node
        // upstream's own dedicated identity: once a live poll (not just a
        // locally-successful EditPrefs, see GetExitNodeStatesJSON's doc
        // comment) confirms Running, the stored config's authKey is dead
        // weight - strip it so it stops being carried in the encrypted store
        // and stops being re-sent on every future VPN rebuild
        // (registerExitNode, UpstreamPolicyApplier.kt).
        for (snapshot in exitNodeSnapshots) {
            if (normalizeRuntimeState(snapshot.state) == "RUNNING") {
                session.upstreamSecretStore.clearAuthKey(snapshot.id)
            }
        }

        // A Running backend proves tsnet has durable node state. Retire bootstrap
        // credentials at that point and complete provisioning.
        for (snapshot in snapshots) {
            val profile = session.profileRepository.getProfileImmediate(snapshot.tailnetId) ?: continue
            val normalized = normalizeRuntimeState(snapshot.state)
            if (normalized == "RUNNING" && profile.provisioningState == ProvisioningState.PROVISIONING) {
                mutationMutex.withLock {
                    val current = session.profileRepository.getProfileImmediate(snapshot.tailnetId)
                        ?: return@withLock
                    if (current.provisioningState == ProvisioningState.PROVISIONING) {
                        session.profileRepository.updateProfile(
                            current.copy(provisioningState = ProvisioningState.READY, enabled = true),
                        )
                        engine.clearTailnetAuthKey(snapshot.tailnetId)
                        session.credentialStore.deleteAuthKey(snapshot.tailnetId)
                        clearError(snapshot.tailnetId)
                    }
                }
            } else if (
                profile.provisioningState == ProvisioningState.PROVISIONING &&
                normalized in setOf("ERROR", "NEEDS_LOGIN", "NEEDS_MACHINE_AUTH")
            ) {
                mutationMutex.withLock {
                    failProvisioning(session, snapshot.tailnetId, "Tailnet provisioning state: ${snapshot.state}")
                }
            }
        }
    }

    // Only the fields UpstreamHealthLine (UpstreamsView.kt) actually renders:
    // ready/dialAttempts/dialSuccesses/dialFailures/lastError. Every
    // UpstreamStatSnapshot also carries byte counters and millisecond
    // timestamps (lastAttemptAtMillis in particular) that the Go side updates
    // on literally every dial - see stats.go's recordAttempt/recordSuccess/
    // recordFailure - so those fields differ on almost every 1s poll tick
    // whenever there is any traffic on any upstream. Comparing the full data
    // class would make _upstreamStats emit a "new" map (and force every
    // visible upstream row to recompose/redraw) roughly every second for as
    // long as the Proxies & tunnels screen stays open with any live traffic,
    // even though nothing the UI actually shows changed. Comparing only the
    // rendered subset keeps StateFlow's conflation meaningful.
    private fun renderedStatsKey(s: UpstreamStatSnapshot) =
        listOf(s.ready, s.dialAttempts, s.dialSuccesses, s.dialFailures, s.lastError)

    private fun refreshUpstreamStats(session: MultiProxySession) {
        val engine = session.engine
        if (engine == null) {
            _upstreamStats.value = emptyMap()
            return
        }
        try {
            val snapshots = json.decodeFromString<List<UpstreamStatSnapshot>>(engine.upstreamStatsJSON)
            val next = snapshots.associateBy { it.id }
            val current = _upstreamStats.value
            val unchanged = current.keys == next.keys &&
                current.all { (id, old) -> renderedStatsKey(old) == renderedStatsKey(next.getValue(id)) }
            if (!unchanged) {
                _upstreamStats.value = next
            }
        } catch (e: Exception) {
            TSLog.e("MultiProxySession", "Failed to decode upstream stats: ${e.message}")
        }
    }

    private const val maxUpstreamHealthEvents = 50

    /** Called from the engine's OnUpstreamHealthChanged callback (IPNService.kt). */
    fun recordUpstreamHealthChange(upstreamId: String, ready: Boolean, reason: String) {
        val message = if (ready) {
            "Upstream $upstreamId is reachable again"
        } else {
            "Upstream $upstreamId became unreachable${if (reason.isNotEmpty()) ": $reason" else ""}"
        }
        TSLog.w("MultiProxySession", message)
        _upstreamHealthEvents.value =
            (_upstreamHealthEvents.value + UpstreamHealthEvent(
                upstreamId = upstreamId,
                ready = ready,
                reason = reason,
                timestampMillis = System.currentTimeMillis(),
            )).takeLast(maxUpstreamHealthEvents)
    }

    private suspend fun failProvisioning(session: MultiProxySession, id: String, message: String) {
        val current = session.profileRepository.getProfileImmediate(id) ?: return
        try {
            session.engine?.setTailnetEnabled(id, false)
        } catch (_: Exception) {
        }
        session.profileRepository.updateProfile(
            current.copy(provisioningState = ProvisioningState.ERROR, enabled = false),
        )
        setError(id, message)
    }

    private fun normalizeRuntimeState(state: String): String = when (state.lowercase()) {
        "running" -> "RUNNING"
        "starting" -> "STARTING"
        "stopped" -> "STOPPED"
        "needslogin", "needs_login" -> "NEEDS_LOGIN"
        "needsmachineauth", "needs_machine_auth" -> "NEEDS_MACHINE_AUTH"
        "error" -> "ERROR"
        else -> state.uppercase()
    }

    private fun setError(id: String, message: String) {
        _lastErrors.value = _lastErrors.value + (id to message)
        TSLog.e("MultiProxySession", "$id: $message")
    }

    private fun clearError(id: String) {
        _lastErrors.value = _lastErrors.value - id
    }

    private const val maxAddressCrossovers = 50

    fun recordAddressCrossover(ip: String, candidateTailnetIDsCSV: String, chosenTailnetID: String) {
        val message = "Address $ip is claimed by more than one connected tailnet ($candidateTailnetIDsCSV) - using $chosenTailnetID"
        TSLog.w("MultiProxySession", message)
        _addressCrossovers.value =
            (_addressCrossovers.value + AddressCrossover(
                ip = ip,
                candidateTailnetIDs = candidateTailnetIDsCSV.split(",").filter { it.isNotEmpty() },
                chosenTailnetID = chosenTailnetID,
                timestampMillis = System.currentTimeMillis(),
            )).takeLast(maxAddressCrossovers)
    }
}

data class AddressCrossover(
    val ip: String,
    val candidateTailnetIDs: List<String>,
    val chosenTailnetID: String,
    val timestampMillis: Long,
)

data class UpstreamHealthEvent(
    val upstreamId: String,
    val ready: Boolean,
    val reason: String,
    val timestampMillis: Long,
)
