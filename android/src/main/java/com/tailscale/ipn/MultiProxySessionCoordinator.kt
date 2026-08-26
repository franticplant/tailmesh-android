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

    // Address crossovers: a real (non-synthetic) Tailscale IP was claimed by
    // more than one active tailnet at once and the engine picked one
    // best-effort. Kept as a small accumulating log (not a keyed map like
    // lastErrors) since more than one distinct crossover can be worth seeing,
    // and it isn't tied to a single profile id the way an error is.
    private val _addressCrossovers = MutableStateFlow<List<AddressCrossover>>(emptyList())
    val addressCrossovers: StateFlow<List<AddressCrossover>> = _addressCrossovers.asStateFlow()

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
                delay(1000)
            }
        }
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
            return
        }

        val snapshots = try {
            json.decodeFromString<List<TailnetRuntimeSnapshot>>(engine.getTailnetStatesJSON())
        } catch (e: Exception) {
            TSLog.e("MultiProxySession", "Failed to decode runtime state: ${e.message}")
            return
        }

        _runtimeStates.value = snapshots.associate { it.tailnetId to normalizeRuntimeState(it.state) }
        _machineNames.value = snapshots.mapNotNull { snapshot ->
            snapshot.machineName.takeIf { it.isNotBlank() }?.let { snapshot.tailnetId to it }
        }.toMap()

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
