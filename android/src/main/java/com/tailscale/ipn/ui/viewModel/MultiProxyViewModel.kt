package com.tailscale.ipn.ui.viewModel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.tailscale.ipn.AddressCrossover
import com.tailscale.ipn.IPNService
import com.tailscale.ipn.MultiProxySession
import com.tailscale.ipn.MultiProxySessionCoordinator
import com.tailscale.ipn.UninitializedApp
import com.tailscale.ipn.multiproxy.db.TailnetProfile
import com.tailscale.ipn.ui.localapi.Client
import com.tailscale.ipn.ui.model.IpnLocal
import com.tailscale.ipn.util.TSLog
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class MultiProxyPeer(
    val tailnetId: String,
    val hostname: String,
    val currentIpv4: String,
    val currentIpv6: String,
    val syntheticDnsName: String,
    val syntheticIpv6: String,
    val kind: String,
)

@Serializable
data class AddressConflictCandidate(
    val tailnetId: String,
    val hostname: String = "",
    val active: Boolean = false,
)

/**
 * A real (non-synthetic) Tailscale address that more than one connected
 * tailnet currently has a peer at. Unlike [AddressCrossover], which is only
 * recorded once traffic actually hits such an address, this is derived from
 * the netmaps, so a conflict is visible before anything trips over it.
 */
@Serializable
data class AddressConflict(
    val ip: String,
    val candidates: List<AddressConflictCandidate> = emptyList(),
    val chosenTailnetId: String = "",
)

data class TailnetProfileUiState(
    val profile: TailnetProfile,
    val runtimeState: String,
    val machineName: String = "",
    val lastError: String? = null,
    val exitNodeIp: String = "",
)

class MultiProxyViewModel : ViewModel() {
    private val _uiStates = MutableStateFlow<List<TailnetProfileUiState>>(emptyList())
    val uiStates: StateFlow<List<TailnetProfileUiState>> = _uiStates.asStateFlow()

    private val _peers = MutableStateFlow<List<MultiProxyPeer>>(emptyList())
    val peers: StateFlow<List<MultiProxyPeer>> = _peers.asStateFlow()

    val activeMode: StateFlow<com.tailscale.ipn.VpnRuntimeMode> = IPNService.runtimeMode

    // Real (non-synthetic) Tailscale addresses that were claimed by more
    // than one connected tailnet at once, and which upstream the engine
    // picked for each - surfaced so a best-effort routing decision is
    // visible instead of silent.
    val addressCrossovers: StateFlow<List<AddressCrossover>> = MultiProxySessionCoordinator.addressCrossovers

    // The same ambiguity, but known ahead of time from the netmaps rather
    // than discovered by a connection going somewhere unexpected.
    private val _addressConflicts = MutableStateFlow<List<AddressConflict>>(emptyList())
    val addressConflicts: StateFlow<List<AddressConflict>> = _addressConflicts.asStateFlow()

    private val _regularProfiles = MutableStateFlow<List<IpnLocal.LoginProfile>>(emptyList())
    val regularProfiles: StateFlow<List<IpnLocal.LoginProfile>> = _regularProfiles.asStateFlow()

    private var session: MultiProxySession? = null
    private var profilesJob: Job? = null
    private var peersJob: Job? = null
    private val json = Json { ignoreUnknownKeys = true }

    fun setSession(s: MultiProxySession?) {
        if (session === s) return
        session = s
        profilesJob?.cancel()
        peersJob?.cancel()
        _peers.value = emptyList()

        if (s == null) {
            _uiStates.value = emptyList()
            return
        }

        MultiProxySessionCoordinator.bind(s)

        Client(viewModelScope).profiles { result ->
            result.onSuccess { _regularProfiles.value = it }
                .onFailure { TSLog.e("MultiProxyViewModel", "Failed to load regular profiles: " + it.message) }
        }

        profilesJob = viewModelScope.launch {
            combine(
                s.profileRepository.profiles,
                MultiProxySessionCoordinator.runtimeStates,
                MultiProxySessionCoordinator.machineNames,
                MultiProxySessionCoordinator.lastErrors,
                MultiProxySessionCoordinator.exitNodeIps,
            ) { profiles, runtimeStates, machineNames, errors, exitNodeIps ->
                profiles.map { profile ->
                    TailnetProfileUiState(
                        profile = profile,
                        runtimeState = runtimeStates[profile.id]
                            ?: if (profile.enabled) "NOT_LOADED" else "STOPPED",
                        machineName = machineNames[profile.id].orEmpty(),
                        lastError = errors[profile.id],
                        exitNodeIp = exitNodeIps[profile.id].orEmpty(),
                    )
                }
            }.collect { _uiStates.value = it }
        }

        peersJob = viewModelScope.launch {
            while (true) {
                try {
                    val jsonStr = s.engine?.getTargetsJSONV2() ?: "[]"
                    _peers.value = json.decodeFromString<List<MultiProxyPeer>>(jsonStr)
                } catch (e: Exception) {
                    TSLog.e("MultiProxyViewModel", "Failed to decode peer snapshot: ${e.message}")
                }
                try {
                    val conflictJson = s.engine?.getAddressConflictsJSON() ?: "[]"
                    _addressConflicts.value = json.decodeFromString<List<AddressConflict>>(conflictJson)
                } catch (e: Exception) {
                    TSLog.e("MultiProxyViewModel", "Failed to decode address conflicts: ${e.message}")
                }
                delay(2000)
            }
        }
    }

    fun startMultiProxy() {
        session?.let { MultiProxySessionCoordinator.startMultiProxyMode(it) }
    }

    fun stopMultiProxy() {
        session?.let { MultiProxySessionCoordinator.stopMultiProxyMode(it) }
    }

    fun addProfile(name: String, authKey: String) {
        session?.let { MultiProxySessionCoordinator.provision(it, name, authKey) }
    }

    fun useStandardProfile(profile: IpnLocal.LoginProfile) {
        Client(viewModelScope).switchProfile(profile) { result ->
            result.onSuccess { UninitializedApp.get().startVPN() }
                .onFailure { TSLog.e("MultiProxyViewModel", "Failed to switch regular profile: " + it.message) }
        }
    }

    fun importRegularProfile(profile: IpnLocal.LoginProfile) {
        session?.let {
            val name = profile.NetworkProfile?.DisplayName?.takeIf { it.isNotBlank() } ?: profile.Name
            MultiProxySessionCoordinator.importRegularProfile(it, profile.ID, name)
        }
    }

    fun toggleProfile(id: String, enabled: Boolean) {
        session?.let { MultiProxySessionCoordinator.setEnabled(it, id, enabled) }
    }

    fun deleteProfile(id: String) {
        session?.let { MultiProxySessionCoordinator.forget(it, id) }
    }

    fun renameProfile(id: String, displayName: String) {
        session?.let { MultiProxySessionCoordinator.rename(it, id, displayName) }
    }

    /**
     * Lists the peers of a running tailnet that offer to be an exit node, for picking one to
     * route that tailnet's own general internet traffic through - at no extra auth cost, since it
     * reuses the tailnet's existing node identity. See [setTailnetExitNode].
     */
    fun fetchExitNodeCandidates(tailnetId: String): List<ExitNodeCandidate> {
        val jsonStr =
            try {
                session?.engine?.getExitNodeCandidatesJSON(tailnetId) ?: "[]"
            } catch (e: Exception) {
                TSLog.e("MultiProxyViewModel", "Failed to fetch exit node candidates: ${e.message}")
                "[]"
            }
        return try {
            val arr = org.json.JSONArray(jsonStr)
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
     * Points this tailnet's own traffic at one of its peers in place - no extra auth, no extra
     * device slot. Pass an empty peerAddr to clear it. Only one exit node can be active per
     * tailnet this way; use the Upstreams screen's "exit node" upstream kind for a second,
     * simultaneously-active exit node from the same tailnet.
     */
    fun setTailnetExitNode(tailnetId: String, peerAddr: String) {
        viewModelScope.launch {
            try {
                session?.engine?.setTailnetExitNode(tailnetId, peerAddr)
            } catch (e: Exception) {
                TSLog.e("MultiProxyViewModel", "Failed to set exit node: ${e.message}")
            }
        }
    }
}
