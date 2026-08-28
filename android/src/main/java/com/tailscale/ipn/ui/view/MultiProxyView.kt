package com.tailscale.ipn.ui.view

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.tailscale.ipn.VpnRuntimeMode
import com.tailscale.ipn.ui.viewModel.ExitNodeCandidate
import com.tailscale.ipn.ui.viewModel.MultiProxyViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MultiProxyView(
    viewModel: MultiProxyViewModel = viewModel(),
    onNavigateBack: () -> Unit,
    onAddAccount: () -> Unit,
    onAddAuthKey: () -> Unit,
) {
    val uiStates by viewModel.uiStates.collectAsState()
    val regularProfiles by viewModel.regularProfiles.collectAsState()
    val peers by viewModel.peers.collectAsState()
    val activeMode by viewModel.activeMode.collectAsState()
    val addressCrossovers by viewModel.addressCrossovers.collectAsState()
    val addressConflicts by viewModel.addressConflicts.collectAsState()
    var showAddDialog by remember { mutableStateOf(false) }
    var renameId by remember { mutableStateOf<String?>(null) }
    var renameValue by remember { mutableStateOf("") }
    var deleteId by remember { mutableStateOf<String?>(null) }
    var exitNodeTailnetId by remember { mutableStateOf<String?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Upstreams") },
                navigationIcon = {
                    Text(
                        "Back",
                        modifier = Modifier.clickable { onNavigateBack() }.padding(8.dp),
                    )
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { showAddDialog = true }) { Text("+") }
        },
    ) { padding ->
        LazyColumn(contentPadding = padding, modifier = Modifier.fillMaxSize()) {
            item {
                Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                    val modeLabel = when (activeMode) {
                        VpnRuntimeMode.MULTIPROXY -> "Active VPN mode: Multi-Tailnet"
                        VpnRuntimeMode.STANDARD -> "Active VPN mode: Standard (single upstream)"
                        VpnRuntimeMode.STOPPED -> "VPN is stopped"
                    }
                    Text(modeLabel, style = MaterialTheme.typography.titleMedium)
                    Spacer(modifier = Modifier.height(8.dp))
                    if (activeMode == VpnRuntimeMode.MULTIPROXY) {
                        OutlinedButton(onClick = viewModel::stopMultiProxy) { Text("Stop Multi-Tailnet") }
                    } else {
                        Button(onClick = viewModel::startMultiProxy) { Text("Start Multi-Tailnet") }
                    }
                }
            }

            if (addressConflicts.isNotEmpty()) {
                item {
                    val hitIPs = addressCrossovers.map { it.ip }.toSet()
                    Card(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(
                                "Conflicting addresses",
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.onErrorContainer,
                            )
                            Text(
                                "Tailscale draws real addresses from one pool shared by every tailnet, so " +
                                    "these addresses belong to a different machine on each connected tailnet. " +
                                    "One is picked automatically. Use a machine's name instead of its address " +
                                    "to avoid the ambiguity entirely.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onErrorContainer,
                                modifier = Modifier.padding(top = 4.dp, bottom = 8.dp),
                            )
                            addressConflicts.forEach { conflict ->
                                val claimants = conflict.candidates.joinToString(", ") { candidate ->
                                    val name = candidate.hostname.trimEnd('.').ifBlank { candidate.tailnetId }
                                    "$name (${candidate.tailnetId})"
                                }
                                val chosen = conflict.chosenTailnetId.ifBlank { null }
                                Text(
                                    buildString {
                                        append(conflict.ip)
                                        append(": ")
                                        append(claimants)
                                        append(if (chosen != null) " - using $chosen" else " - unreachable, no claimant is connected")
                                        if (conflict.ip in hitIPs) append(" - traffic has used this")
                                    },
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onErrorContainer,
                                    modifier = Modifier.padding(vertical = 2.dp),
                                )
                            }
                        }
                    }
                }
            }

            // Crossovers observed in traffic for addresses that are no longer
            // in conflict (a peer left since) still belong on screen: a
            // connection may already have been sent somewhere unexpected.
            if (addressCrossovers.any { c -> addressConflicts.none { it.ip == c.ip } }) {
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(
                                "Earlier ambiguous traffic",
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.onErrorContainer,
                            )
                            Text(
                                "Traffic went to these addresses while more than one connected tailnet " +
                                    "claimed them, so it may have reached the wrong machine. They are no " +
                                    "longer in conflict.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onErrorContainer,
                                modifier = Modifier.padding(top = 4.dp, bottom = 8.dp),
                            )
                            addressCrossovers
                                .filter { c -> addressConflicts.none { it.ip == c.ip } }
                                .takeLast(10).reversed().forEach { crossover ->
                                Text(
                                    "${crossover.ip}: claimed by ${crossover.candidateTailnetIDs.joinToString(", ")} " +
                                        "- using ${crossover.chosenTailnetID}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onErrorContainer,
                                    modifier = Modifier.padding(vertical = 2.dp),
                                )
                            }
                        }
                    }
                }
            }

            if (regularProfiles.isNotEmpty()) {
                item {
                    Text("Accounts", style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(16.dp))
                }
                items(regularProfiles, key = { "account:" + it.ID }) { profile ->
                    val imported = uiStates.any { it.profile.sourceProfileId == profile.ID }
                    Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp)) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(profile.NetworkProfile?.tailnetNameForDisplay() ?: profile.Name, style = MaterialTheme.typography.titleLarge)
                            Text(profile.Name)
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 8.dp)) {
                                Button(onClick = { viewModel.useStandardProfile(profile) }) { Text("Use Standard") }
                                OutlinedButton(
                                    enabled = !imported,
                                    onClick = { viewModel.importRegularProfile(profile) },
                                ) { Text(if (imported) "Added to Multi" else "Add to Multi") }
                            }
                        }
                    }
                }
            }

            if (uiStates.isEmpty()) {
                item {
                    Text(
                        "No multiproxy upstreams configured. Add an account above or provision one with an auth key.",
                        modifier = Modifier.padding(16.dp),
                    )
                }
            }

            items(uiStates, key = { "upstream:" + it.profile.id }) { state ->
                Card(modifier = Modifier.fillMaxWidth().padding(8.dp)) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(state.profile.displayName, style = MaterialTheme.typography.titleLarge)
                        Text("Included in Multi: ${if (state.profile.enabled) "Enabled" else "Disabled"}")
                        Text("Active in current Multi session: ${if (activeMode == VpnRuntimeMode.MULTIPROXY && state.runtimeState == "RUNNING") "Yes" else "No"}")
                        Text("Provisioning: ${state.profile.provisioningState}")
                        Text("Runtime: " + state.runtimeState)
                        if (state.machineName.isNotBlank()) {
                            Text("Machine: " + state.machineName)
                        }
                        if (state.exitNodeIp.isNotBlank()) {
                            Text("Exit node: " + state.exitNodeIp)
                        }
                        state.lastError?.let {
                            Text(
                                "Error: $it",
                                color = MaterialTheme.colorScheme.error,
                            )
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Button(
                                onClick = {
                                    viewModel.toggleProfile(state.profile.id, !state.profile.enabled)
                                },
                            ) {
                                Text(if (state.profile.enabled) "Disable" else "Enable")
                            }
                            OutlinedButton(
                                onClick = {
                                    renameId = state.profile.id
                                    renameValue = state.profile.displayName
                                },
                            ) { Text("Rename") }
                            OutlinedButton(
                                enabled = state.runtimeState == "RUNNING",
                                onClick = { exitNodeTailnetId = state.profile.id },
                            ) { Text("Exit node") }
                            Button(
                                onClick = { deleteId = state.profile.id },
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = MaterialTheme.colorScheme.error,
                                ),
                            ) { Text("Forget") }
                        }
                    }
                }
            }

            if (peers.isNotEmpty()) {
                item {
                    Text(
                        "Discovered Peers",
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.padding(8.dp),
                    )
                }
                items(peers, key = { "peer:" + it.tailnetId + ":" + it.syntheticIpv6 }) { peer ->
                    Card(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp),
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(peer.hostname, style = MaterialTheme.typography.titleSmall)
                            Text("Tailnet ID: ${peer.tailnetId}")
                            Text("Synthetic DNS: ${peer.syntheticDnsName}")
                            Text("Synthetic IPv6: ${peer.syntheticIpv6}")
                            if (peer.currentIpv4.isNotBlank() && peer.currentIpv4 != "invalid IP") {
                                Text("Current Tailnet IPv4: ${peer.currentIpv4}")
                            }
                            if (peer.currentIpv6.isNotBlank() && peer.currentIpv6 != "invalid IP") {
                                Text("Current Tailnet IPv6: ${peer.currentIpv6}")
                            }
                        }
                    }
                }
            }
        }

        if (showAddDialog) {
            AlertDialog(
                onDismissRequest = { showAddDialog = false },
                title = { Text("Add upstream") },
                text = { Text("Authenticate once as a regular account, then enable it for Standard or Multi-Tailnet mode.") },
                confirmButton = {
                    Button(onClick = { showAddDialog = false; onAddAccount() }) { Text("Web login") }
                },
                dismissButton = {
                    TextButton(onClick = { showAddDialog = false; onAddAuthKey() }) { Text("Auth key") }
                },
            )
        }

        renameId?.let { id ->
            AlertDialog(
                onDismissRequest = { renameId = null },
                title = { Text("Rename Tailnet") },
                text = {
                    OutlinedTextField(
                        value = renameValue,
                        onValueChange = { renameValue = it },
                        label = { Text("Display Name") },
                    )
                },
                confirmButton = {
                    Button(
                        enabled = renameValue.isNotBlank(),
                        onClick = {
                            viewModel.renameProfile(id, renameValue.trim())
                            renameId = null
                        },
                    ) { Text("Rename") }
                },
                dismissButton = {
                    TextButton(onClick = { renameId = null }) { Text("Cancel") }
                },
            )
        }

        exitNodeTailnetId?.let { tailnetId ->
            // fetchExitNodeCandidates makes a live, JNI-crossing Status() call
            // (up to a 5s timeout in Go) - fetched off the main thread in
            // LaunchedEffect, not synchronously in remember{}, so opening
            // this dialog never blocks composition.
            var candidates by remember(tailnetId) { mutableStateOf<List<ExitNodeCandidate>>(emptyList()) }
            LaunchedEffect(tailnetId) {
                candidates = withContext(Dispatchers.IO) { viewModel.fetchExitNodeCandidates(tailnetId) }
            }
            var selected by remember(tailnetId) { mutableStateOf<ExitNodeCandidate?>(null) }
            // Pre-select whichever candidate matches the tailnet's actual,
            // currently-active exit node IP (from the live runtime poll -
            // see MultiProxySessionCoordinator.exitNodeIps) once candidates
            // load, so reopening this dialog shows real state instead of
            // always starting blank. Only runs while nothing has been
            // clicked locally yet, so it doesn't clobber an in-progress pick.
            val currentExitNodeIp = uiStates.firstOrNull { it.profile.id == tailnetId }?.exitNodeIp.orEmpty()
            LaunchedEffect(tailnetId, candidates, currentExitNodeIp) {
                if (selected == null && currentExitNodeIp.isNotBlank()) {
                    selected = candidates.firstOrNull { it.ip == currentExitNodeIp }
                }
            }
            AlertDialog(
                onDismissRequest = { exitNodeTailnetId = null },
                title = { Text("Exit node") },
                text = {
                    Column {
                        Text(
                            "Route this tailnet's own general internet traffic through one of its " +
                                "peers, in place - no extra device or auth key needed. Only one can " +
                                "be active per tailnet this way.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        if (candidates.isEmpty()) {
                            Text(
                                "No peers offer to be an exit node on this tailnet.",
                                style = MaterialTheme.typography.bodySmall,
                            )
                        } else {
                            candidates.forEach { candidate ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable { selected = candidate }
                                        .padding(vertical = 8.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    RadioButton(
                                        selected = selected?.id == candidate.id,
                                        onClick = { selected = candidate },
                                    )
                                    Text("${candidate.hostname} (${candidate.ip})")
                                }
                            }
                        }
                    }
                },
                confirmButton = {
                    Button(
                        enabled = selected != null,
                        onClick = {
                            viewModel.setTailnetExitNode(tailnetId, selected?.ip.orEmpty())
                            exitNodeTailnetId = null
                        },
                    ) { Text("Use") }
                },
                dismissButton = {
                    Row {
                        TextButton(onClick = {
                            viewModel.setTailnetExitNode(tailnetId, "")
                            exitNodeTailnetId = null
                        }) { Text("Clear") }
                        TextButton(onClick = { exitNodeTailnetId = null }) { Text("Cancel") }
                    }
                },
            )
        }

        deleteId?.let { id ->
            AlertDialog(
                onDismissRequest = { deleteId = null },
                title = { Text("Forget Tailnet?") },
                text = {
                    Text(
                        "This removes the local Tailnet identity and saved state. Disable the profile instead if you want to preserve its identity for later.",
                    )
                },
                confirmButton = {
                    Button(
                        onClick = {
                            viewModel.deleteProfile(id)
                            deleteId = null
                        },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.error,
                        ),
                    ) { Text("Forget") }
                },
                dismissButton = {
                    TextButton(onClick = { deleteId = null }) { Text("Cancel") }
                },
            )
        }
    }
}
