// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.view

import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import com.tailscale.ipn.App
import com.tailscale.ipn.R
import com.tailscale.ipn.multiproxy.CaptureSettings
import com.tailscale.ipn.multiproxy.PacketCaptures
import com.tailscale.ipn.ui.util.InstalledAppsManager
import java.io.File
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

private enum class CaptureMode {
  OFF,
  ALL,
  APPS,
  LISTENERS,
}

/**
 * Records raw IP traffic crossing the VPN tunnel to a .pcapng file, either every packet or only
 * packets belonging to a chosen set of apps. Every packet, in either mode, carries a per-packet
 * comment naming its owning app (see PacketCaptures.appNamesLines) - see multiproxy/capture.go for
 * how attribution and the size cap work on the Go side.
 */
@Composable
fun PacketCaptureView(backToSettings: BackNavigation) {
  val context = LocalContext.current
  val scope = rememberCoroutineScope()

  var mode by rememberSaveable { mutableStateOf(CaptureMode.ALL) }
  // Shared with the remote-control API, so a capture started from either
  // place is visible in both. See PacketCaptures.
  val activeCapture by PacketCaptures.active.collectAsState()
  val isCapturing = activeCapture != null
  var errorMessage by remember { mutableStateOf<String?>(null) }
  var bytesWritten by remember { mutableStateOf(0L) }
  var packetCount by remember { mutableStateOf(0L) }
  var capacityReached by remember { mutableStateOf(false) }
  var capturePath by remember { mutableStateOf<String?>(null) }

  val captureSettings = remember { CaptureSettings(context) }
  var maxAgeDays by remember { mutableStateOf(captureSettings.maxAgeDays) }
  var pastCaptures by remember { mutableStateOf<List<File>>(emptyList()) }

  fun refreshPastCaptures() {
    pastCaptures = PacketCaptures.purgeExpiredAndList(context, maxAgeDays)
  }

  // Runs once per visit to this screen - see PacketCaptures.purgeExpiredAndList's doc
  // comment for why "on screen open" is the whole cleanup schedule, not just
  // the initial listing.
  LaunchedEffect(Unit) { refreshPastCaptures() }

  var searchQuery by rememberSaveable { mutableStateOf("") }
  var selectedPackages by rememberSaveable { mutableStateOf(setOf<String>()) }
  var selectedListenerIds by rememberSaveable { mutableStateOf(setOf<String>()) }
  val listeners by App.get().multiProxySession.socks5ListenerRepository.listeners.collectAsState()

  val installedAppsManager = remember { InstalledAppsManager(App.get().packageManager) }
  val installedApps = remember { installedAppsManager.fetchInstalledApps() }
  val filteredApps =
      remember(installedApps, searchQuery) {
        if (searchQuery.isBlank()) installedApps
        else
            installedApps.filter {
              it.name.contains(searchQuery, ignoreCase = true) ||
                  it.packageName.contains(searchQuery, ignoreCase = true)
            }
      }

  // Live size/packet count while a capture is running. A capture is a
  // "polling-heavy job" in the sense the overnight backlog's polling
  // guidance was written for, so this checks in every few seconds rather
  // than on every recomposition.
  LaunchedEffect(isCapturing) {
    while (isCapturing) {
      val stats = PacketCaptures.stats()
      bytesWritten = stats.bytesWritten
      packetCount = stats.packetCount
      capacityReached = stats.capacityReached
      delay(3000)
    }
  }

  // A capture started remotely becomes this screen's current one too.
  LaunchedEffect(activeCapture) {
    activeCapture?.let {
      capturePath = it
      bytesWritten = 0L
      packetCount = 0L
      capacityReached = false
    }
    refreshPastCaptures()
  }

  fun startCapture() {
    errorMessage = null
    try {
      when (mode) {
        CaptureMode.ALL -> PacketCaptures.startAll()
        CaptureMode.APPS -> PacketCaptures.startApps(selectedPackages)
        CaptureMode.LISTENERS -> PacketCaptures.startListeners(selectedListenerIds)
        CaptureMode.OFF -> return
      }
    } catch (ex: Exception) {
      errorMessage = ex.message ?: "Failed to start capture"
    }
  }

  fun stopCapture() {
    PacketCaptures.stop()
    scope.launch {
      val stats = PacketCaptures.stats()
      bytesWritten = stats.bytesWritten
      packetCount = stats.packetCount
      capacityReached = stats.capacityReached
      // The file itself was already complete and on disk the moment the
      // capture started - stopping only closes the Go side's writer.
      // Refreshing here is what makes it show up in "Past captures" instead
      // of only being reachable through capturePath's in-memory,
      // this-composition-only state.
      refreshPastCaptures()
    }
  }

  fun exportCapture(target: File? = null) {
    val file = target ?: capturePath?.let { File(it) } ?: return
    if (!file.exists()) {
      errorMessage = "Capture file no longer exists"
      return
    }
    val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
    val intent =
        Intent(Intent.ACTION_SEND).apply {
          // pcapng, not classic pcap - "application/vnd.tcpdump.pcap" would be
          // misleading here (that MIME's classic-format connotation is exactly
          // what per-packet app-name comments needed to move away from).
          // There's no registered pcapng MIME type, so this is generic; every
          // pcapng-capable tool (Wireshark included) identifies the format
          // from its magic bytes, not the MIME type on the share intent.
          type = "application/octet-stream"
          putExtra(Intent.EXTRA_STREAM, uri)
          addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
    context.startActivity(Intent.createChooser(intent, file.name))
  }

  fun clearCapture(target: File? = null) {
    val deletingCurrent = target == null || target.absolutePath == capturePath
    if (deletingCurrent && isCapturing) stopCapture()
    val file = target ?: capturePath?.let { File(it) }
    file?.delete()
    if (deletingCurrent) {
      capturePath = null
      bytesWritten = 0L
      packetCount = 0L
      capacityReached = false
    }
    refreshPastCaptures()
  }

  Scaffold(topBar = { Header(titleRes = R.string.packet_capture, onBack = backToSettings) }) {
      innerPadding ->
    LazyColumn(modifier = Modifier.padding(innerPadding)) {
      item("explanation") {
        ListItem(headlineContent = { Text(stringResource(R.string.packet_capture_explanation)) })
      }

      item("modeChips") {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
          FilterChip(
              selected = mode == CaptureMode.ALL,
              enabled = !isCapturing,
              onClick = { mode = CaptureMode.ALL },
              label = { Text(stringResource(R.string.packet_capture_mode_all)) },
          )
          FilterChip(
              selected = mode == CaptureMode.APPS,
              enabled = !isCapturing,
              onClick = { mode = CaptureMode.APPS },
              label = { Text(stringResource(R.string.packet_capture_mode_apps)) },
          )
          FilterChip(
              selected = mode == CaptureMode.LISTENERS,
              enabled = !isCapturing,
              onClick = { mode = CaptureMode.LISTENERS },
              label = { Text(stringResource(R.string.packet_capture_mode_listeners)) },
          )
        }
      }

      if (mode == CaptureMode.APPS && !isCapturing) {
        item("search") {
          OutlinedTextField(
              value = searchQuery,
              onValueChange = { searchQuery = it },
              modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
              placeholder = { Text(stringResource(R.string.packet_capture_search_hint)) },
              leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
              singleLine = true,
          )
        }
        items(filteredApps, key = { it.packageName }) { app ->
          ListItem(
              headlineContent = { Text(app.name) },
              leadingContent = {
                Checkbox(
                    checked = selectedPackages.contains(app.packageName),
                    onCheckedChange = { checked ->
                      selectedPackages =
                          if (checked) selectedPackages + app.packageName
                          else selectedPackages - app.packageName
                    })
              },
          )
        }
      }

      if (mode == CaptureMode.LISTENERS && !isCapturing) {
        if (listeners.isEmpty()) {
          item("listenersEmpty") {
            ListItem(
                headlineContent = { Text(stringResource(R.string.packet_capture_listeners_empty)) })
          }
        } else {
          items(listeners, key = { it.id }) { listener ->
            ListItem(
                headlineContent = { Text("${listener.bindAddr}:${listener.port}") },
                supportingContent = { Text(listener.upstream) },
                leadingContent = {
                  Checkbox(
                      checked = selectedListenerIds.contains(listener.id),
                      onCheckedChange = { checked ->
                        selectedListenerIds =
                            if (checked) selectedListenerIds + listener.id
                            else selectedListenerIds - listener.id
                      })
                },
            )
          }
        }
      }

      item("startStop") {
        Row(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
          if (!isCapturing) {
            val noAppsSelected = mode == CaptureMode.APPS && selectedPackages.isEmpty()
            val noListenersSelected = mode == CaptureMode.LISTENERS && selectedListenerIds.isEmpty()
            val disabled = noAppsSelected || noListenersSelected
            Button(onClick = { startCapture() }, enabled = !disabled) {
              Text(stringResource(R.string.packet_capture_start))
            }
            if (noAppsSelected) {
              Text(
                  stringResource(R.string.packet_capture_no_apps_selected),
                  style = MaterialTheme.typography.bodySmall,
                  modifier = Modifier.padding(start = 12.dp),
                  color = MaterialTheme.colorScheme.error)
            }
            if (noListenersSelected) {
              Text(
                  stringResource(R.string.packet_capture_no_listeners_selected),
                  style = MaterialTheme.typography.bodySmall,
                  modifier = Modifier.padding(start = 12.dp),
                  color = MaterialTheme.colorScheme.error)
            }
          } else {
            Button(onClick = { stopCapture() }) {
              Text(stringResource(R.string.packet_capture_stop))
            }
          }
        }
      }

      errorMessage?.let { msg ->
        item("error") {
          Text(
              msg,
              color = MaterialTheme.colorScheme.error,
              modifier = Modifier.padding(horizontal = 16.dp))
        }
      }

      item("statusDivider") { HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp)) }

      item("status") {
        val sizeLabel =
            if (bytesWritten < 1024 * 1024) "${bytesWritten / 1024} KB"
            else "%.1f MB".format(bytesWritten / (1024.0 * 1024.0))
        Text(
            capturePath?.let { "${File(it).name}: $sizeLabel, $packetCount packets" }
                ?: stringResource(R.string.packet_capture_no_file),
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(horizontal = 16.dp))
        if (capacityReached) {
          Text(
              stringResource(R.string.packet_capture_capacity_reached),
              style = MaterialTheme.typography.bodySmall,
              color = MaterialTheme.colorScheme.error,
              modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
        }
      }

      item("exportClear") {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
          val hasFile = capturePath != null
          OutlinedButton(onClick = { exportCapture() }, enabled = hasFile) {
            Text(stringResource(R.string.packet_capture_export))
          }
          OutlinedButton(onClick = { clearCapture() }, enabled = hasFile) {
            Text(stringResource(R.string.packet_capture_clear))
          }
        }
      }

      item("retentionDivider") { HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp)) }

      item("retention") {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
          Text(
              stringResource(R.string.packet_capture_retention_label),
              style = MaterialTheme.typography.bodyMedium,
              modifier = Modifier.padding(top = 12.dp))
          OutlinedButton(
              onClick = {
                maxAgeDays = (maxAgeDays - 1).coerceAtLeast(1)
                captureSettings.maxAgeDays = maxAgeDays
                refreshPastCaptures()
              }) {
                Text("-")
              }
          Text(
              stringResource(R.string.packet_capture_retention_days, maxAgeDays),
              style = MaterialTheme.typography.bodyMedium,
              modifier = Modifier.padding(top = 12.dp))
          OutlinedButton(
              onClick = {
                maxAgeDays += 1
                captureSettings.maxAgeDays = maxAgeDays
                refreshPastCaptures()
              }) {
                Text("+")
              }
        }
      }

      item("pastCapturesHeader") {
        ListItem(
            headlineContent = { Text(stringResource(R.string.packet_capture_past_header)) },
        )
      }

      // Excludes the file the status section above already shows, so a
      // capture in progress (or just stopped) isn't listed twice.
      val otherCaptures = pastCaptures.filter { it.absolutePath != capturePath }
      if (otherCaptures.isEmpty()) {
        item("pastCapturesEmpty") {
          ListItem(headlineContent = { Text(stringResource(R.string.packet_capture_past_empty)) })
        }
      } else {
        items(otherCaptures, key = { it.absolutePath }) { file ->
          val sizeLabel =
              if (file.length() < 1024 * 1024) "${file.length() / 1024} KB"
              else "%.1f MB".format(file.length() / (1024.0 * 1024.0))
          ListItem(
              headlineContent = { Text(file.name) },
              supportingContent = { Text(sizeLabel) },
              trailingContent = {
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                  OutlinedButton(onClick = { exportCapture(file) }) {
                    Text(stringResource(R.string.packet_capture_export))
                  }
                  OutlinedButton(onClick = { clearCapture(file) }) {
                    Text(stringResource(R.string.packet_capture_delete))
                  }
                }
              },
          )
        }
      }
    }
  }
}
