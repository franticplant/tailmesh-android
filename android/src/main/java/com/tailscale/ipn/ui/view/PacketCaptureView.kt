// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.view

import android.content.Intent
import android.content.pm.PackageManager
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
import com.tailscale.ipn.ui.util.InstalledAppsManager
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

// captureMaxBytes bounds one capture file - see capture.go's
// defaultCaptureMaxBytes for the equivalent Go-side rationale. Kept in sync
// deliberately rather than passing 0 (the Go default) so this file also
// documents the number the "Capacity reached" message refers to.
private const val captureMaxBytes = 32L * 1024 * 1024

private enum class CaptureMode {
  OFF,
  ALL,
  APPS,
}

private fun capturesDir(context: android.content.Context): File {
  val dir = File(context.filesDir, "captures")
  dir.mkdirs()
  return dir
}

/**
 * Records raw IP traffic crossing the VPN tunnel to a .pcap file, either every packet or only
 * packets belonging to a chosen set of apps - see multiproxy/capture.go for how attribution and the
 * size cap work on the Go side.
 */
@Composable
fun PacketCaptureView(backToSettings: BackNavigation) {
  val context = LocalContext.current
  val scope = rememberCoroutineScope()
  // Fetched fresh at each use (a function, not a `val`) rather than once at composition time:
  // the engine can still be null right after this screen opens (VPN still starting up) and
  // become available moments later - capturing it once here would keep pointing at that
  // initial null for the rest of this screen's lifetime instead of picking up the real engine
  // once it exists. See validation_and_gaps.md's PCAP entry for the device-testing finding that
  // led to this - a silent no-op here left a capture attempt looking "started" in the UI with
  // no data and no file ever written.
  fun engine() = App.get().multiProxySession.engine

  var mode by rememberSaveable { mutableStateOf(CaptureMode.ALL) }
  var isCapturing by remember { mutableStateOf(false) }
  var errorMessage by remember { mutableStateOf<String?>(null) }
  var bytesWritten by remember { mutableStateOf(0L) }
  var packetCount by remember { mutableStateOf(0L) }
  var capacityReached by remember { mutableStateOf(false) }
  var capturePath by remember { mutableStateOf<String?>(null) }

  var searchQuery by rememberSaveable { mutableStateOf("") }
  var selectedPackages by rememberSaveable { mutableStateOf(setOf<String>()) }

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
      bytesWritten = engine()?.packetCaptureBytesWritten() ?: 0L
      packetCount = engine()?.packetCapturePacketCount() ?: 0L
      capacityReached = engine()?.packetCaptureCapacityReached() ?: false
      delay(3000)
    }
  }

  fun uidFor(packageName: String): Int? =
      try {
        App.get().packageManager.getApplicationInfo(packageName, 0).uid
      } catch (e: PackageManager.NameNotFoundException) {
        null
      }

  fun startCapture() {
    errorMessage = null
    val e = engine()
    if (e == null) {
      // Previously this fell through silently (Kotlin's `?.` on a null receiver just
      // evaluates to null) and still flipped isCapturing on with a filename that was never
      // actually opened by the Go side - the UI claimed a capture was running while nothing
      // was written and no file existed on disk. Surfacing it here instead of guessing why the
      // engine isn't up yet (VPN still starting, no active session, etc.) - whatever the
      // reason, "not running yet" is a real, sayable state, not silence.
      errorMessage = "VPN engine not running yet - connect and try again"
      return
    }
    val dir = capturesDir(context)
    val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
    val file = File(dir, "capture-$stamp.pcap")
    try {
      when (mode) {
        CaptureMode.ALL -> e.startPacketCaptureAll(file.absolutePath, captureMaxBytes)
        CaptureMode.APPS -> {
          val uids = selectedPackages.mapNotNull { uidFor(it) }
          e.startPacketCaptureApps(uids.joinToString(","), file.absolutePath, captureMaxBytes)
        }
        CaptureMode.OFF -> return
      }
      capturePath = file.absolutePath
      bytesWritten = 0L
      packetCount = 0L
      capacityReached = false
      isCapturing = true
    } catch (ex: Exception) {
      errorMessage = ex.message ?: "Failed to start capture"
    }
  }

  fun stopCapture() {
    val e = engine()
    e?.stopPacketCapture()
    isCapturing = false
    scope.launch {
      bytesWritten = e?.packetCaptureBytesWritten() ?: bytesWritten
      packetCount = e?.packetCapturePacketCount() ?: packetCount
      capacityReached = e?.packetCaptureCapacityReached() ?: capacityReached
    }
  }

  fun exportCapture() {
    val path = capturePath ?: return
    val file = File(path)
    if (!file.exists()) {
      errorMessage = "Capture file no longer exists"
      return
    }
    val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
    val intent =
        Intent(Intent.ACTION_SEND).apply {
          type = "application/vnd.tcpdump.pcap"
          putExtra(Intent.EXTRA_STREAM, uri)
          addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
    context.startActivity(Intent.createChooser(intent, file.name))
  }

  fun clearCapture() {
    if (isCapturing) stopCapture()
    capturePath?.let { File(it).delete() }
    capturePath = null
    bytesWritten = 0L
    packetCount = 0L
    capacityReached = false
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

      item("startStop") {
        Row(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
          if (!isCapturing) {
            val disabled = mode == CaptureMode.APPS && selectedPackages.isEmpty()
            Button(onClick = { startCapture() }, enabled = !disabled) {
              Text(stringResource(R.string.packet_capture_start))
            }
            if (disabled) {
              Text(
                  stringResource(R.string.packet_capture_no_apps_selected),
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
    }
  }
}
