// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.multiproxy

import android.content.Context
import android.content.pm.PackageManager
import com.tailscale.ipn.App
import com.tailscale.ipn.ui.util.InstalledAppsManager
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Packet capture control, shared by the Packet capture screen and the remote-control API.
 *
 * The engine allows one capture at a time; [active] is the path of the running one, so a capture
 * started from either place shows up in the other.
 */
object PacketCaptures {
  /**
   * Bounds one capture file - see capture.go's defaultCaptureMaxBytes for the equivalent Go-side
   * rationale. Passed explicitly rather than 0 (the Go default) so the "Capacity reached" message
   * has a number to refer to.
   */
  const val DEFAULT_MAX_BYTES = 32L * 1024 * 1024

  private val _active = MutableStateFlow<String?>(null)
  val active: StateFlow<String?> = _active.asStateFlow()

  data class Stats(val bytesWritten: Long, val packetCount: Long, val capacityReached: Boolean)

  fun capturesDir(context: Context = App.get()): File {
    val dir = File(context.filesDir, "captures")
    dir.mkdirs()
    return dir
  }

  /**
   * Deletes every capture file older than [maxAgeDays], then returns whatever remains, newest
   * first.
   *
   * This is the whole retention mechanism: no scheduled job, no background timer. It costs one
   * listFiles plus one lastModified check per existing capture file, so calling it every time the
   * list is shown is negligible, and no capture outlives the next look at the list after it
   * expires.
   */
  fun purgeExpiredAndList(
      context: Context = App.get(),
      maxAgeDays: Int = CaptureSettings(context).maxAgeDays,
  ): List<File> {
    val cutoff = System.currentTimeMillis() - TimeUnit.DAYS.toMillis(maxAgeDays.toLong())
    val files = capturesDir(context).listFiles() ?: emptyArray()
    val (expired, kept) = files.partition { it.lastModified() < cutoff && it.path != active.value }
    expired.forEach { it.delete() }
    return kept.sortedByDescending { it.lastModified() }
  }

  /**
   * "uid:name" per line, one per installed app - passed to the engine so every captured packet's
   * pcapng comment can name its owning app, not just the selected ones (see capture.go's
   * packetCapture.start for why "All traffic" mode wants attribution too). Built fresh at each
   * start, so a newly installed app gets a name.
   */
  fun appNamesLines(): String =
      InstalledAppsManager(App.get().packageManager)
          .fetchInstalledApps()
          .mapNotNull { app -> uidFor(app.packageName)?.let { uid -> "$uid:${app.name}" } }
          .joinToString("\n")

  fun uidFor(packageName: String): Int? =
      try {
        App.get().packageManager.getApplicationInfo(packageName, 0).uid
      } catch (e: PackageManager.NameNotFoundException) {
        null
      }

  /** Captures every packet. Returns the capture file's path. */
  fun startAll(maxBytes: Long = DEFAULT_MAX_BYTES): String = start { e, path ->
    e.startPacketCaptureAll(path, maxBytes, appNamesLines())
  }

  /** Captures only packets of the given apps. Returns the capture file's path. */
  fun startApps(packageNames: Collection<String>, maxBytes: Long = DEFAULT_MAX_BYTES): String {
    val uids =
        packageNames.map { pkg -> uidFor(pkg) ?: throw ControlException("No installed app $pkg") }
    if (uids.isEmpty()) throw ControlException("Choose at least one app to capture")
    return start { e, path ->
      e.startPacketCaptureApps(uids.joinToString(","), path, maxBytes, appNamesLines())
    }
  }

  /** Captures traffic through the given inbound SOCKS5 listeners. Returns the file's path. */
  fun startListeners(listenerIds: Collection<String>, maxBytes: Long = DEFAULT_MAX_BYTES): String {
    if (listenerIds.isEmpty()) throw ControlException("Choose at least one listener to capture")
    return start { e, path ->
      e.startPacketCaptureSOCKS5Listeners(listenerIds.joinToString(","), path, maxBytes)
    }
  }

  @Synchronized
  private fun start(begin: (libtailscale.MultiProxyEngine, String) -> Unit): String {
    val e =
        App.get().multiProxySession.engine
            ?: throw ControlException("VPN engine not running yet - connect and try again")
    if (_active.value != null) throw ControlException("A capture is already running")
    val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
    // .pcapng, not .pcap: per-packet app-name comments require pcapng's
    // per-block options, which the classic pcap format has no room for.
    val file = File(capturesDir(), "capture-$stamp.pcapng")
    try {
      begin(e, file.absolutePath)
    } catch (ex: Exception) {
      throw ControlException(ex.message ?: "Failed to start capture")
    }
    _active.value = file.absolutePath
    return file.absolutePath
  }

  /** Stops the running capture, if any, and returns its path. */
  @Synchronized
  fun stop(): String? {
    App.get().multiProxySession.engine?.stopPacketCapture()
    val path = _active.value
    _active.value = null
    return path
  }

  /** Live counters of the running (or most recently stopped) capture. */
  fun stats(): Stats {
    val e = App.get().multiProxySession.engine ?: return Stats(0, 0, false)
    return Stats(
        e.packetCaptureBytesWritten(),
        e.packetCapturePacketCount(),
        e.packetCaptureCapacityReached(),
    )
  }

  /** Deletes a capture file, stopping it first if it is the running one. */
  fun delete(path: String) {
    val file = File(path).canonicalFile
    if (file.parentFile != capturesDir().canonicalFile) {
      throw ControlException("Not a capture file")
    }
    if (path == _active.value) stop()
    file.delete()
  }
}
