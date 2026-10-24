// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.TrafficStats
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.os.SystemClock
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.ServiceCompat
import androidx.core.graphics.drawable.IconCompat
import com.tailscale.ipn.util.TSLog
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * The status-bar speed meter: the phone's download and upload rate, drawn as the icon of an ongoing
 * notification, which is the only place an app can put anything next to the clock.
 *
 * The rate is what crosses the phone's Wi-Fi, mobile and Ethernet interfaces, read from Android's
 * per-interface counters (TrafficStats.getRxBytes(iface), Android 12+), not from Tailmesh's own
 * accounting. So it is the same with the VPN on, off or Proxy-Only, and traffic that only passes
 * through the VPN interface or between apps on the phone is not counted twice: only what physically
 * leaves or arrives does. The USB tether to a computer is not an Android network and is left out.
 *
 * Off by default; turned on in Settings or with remote control's settings.setSpeedMeter.
 */
object SpeedMeter {
  private const val TAG = "SpeedMeter"
  private const val PREFS = "speed_meter"
  private const val KEY_ENABLED = "enabled"
  // A new id because importance cannot be raised on an existing channel: the first one, LOW,
  // counted as "silent", and Pixel hides silent notifications' icons from the status bar.
  const val CHANNEL_ID = "speed-meter-statusbar"
  private const val OLD_CHANNEL_ID = "speed-meter"
  const val NOTIFICATION_ID = 0x5bee

  /** Per-interface counters need Android 12; before that there is nothing reliable to read. */
  val supported: Boolean
    get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S

  private val _enabled = MutableStateFlow(false)
  val enabled: StateFlow<Boolean> = _enabled

  /** Whether the service is running, which a start from the background may not achieve. */
  @Volatile var running = false

  /** The last rate shown, for remote control: bytes per second down and up, and the networks. */
  @Volatile var last: Rate? = null

  data class Rate(
      val rxPerSec: Long,
      val txPerSec: Long,
      val networks: List<NetworkInfo>,
      val at: Long
  )

  data class NetworkInfo(
      val iface: String,
      val transport: String,
      val rxBytes: Long,
      val txBytes: Long
  )

  fun init(context: Context) {
    _enabled.value = prefs(context).getBoolean(KEY_ENABLED, false)
  }

  fun setEnabled(context: Context, on: Boolean) {
    prefs(context).edit().putBoolean(KEY_ENABLED, on).apply()
    _enabled.value = on
    if (on) start(context) else context.stopService(Intent(context, SpeedMeterService::class.java))
  }

  /**
   * Starts the meter if it is turned on. Safe from anywhere: when Android does not allow starting a
   * foreground service right now (the app is in the background), this logs and does nothing, and
   * the next start from the app, boot or an update brings it back.
   */
  fun startIfEnabled(context: Context) {
    if (prefs(context).getBoolean(KEY_ENABLED, false)) start(context)
  }

  private fun start(context: Context) {
    if (!supported) return
    try {
      context.startForegroundService(Intent(context, SpeedMeterService::class.java))
    } catch (e: Exception) {
      TSLog.w(TAG, "could not start the speed meter now: $e")
    }
  }

  /**
   * DEFAULT importance, with no sound or vibration: anything lower is a "silent" notification, and
   * the status bar (on Pixel by default) leaves silent ones' icons out - the icon is the meter.
   */
  fun createChannel(context: Context) {
    val nm = context.getSystemService(android.app.NotificationManager::class.java)
    nm.deleteNotificationChannel(OLD_CHANNEL_ID)
    val channel =
        android.app
            .NotificationChannel(
                CHANNEL_ID,
                context.getString(R.string.speed_meter_channel),
                android.app.NotificationManager.IMPORTANCE_DEFAULT)
            .apply {
              description = context.getString(R.string.speed_meter_channel_description)
              setSound(null, null)
              enableVibration(false)
              enableLights(false)
              setShowBadge(false)
            }
    nm.createNotificationChannel(channel)
  }

  private fun prefs(context: Context) =
      context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

  /**
   * Compact rate for the icon, at most four characters: "0", "999B", "1.2K", "850K", "12M", "1.2G".
   * Bytes per second; K, M and G are powers of 1000, as speed tests use.
   */
  fun compact(bytesPerSec: Long): String {
    val b = bytesPerSec.coerceAtLeast(0)
    fun fmt(v: Double, unit: String) =
        if (v < 10) "%.1f$unit".format(java.util.Locale.ROOT, v).replace(".0$unit", unit)
        else "${v.toLong()}$unit"
    return when {
      b == 0L -> "0"
      b < 1000 -> "${b}B"
      b < 999_500 -> fmt(b / 1e3, "K")
      b < 999_500_000 -> fmt(b / 1e6, "M")
      else -> fmt(b / 1e9, "G")
    }
  }

  /** The same rate for the notification text, e.g. "1.2 MB/s". */
  fun readable(bytesPerSec: Long): String {
    val b = bytesPerSec.coerceAtLeast(0).toDouble()
    return when {
      b < 1e3 -> "${b.toLong()} B/s"
      b < 1e6 -> "%.1f KB/s".format(java.util.Locale.ROOT, b / 1e3)
      b < 1e9 -> "%.1f MB/s".format(java.util.Locale.ROOT, b / 1e6)
      else -> "%.2f GB/s".format(java.util.Locale.ROOT, b / 1e9)
    }
  }

  /**
   * The rate over a short sliding window of cumulative counter samples. Android's per-interface
   * counters advance in batches, so two samples a second apart often differ by nothing and the next
   * pair by twice the real rate; over about three seconds that evens out, and a stop in traffic
   * still shows as 0 within the window.
   */
  class RateWindow(private val windowMs: Long = 3_000) {
    private data class Sample(val at: Long, val rx: Long, val tx: Long)

    private val samples = ArrayDeque<Sample>()

    /** Forgets every sample, e.g. after the screen was off, so nothing averages over that gap. */
    fun reset() = samples.clear()

    /**
     * Adds the counters read at [at] (milliseconds, monotonic) and returns the rate in bytes per
     * second down and up, or null until there are two samples.
     */
    fun add(at: Long, rx: Long, tx: Long): Pair<Long, Long>? {
      val last = samples.lastOrNull()
      // A counter going back (an interface went away) or time not moving: start again.
      if (last != null && (rx < last.rx || tx < last.tx || at <= last.at)) samples.clear()
      samples.addLast(Sample(at, rx, tx))
      // Keep the newest sample at or before the window's start, so the span covers the window.
      while (samples.size > 2 && samples[1].at <= at - windowMs) samples.removeFirst()
      val first = samples.first()
      if (samples.size < 2) return null
      val ms = at - first.at
      return (rx - first.rx) * 1000 / ms to (tx - first.tx) * 1000 / ms
    }
  }

  /** Starts the meter after a reboot, if it was on. */
  class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
      if (intent.action == Intent.ACTION_BOOT_COMPLETED) startIfEnabled(context)
    }
  }
}

/** Keeps the speed meter's notification up to date, once a second while the screen is on. */
class SpeedMeterService : Service() {
  private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
  private var loop: Job? = null

  /** The non-VPN internet networks Android has, by network: interface and transport. */
  private val networks = ConcurrentHashMap<Network, Pair<String, String>>()
  private var callback: ConnectivityManager.NetworkCallback? = null

  override fun onBind(intent: Intent?): IBinder? = null

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    if (!SpeedMeter.supported) {
      stopSelf()
      return START_NOT_STICKY
    }
    SpeedMeter.createChannel(this)
    ServiceCompat.startForeground(
        this,
        SpeedMeter.NOTIFICATION_ID,
        build(0, 0, emptyList()),
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        else 0)
    SpeedMeter.running = true
    watchNetworks()
    if (loop == null) loop = scope.launch { run() }
    return START_STICKY
  }

  override fun onDestroy() {
    scope.cancel()
    callback?.let {
      try {
        getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it)
      } catch (_: Exception) {}
    }
    callback = null
    SpeedMeter.last = null
    SpeedMeter.running = false
    super.onDestroy()
  }

  private fun watchNetworks() {
    if (callback != null) return
    val cm = getSystemService(ConnectivityManager::class.java)
    val cb =
        object : ConnectivityManager.NetworkCallback() {
          private val caps = ConcurrentHashMap<Network, NetworkCapabilities>()

          override fun onCapabilitiesChanged(network: Network, nc: NetworkCapabilities) {
            caps[network] = nc
            update(network, cm.getLinkProperties(network), nc)
          }

          override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
            update(network, lp, caps[network] ?: cm.getNetworkCapabilities(network))
          }

          override fun onLost(network: Network) {
            caps.remove(network)
            networks.remove(network)
          }
        }
    // The default request already asks for NOT_VPN, so the VPN's own interface, which carries the
    // same bytes a second time, never shows up.
    cm.registerNetworkCallback(NetworkRequest.Builder().build(), cb)
    callback = cb
  }

  private fun update(network: Network, lp: LinkProperties?, nc: NetworkCapabilities?) {
    val iface = lp?.interfaceName
    if (iface == null || nc == null) {
      networks.remove(network)
      return
    }
    val transport =
        when {
          nc.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
          nc.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "mobile"
          nc.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
          else -> null
        }
    if (transport == null) networks.remove(network) else networks[network] = iface to transport
  }

  private suspend fun run() {
    val power = getSystemService(PowerManager::class.java)
    val window = SpeedMeter.RateWindow()
    var shown: String? = null
    while (scope.isActive) {
      PerfCounters.inc("kt.speedMeterTick")
      if (!power.isInteractive) {
        // Nobody sees the status bar; don't wake up every second for it. Start a fresh window
        // afterwards, or the first reading would average over the whole time the screen was off.
        window.reset()
        delay(5_000)
        continue
      }
      val sample = sample()
      val rate =
          window.add(
              SystemClock.elapsedRealtime(),
              sample.sumOf { it.rxBytes },
              sample.sumOf { it.txBytes })
      if (rate != null) {
        val (down, up) = rate
        SpeedMeter.last = SpeedMeter.Rate(down, up, sample, System.currentTimeMillis())
        // Post only when something visible changed: the icon, the text or the networks.
        val key =
            "${SpeedMeter.readable(down)} ${SpeedMeter.readable(up)} ${sample.map { it.transport }.distinct()}"
        if (key != shown) {
          notify(build(down, up, sample))
          shown = key
        }
      }
      delay(1_000)
    }
  }

  /** Cumulative counters of every tracked interface; an interface on two networks counts once. */
  private fun sample(): List<SpeedMeter.NetworkInfo> =
      networks.values
          .distinctBy { it.first }
          .mapNotNull { (iface, transport) ->
            val rx = TrafficStats.getRxBytes(iface)
            val tx = TrafficStats.getTxBytes(iface)
            if (rx < 0 || tx < 0) null else SpeedMeter.NetworkInfo(iface, transport, rx, tx)
          }

  private fun notify(n: Notification) {
    try {
      NotificationManagerCompat.from(this).notify(SpeedMeter.NOTIFICATION_ID, n)
    } catch (e: SecurityException) {
      // No notification permission: the service still runs, there is just nothing to see.
    }
  }

  private fun build(down: Long, up: Long, sample: List<SpeedMeter.NetworkInfo>): Notification {
    val open =
        PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java)
                .setFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
    val via =
        sample
            .map { it.transport }
            .distinct()
            .joinToString(" + ") {
              when (it) {
                "wifi" -> "Wi-Fi"
                "mobile" -> getString(R.string.speed_meter_mobile)
                else -> "Ethernet"
              }
            }
    return NotificationCompat.Builder(this, SpeedMeter.CHANNEL_ID)
        .setSmallIcon(IconCompat.createWithBitmap(icon(down, up)))
        .setContentTitle("↓ ${SpeedMeter.readable(down)}   ↑ ${SpeedMeter.readable(up)}")
        .setContentText(via.ifEmpty { getString(R.string.speed_meter_no_network) })
        .setContentIntent(open)
        .setOngoing(true)
        .setOnlyAlertOnce(true)
        .setShowWhen(false)
        .setLocalOnly(true)
        .setCategory(NotificationCompat.CATEGORY_STATUS)
        .setPriority(NotificationCompat.PRIORITY_DEFAULT)
        .build()
  }

  private val paint =
      Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.WHITE
        typeface = Typeface.create("sans-serif-condensed", Typeface.BOLD)
        textAlign = Paint.Align.CENTER
      }

  /**
   * Download over upload, each on its own line, sized to fill a square status-bar icon. Android
   * draws only the alpha channel, tinted to match the status bar, so white on transparent is right
   * in both light and dark themes.
   */
  private fun icon(down: Long, up: Long): Bitmap {
    val size = ICON_PX
    val bmp = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
    val canvas = Canvas(bmp)
    val lines = listOf(SpeedMeter.compact(down), SpeedMeter.compact(up))
    val lineHeight = size / 2f
    // One size for both lines, the largest that fits the wider one, so they read as a pair.
    paint.textSize = lineHeight * 1.05f
    val widest = lines.maxOf { paint.measureText(it) }
    if (widest > size) paint.textSize *= size / widest
    val fm = paint.fontMetrics
    lines.forEachIndexed { i, text ->
      // Centre each line vertically in its half.
      val baseline = lineHeight * i + (lineHeight - (fm.descent + fm.ascent)) / 2
      canvas.drawText(text, size / 2f, baseline, paint)
    }
    return bmp
  }

  private companion object {
    // Status-bar icons are 24dp; at the densest common screens that is about 96px. Android scales
    // down, so drawing large keeps the text crisp.
    const val ICON_PX = 96
  }
}
