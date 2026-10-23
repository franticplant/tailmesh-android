// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package com.tailscale.ipn.multiproxy

import android.content.Context
import com.tailscale.ipn.App
import com.tailscale.ipn.NetworkChangeCallback
import com.tailscale.ipn.util.TSLog
import java.util.concurrent.Executors
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * "Direct tailnet connections over cable or hotspot" (Multi-Tailnet only).
 *
 * Off by default. When on, the tailnets' sockets are left unbound from the active Wi-Fi or mobile
 * network (still VPN-protected), so a peer on the phone's USB tether or hotspot is reached directly
 * instead of through a relay - but only while that is safe for IPv6, which the engine decides from
 * the network inventory (libtailscale/multiproxy/direct_links.go). This re-applies on every network
 * change and when the engine starts.
 */
object DirectLinks {
  private const val TAG = "DirectLinks"
  private const val PREFS = "direct-links"
  private const val KEY_ENABLED = "enabled"

  /** Mirrors multiproxy.DirectLinksState. */
  @Serializable
  data class State(
      val setting: Boolean = false,
      val unbind: Boolean = false,
      val reason: String = "",
      val defaultNetwork: String = "",
      val defaultHasIpv6: Boolean = false,
      val otherIpv6Networks: List<String> = emptyList(),
      val ignoredIpv6Networks: List<String> = emptyList(),
      val unbound: Boolean = false,
      val byNodeAttr: Boolean = false,
      val changedAtMillis: Long = 0,
      val reboundAtMillis: Long = 0,
      val reboundNodes: Int = 0,
      val reboundFailedNodes: Int = 0,
  )

  private val json = Json { ignoreUnknownKeys = true }

  // One thread: evaluations stay in order, and network callbacks (which hold
  // NetworkChangeCallback's lock) never wait on the engine.
  private val executor = Executors.newSingleThreadExecutor { r -> Thread(r, "direct-links") }

  private val _enabled = MutableStateFlow(false)
  val enabled: StateFlow<Boolean> = _enabled

  private val _state = MutableStateFlow(State())
  /** The last state the engine reported; reason "not-running" while Multi-Tailnet is off. */
  val state: StateFlow<State> = _state

  @Volatile private var initialized = false

  fun init(context: Context) {
    _enabled.value = prefs(context).getBoolean(KEY_ENABLED, false)
    initialized = true
  }

  fun setEnabled(context: Context, on: Boolean) {
    prefs(context).edit().putBoolean(KEY_ENABLED, on).apply()
    _enabled.value = on
    reevaluate("setting")
  }

  /** Re-applies the setting against the current networks, off the caller's thread. */
  fun reevaluate(why: String) {
    executor.execute {
      try {
        apply(why)
      } catch (e: Exception) {
        TSLog.w(TAG, "reevaluate ($why) failed: $e")
      }
    }
  }

  /** Same as [reevaluate] but waits for the result; for remote control. */
  fun reevaluateNow(why: String): State = executor.submit<State> { apply(why) }.get()

  private fun apply(why: String): State {
    if (!initialized) init(App.get())
    val engine = App.get().multiProxySession.engine
    if (engine == null) {
      val s = State(setting = _enabled.value, reason = "not-running")
      _state.value = s
      return s
    }
    val inventory = NetworkInventory.toJson(NetworkChangeCallback.networkInventory())
    val raw = engine.applyDirectLinks(_enabled.value, inventory)
    val s =
        try {
          json.decodeFromString<State>(raw)
        } catch (e: Exception) {
          TSLog.w(TAG, "bad state from engine: $e")
          State(setting = _enabled.value, reason = "unknown")
        }
    if (s != _state.value) TSLog.d(TAG, "$why: ${s.reason} unbound=${s.unbound}")
    _state.value = s
    return s
  }

  /** The engine's current view, with the effective binding read fresh. */
  fun current(): State {
    val engine = App.get().multiProxySession.engine ?: return _state.value
    return try {
      json.decodeFromString<State>(engine.getDirectLinksJSON())
    } catch (e: Exception) {
      _state.value
    }
  }

  /**
   * Which network an IPv6 packet from a magicsock-like socket would leave through right now, as the
   * engine's raw JSON ({unbound, localAddr, network, error}); null while Multi-Tailnet is off.
   */
  fun probeIPv6(): String? {
    val engine = App.get().multiProxySession.engine ?: return null
    return engine.probeDirectLinksIPv6JSON(
        NetworkInventory.toJson(NetworkChangeCallback.networkInventory()))
  }

  /** One plain line for the Settings subtitle. */
  fun describe(s: State, enabled: Boolean): String =
      when {
        !enabled && s.byNodeAttr ->
            "Off here, but a tailnet's admin settings already unbind sockets"
        !enabled -> "Off"
        s.reason == "not-running" -> "On; applies while Multi-Tailnet runs"
        s.reason == "on" -> "Active"
        s.reason == "off-ipv6-unsafe" ->
            "Paused: ${s.otherIpv6Networks.joinToString()} has IPv6 and " +
                "${s.defaultNetwork.ifEmpty { "the default network" }} doesn't"
        s.reason == "off-no-network-info" -> "Paused: no network information yet"
        else -> s.reason
      }

  private fun prefs(context: Context) =
      context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
