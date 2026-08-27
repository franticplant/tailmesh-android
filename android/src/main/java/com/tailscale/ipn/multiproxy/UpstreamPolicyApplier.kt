// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.multiproxy

import android.content.Context
import android.content.pm.PackageManager
import com.tailscale.ipn.multiproxy.db.AppBindingRepository
import com.tailscale.ipn.multiproxy.db.Upstream
import com.tailscale.ipn.multiproxy.db.UpstreamKind
import com.tailscale.ipn.multiproxy.db.UpstreamRepository
import com.tailscale.ipn.util.TSLog
import libtailscale.Libtailscale
import libtailscale.MultiProxyEngine
import org.json.JSONArray
import org.json.JSONObject

/**
 * Pushes the stored upstreams and per-app bindings into a running engine.
 *
 * The engine holds no configuration of its own across restarts; the database and the encrypted
 * config store are the source of truth, and this is what reconciles the two. It runs once per VPN
 * (re)build, at the same lifecycle point as the split-tunnel package list.
 *
 * Nothing here is fatal. An upstream that fails to register is logged and skipped, leaving the rest
 * of the configuration in force - which for a policy rule naming the missing upstream means its
 * traffic fails closed, not that it silently goes somewhere else.
 */
class UpstreamPolicyApplier(
    context: Context,
    private val upstreams: UpstreamRepository,
    private val bindings: AppBindingRepository,
    private val secrets: UpstreamSecretStore,
    private val settings: RoutingSettings,
) {
  private val packageManager: PackageManager = context.applicationContext.packageManager

  fun apply(engine: MultiProxyEngine) {
    val desired = upstreams.registrationOrder()
    removeStale(engine, desired)
    register(engine, desired)
    applyPolicy(engine)
  }

  /**
   * Unregisters upstreams the engine still holds that are no longer configured or have been
   * disabled.
   *
   * A rebuild can reuse a live engine, so without this a deleted upstream would keep working until
   * the process restarted - the one case where the UI and the datapath could disagree about whether
   * traffic is still flowing through something.
   *
   * Tailnets and the built-in direct upstream are skipped: neither is ours to remove.
   */
  private fun removeStale(engine: MultiProxyEngine, desired: List<Upstream>) {
    val keep = desired.map { it.id }.toSet()
    val registered =
        try {
          JSONArray(engine.upstreamsJSON)
        } catch (e: Exception) {
          TSLog.e(TAG, "could not read registered upstreams: $e")
          return
        }

    for (i in 0 until registered.length()) {
      val entry = registered.optJSONObject(i) ?: continue
      val id = entry.optString("id")
      val kind = entry.optString("kind")
      if (id.isEmpty() || id in keep) continue
      if (kind != KIND_SOCKS5 && kind != KIND_WIREGUARD) continue
      try {
        engine.removeUpstream(id)
      } catch (e: Exception) {
        TSLog.e(TAG, "could not remove upstream $id: $e")
      }
    }
  }

  private fun register(engine: MultiProxyEngine, desired: List<Upstream>) {
    for (upstream in desired) {
      val config = secrets.getConfig(upstream.id)
      if (config.isNullOrEmpty()) {
        // The row exists but its configuration does not. That can only happen if
        // the encrypted store was cleared independently of the database, so say
        // so rather than registering something half-configured.
        TSLog.e(TAG, "upstream ${upstream.id} has no stored configuration; skipping")
        continue
      }
      try {
        when (upstream.kind) {
          UpstreamKind.SOCKS5 -> registerSocks5(engine, upstream, config)
          UpstreamKind.WIREGUARD -> engine.addWireGuardUpstream(upstream.id, config)
        }
      } catch (e: Exception) {
        TSLog.e(TAG, "could not register upstream ${upstream.id}: $e")
      }
    }
  }

  private fun registerSocks5(engine: MultiProxyEngine, upstream: Upstream, config: String) {
    val json = JSONObject(config)
    engine.addSOCKS5UpstreamVia(
        upstream.id,
        json.optString("address"),
        json.optString("username"),
        json.optString("password"),
        upstream.via,
    )
  }

  /**
   * Resolves each binding's package to a UID and installs the resulting policy.
   *
   * Package to UID is resolved here rather than stored, because a UID is only stable until the app
   * is reinstalled while the binding is meant to outlive that. A binding whose package is no longer
   * installed is dropped for this session; the row stays, so reinstalling the app restores it.
   */
  private fun applyPolicy(engine: MultiProxyEngine) {
    val entries = JSONArray()
    for ((packageName, upstreamId) in bindings.getAllImmediate()) {
      val uid =
          try {
            packageManager.getPackageUid(packageName, 0)
          } catch (e: PackageManager.NameNotFoundException) {
            TSLog.d(TAG, "binding for $packageName ignored; package is not installed")
            continue
          }
      entries.put(JSONObject().put("appUid", uid).put("upstream", upstreamId))
    }

    // Broad capture (RoutingSettings.broadCaptureEnabled) hands the engine
    // ordinary internet and LAN traffic it never used to see. Turning that on
    // must not, by itself, change behaviour for an app the user has not
    // routed anywhere: with no explicit default the newly-captured traffic
    // would otherwise fall into the legacy subnet-route/exit-node chain
    // (nat_router.go's resolveFlow), which was never meant to carry ordinary
    // internet traffic. Direct - dial straight from the device, same as
    // today's un-captured behaviour - is the safe default in that case.
    val defaultUpstream =
        settings.defaultUpstreamId.ifEmpty {
          if (settings.broadCaptureEnabled) Libtailscale.multiProxyDirectUpstreamID() else ""
        }

    val policy =
        try {
          Libtailscale.buildAppBindingPolicyJSON(
              entries.toString(),
              defaultUpstream,
              settings.defaultDNSUpstreamId,
              settings.lanExclusionEnabled)
        } catch (e: Exception) {
          TSLog.e(TAG, "could not build routing policy: $e")
          return
        }

    try {
      engine.setPolicyJSON(policy)
    } catch (e: Exception) {
      TSLog.e(TAG, "could not apply routing policy: $e")
    }
  }

  companion object {
    private const val TAG = "UpstreamPolicyApplier"
    private const val KIND_SOCKS5 = "socks5"
    private const val KIND_WIREGUARD = "wireguard"
  }
}
