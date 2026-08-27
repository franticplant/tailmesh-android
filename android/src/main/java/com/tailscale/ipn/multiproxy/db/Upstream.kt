// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.multiproxy.db

/**
 * The kinds of non-Tailnet upstream the app can configure.
 *
 * Tailnets are upstreams too, but they are not stored here: they have their own lifecycle in
 * [ProfileRepository] and reach the engine through it. `@direct` is built in and likewise has no
 * row.
 *
 * SOCKS5 is deliberately the generic escape hatch. Xray-core, sing-box, v2ray and hysteria all
 * expose a local SOCKS5 listener, so this one kind makes every one of them usable without the app
 * taking on their dependencies.
 */
enum class UpstreamKind {
  SOCKS5,
  WIREGUARD;

  companion object {
    fun fromStorage(value: String): UpstreamKind? = entries.firstOrNull { it.name == value }
  }
}

/**
 * One configured upstream, minus its secrets.
 *
 * The configuration itself - a SOCKS5 password, a WireGuard private key - is held separately in
 * [com.tailscale.ipn.multiproxy.UpstreamSecretStore], which is backed by
 * EncryptedSharedPreferences. Nothing sensitive is written to the profiles database.
 *
 * @param via another upstream's id to reach this one through, or empty to reach it from the device.
 *   Chaining is resolved in Go at dial time; a chain that would loop is refused when the upstream is
 *   registered.
 */
data class Upstream(
    val id: String,
    val kind: UpstreamKind,
    val label: String,
    val via: String = "",
    val enabled: Boolean = true,
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
)

/**
 * The user's choice of upstream for one installed app.
 *
 * Keyed by package name, not UID: a UID is only stable until the app is reinstalled, while the
 * choice is about the app. The UID is resolved from the package at VPN build time, and a binding
 * whose package is gone is dropped then.
 */
data class AppBinding(
    val packageName: String,
    val upstreamId: String,
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
)
