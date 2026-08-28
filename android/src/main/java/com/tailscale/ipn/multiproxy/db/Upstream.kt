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
  WIREGUARD,

  /**
   * A dedicated node identity, logged into some tailnet, pinned to route through one of that
   * tailnet's peers. Unlike a plain Tailnet upstream this exists purely to be dialed for ordinary
   * internet traffic - see `upstream_exitnode.go`. It costs a real device slot in that tailnet's
   * admin console, which is why it is its own opt-in kind rather than automatic.
   *
   * This is the "I want two+ exit nodes active from the same tailnet at once" path. Picking a
   * single exit node for a tailnet you already have configured is cheaper and does not need a row
   * here at all - see `ProfileRepository`/`MultiProxyEngine.setTailnetExitNode`.
   */
  EXITNODE;

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
    /** kind=EXITNODE only: which tailnet the peer below was picked from. Informational. */
    val sourceTailnetId: String = "",
    /** kind=EXITNODE only: the chosen peer's Tailscale IP. */
    val peerAddr: String = "",
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
    // Splits where this app's DNS lookups go from where its data goes; empty
    // means "same as upstreamId", today's auto-follow behaviour. Only takes
    // effect alongside a non-empty upstreamId - see COL_BINDING_DNS_UPSTREAM.
    val dnsUpstreamId: String = "",
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
)

/**
 * Orders upstreams so that every chain parent precedes the upstreams chained behind it.
 *
 * Registration order does not affect correctness - `via` is resolved in Go at dial time, not at
 * registration - but registering a parent first means the cycle check sees the real graph, and a
 * dial made immediately after registration finds its parent already there.
 *
 * An upstream in a cycle, or one whose parent is not in the list at all, is still returned rather
 * than dropped. Go refuses a cycle with a clear error, and a chained upstream whose parent is
 * missing fails closed at dial time; either is better than this function silently deciding an
 * upstream the user configured does not exist.
 *
 * Kept out of [UpstreamRepository] so it can be tested without a database.
 */
fun orderByChain(upstreams: List<Upstream>): List<Upstream> {
  val byId = upstreams.associateBy { it.id }
  val ordered = mutableListOf<Upstream>()
  val placed = mutableSetOf<String>()
  val visiting = mutableSetOf<String>()

  fun place(upstream: Upstream) {
    // Already emitted, or reached again while placing its own ancestors - which is
    // what a cycle looks like from here. Either way, stop rather than recurse.
    if (upstream.id in placed || upstream.id in visiting) return
    visiting += upstream.id
    byId[upstream.via]?.let { place(it) }
    visiting -= upstream.id
    if (placed.add(upstream.id)) ordered += upstream
  }

  upstreams.forEach(::place)
  return ordered
}
