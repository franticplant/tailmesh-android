// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.multiproxy.db

/**
 * One configured inbound SOCKS5 listener, minus its optional username/password.
 *
 * Mirrors [Upstream]: the credential itself lives in
 * [com.tailscale.ipn.multiproxy.UpstreamSecretStore.saveListenerAuth], not here - nothing sensitive
 * is written to this database. See `libtailscale/multiproxy/socks5_listener.go`'s
 * `SOCKS5ListenerConfig` for the engine-side counterpart this is reconciled against.
 *
 * @param enabled the user's intent - whether this listener should be running. A listener the engine
 *   has actually stopped because its upstream became unavailable (see
 *   [com.tailscale.ipn.multiproxy.UpstreamPolicyApplier]) stays enabled=true here; the UI shows
 *   that distinction by comparing this against the live upstream's own runtime state, not by
 *   flipping this flag - flipping it would be indistinguishable from the user having turned the
 *   listener off themselves, and would not turn back on automatically once the upstream recovers.
 */
data class SOCKS5ListenerRecord(
    val id: String,
    val bindAddr: String,
    val port: Int,
    val upstream: String,
    val hasAuth: Boolean = false,
    val enabled: Boolean = true,
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
)
