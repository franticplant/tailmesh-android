// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.multiproxy.db

/**
 * One configured tailnet-facing inbound listener: a connection a tailnet peer opens to [upstream]'s
 * node on [listenPort] is forwarded to [localTarget] on the device. See
 * `libtailscale/multiproxy/inbound_listener.go`'s `InboundListenerConfig` for the engine-side
 * counterpart this is reconciled against.
 *
 * @param proxyProtocol whether to prepend a PROXY protocol v2 header carrying the real tailnet peer
 *   address, so the local service can recover the true source rather than seeing the engine's
 *   loopback.
 * @param enabled the user's intent - whether this listener should be running. A listener the engine
 *   has actually stopped because its tailnet became unavailable (see
 *   [com.tailscale.ipn.multiproxy.UpstreamPolicyApplier]) stays enabled=true here; the UI shows
 *   that distinction by comparing this against the live engine, not by flipping this flag.
 */
data class InboundListenerRecord(
    val id: String,
    val upstream: String,
    val listenPort: Int,
    val localTarget: String,
    val proxyProtocol: Boolean = false,
    val enabled: Boolean = true,
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
)
