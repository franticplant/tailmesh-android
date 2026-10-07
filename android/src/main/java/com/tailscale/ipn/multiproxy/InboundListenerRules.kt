// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.multiproxy

import com.tailscale.ipn.multiproxy.db.InboundListenerRecord

/**
 * Pure validation/normalisation for tailnet-facing inbound listeners, kept out of the ViewModel so
 * it can be unit-tested on the host with no Android or engine involved (see
 * InboundListenerRulesTest). Mirrors the checks the Go engine repeats authoritatively in
 * AddInboundListener - this is only here so the UI can reject obviously-bad input before a round
 * trip, not a substitute for the engine's own validation.
 */
object InboundListenerRules {

  /** The listen port, or null if [raw] is not a number in 1..65535. */
  fun parseListenPort(raw: String): Int? = raw.trim().toIntOrNull()?.takeIf { it in 1..65535 }

  /**
   * A normalised `host:port` local target, or null if [raw] is not one. A bracketed IPv6 literal
   * (`[::1]:22`) is handled; an unbracketed one is not, matching the engine's net.SplitHostPort.
   */
  fun parseLocalTarget(raw: String): String? {
    val trimmed = raw.trim()
    if (trimmed.isEmpty()) return null
    val host: String
    val portPart: String
    if (trimmed.startsWith("[")) {
      val close = trimmed.indexOf(']')
      if (close < 0 || close + 1 >= trimmed.length || trimmed[close + 1] != ':') return null
      host = trimmed.substring(1, close)
      portPart = trimmed.substring(close + 2)
    } else {
      val colon = trimmed.lastIndexOf(':')
      if (colon <= 0) return null
      host = trimmed.substring(0, colon)
      portPart = trimmed.substring(colon + 1)
    }
    val port = portPart.toIntOrNull() ?: return null
    if (host.isBlank() || port !in 1..65535) return null
    return "$host:$port"
  }

  /**
   * The listeners that should be registered with the engine right now: the user has them switched
   * on and their tailnet is currently available. This is the filter
   * [com.tailscale.ipn.multiproxy.UpstreamPolicyApplier.applyInboundListeners] applies; extracted
   * so the "disabling the tailnet pauses its listeners" rule is testable directly.
   */
  fun desired(
      configured: List<InboundListenerRecord>,
      availableTailnetIds: Set<String>,
  ): List<InboundListenerRecord> =
      configured.filter { it.enabled && it.upstream in availableTailnetIds }
}
