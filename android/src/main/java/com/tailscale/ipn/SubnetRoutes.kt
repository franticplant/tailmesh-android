// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn

import kotlinx.serialization.Serializable

/** One route accepted from a tailnet peer (Engine.GetSubnetRoutesJSON). */
@Serializable
data class AcceptedSubnet(
    val prefix: String,
    val tailnetId: String,
    val peer: String = "",
)

/** One tailnet advertising a prefix that another enabled tailnet also advertises. */
@Serializable
data class SubnetConflictCandidate(
    val tailnetId: String,
    val peer: String = "",
    val chosen: Boolean = false,
)

@Serializable
data class SubnetConflict(
    val prefix: String,
    val candidates: List<SubnetConflictCandidate> = emptyList(),
)

/** The engine's accepted-subnet table plus exact-prefix conflicts. */
@Serializable
data class SubnetRoutesSnapshot(
    val accepted: List<AcceptedSubnet> = emptyList(),
    val conflicts: List<SubnetConflict> = emptyList(),
) {
  /**
   * A stable key for the routes that affect the VPN's route table. Peer names are deliberately left
   * out: a peer rename does not need a TUN rebuild.
   */
  fun routeKey(): String =
      accepted.sortedWith(compareBy({ it.prefix }, { it.tailnetId })).joinToString("|") {
        "${it.prefix}@${it.tailnetId}"
      }
}
