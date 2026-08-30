// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.multiproxy.db

data class TailnetProfile(
    val id: String,
    val displayName: String,
    val enabled: Boolean,
    val provisioningState: ProvisioningState,
    val createdAt: Long,
    val updatedAt: Long,
    val sourceProfileId: String? = null,
    val owner: UpstreamOwner = UpstreamOwner.IDLE,
    val standardSelected: Boolean = false,
    val migrationVersion: Int = 1,
)

enum class UpstreamOwner {
  IDLE,
  STANDARD,
  MULTIPROXY
}

enum class ProvisioningState {
  UNPROVISIONED,
  PROVISIONING,
  READY,
  ERROR
}

enum class RuntimeState {
  NOT_LOADED,
  STARTING,
  RUNNING,
  STOPPED,
  ERROR
}
