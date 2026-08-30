// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn

import com.tailscale.ipn.ui.viewModel.MultiProxyPeer
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Test

class MultiProxyPeerJsonTest {
  private val json = Json { ignoreUnknownKeys = true }

  @Test
  fun parsesAuthoritativePeerSnapshotSchema() {
    val payload =
        """
            [{
              "tailnetId":"profile-1",
              "hostname":"server.example.ts.net.",
              "currentIpv4":"100.64.0.10",
              "currentIpv6":"fd7a:115c:a1e0::1",
              "syntheticDnsName":"server.0123456789abcdef0123456789abcdef.proxy.",
              "syntheticIpv6":"fd9b:8d7c:6a5e:1:2:3:4:5",
              "kind":"tailscale-node"
            }]
        """
            .trimIndent()

    val peers = json.decodeFromString<List<MultiProxyPeer>>(payload)
    assertEquals(1, peers.size)
    assertEquals("profile-1", peers.single().tailnetId)
    assertEquals("100.64.0.10", peers.single().currentIpv4)
    assertEquals("fd7a:115c:a1e0::1", peers.single().currentIpv6)
    assertEquals(
        "server.0123456789abcdef0123456789abcdef.proxy.",
        peers.single().syntheticDnsName,
    )
    assertEquals("fd9b:8d7c:6a5e:1:2:3:4:5", peers.single().syntheticIpv6)
  }
}
