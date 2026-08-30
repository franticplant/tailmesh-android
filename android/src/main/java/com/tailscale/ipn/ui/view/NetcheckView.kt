// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.view

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.tailscale.ipn.ui.viewModel.DERPRegionLatency
import com.tailscale.ipn.ui.viewModel.NetcheckReport
import com.tailscale.ipn.ui.viewModel.NetcheckViewModel

@Composable
fun NetcheckView(onBack: () -> Unit, viewModel: NetcheckViewModel = viewModel()) {
  val report by viewModel.reportState.collectAsState()
  val isLoading by viewModel.isLoading.collectAsState()

  Scaffold(
      topBar = {
        Header(
            title = { Text("Network Diagnostics") },
            onBack = onBack,
            actions = {
              IconButton(onClick = { viewModel.refreshNetcheck() }, enabled = !isLoading) {
                Icon(
                    imageVector = Icons.Default.Refresh,
                    contentDescription = "Refresh Netcheck",
                    tint = MaterialTheme.colorScheme.onSurface)
              }
            })
      }) { innerPadding ->
        Box(modifier = Modifier.padding(innerPadding).fillMaxSize()) {
          if (isLoading && report == null) {
            Column(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally) {
                  CircularProgressIndicator()
                  Spacer(modifier = Modifier.height(16.dp))
                  Text(
                      text = "Probing NAT & DERP Relays...",
                      style = MaterialTheme.typography.bodyMedium,
                      color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
          } else {
            val r = report
            if (r?.error != null) {
              Column(
                  modifier = Modifier.fillMaxSize().padding(16.dp),
                  verticalArrangement = Arrangement.Center,
                  horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text = r.error ?: "Diagnostic error",
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.error)
                  }
            } else if (r != null) {
              LazyColumn(
                  modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp),
                  verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    item { Spacer(modifier = Modifier.height(8.dp)) }
                    item { NetcheckHeroCard(r) }
                    item {
                      Text(
                          text = "Global DERP Relay Latencies",
                          style = MaterialTheme.typography.titleMedium,
                          fontWeight = FontWeight.Bold,
                          color = MaterialTheme.colorScheme.onSurface)
                    }
                    items(r.derpLatencies) { item -> DERPLatencyRow(item, r.preferredDERP) }
                    item { Spacer(modifier = Modifier.height(16.dp)) }
                  }
            }
          }
        }
      }
}

@Composable
fun NetcheckHeroCard(report: NetcheckReport) {
  Surface(
      modifier = Modifier.fillMaxWidth(),
      shape = RoundedCornerShape(16.dp),
      color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f)) {
        Column(modifier = Modifier.padding(16.dp)) {
          Row(
              verticalAlignment = Alignment.CenterVertically,
              horizontalArrangement = Arrangement.SpaceBetween,
              modifier = Modifier.fillMaxWidth()) {
                Text(
                    text = "NAT Connection Type",
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                val natType =
                    if (report.udp && !report.mappingVariesByDestIP) "Direct UDP Mesh"
                    else if (report.udp) "Restricted / CGNAT" else "Relay Only"
                val natColor =
                    if (report.udp && !report.mappingVariesByDestIP) Color(0xFF2E7D32)
                    else Color(0xFFE65100)
                BadgeChip(text = natType, backgroundColor = natColor)
              }

          Spacer(modifier = Modifier.height(12.dp))
          Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            BadgeChip(
                text = if (report.ipv4) "IPv4 Active" else "IPv4 Off",
                backgroundColor = if (report.ipv4) Color(0xFF1976D2) else Color.Gray)
            BadgeChip(
                text = if (report.ipv6) "IPv6 Active" else "IPv6 Off",
                backgroundColor = if (report.ipv6) Color(0xFF7B1FA2) else Color.Gray)
            if (report.upnp) {
              BadgeChip(text = "UPnP", backgroundColor = Color(0xFF00796B))
            }
            if (report.pmp) {
              BadgeChip(text = "NAT-PMP", backgroundColor = Color(0xFF00796B))
            }
          }
        }
      }
}

@Composable
fun DERPLatencyRow(latency: DERPRegionLatency, preferredRegionID: Int) {
  val isPreferred = latency.regionID == preferredRegionID
  Surface(
      modifier = Modifier.fillMaxWidth(),
      shape = RoundedCornerShape(12.dp),
      color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)) {
        Row(
            modifier = Modifier.padding(16.dp).fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween) {
              Column {
                Row(verticalAlignment = Alignment.CenterVertically) {
                  Text(
                      text = latency.regionName,
                      style = MaterialTheme.typography.bodyLarge,
                      fontWeight = FontWeight.SemiBold,
                      color = MaterialTheme.colorScheme.onSurface)
                  if (isPreferred) {
                    Spacer(modifier = Modifier.width(8.dp))
                    BadgeChip(text = "Preferred", backgroundColor = Color(0xFF2E7D32))
                  }
                }
                Text(
                    text = "${latency.regionCode} (ID: ${latency.regionID})",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
              }

              val pingColor =
                  when {
                    latency.latencyMs < 50.0 -> Color(0xFF2E7D32)
                    latency.latencyMs < 150.0 -> Color(0xFFF57F17)
                    else -> Color(0xFFC62828)
                  }
              Text(
                  text = "${latency.latencyMs.toInt()} ms",
                  style = MaterialTheme.typography.titleMedium,
                  fontWeight = FontWeight.Bold,
                  color = pingColor)
            }
      }
}

@Composable
fun BadgeChip(text: String, backgroundColor: Color) {
  Surface(
      shape = RoundedCornerShape(8.dp),
      color = backgroundColor.copy(alpha = 0.15f),
      contentColor = backgroundColor) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelMedium.copy(fontSize = 11.sp),
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp))
      }
}
