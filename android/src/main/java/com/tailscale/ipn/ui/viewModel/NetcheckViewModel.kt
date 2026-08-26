// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.viewModel

import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import libtailscale.Libtailscale

@Serializable
data class DERPRegionLatency(
    val regionID: Int,
    val regionCode: String,
    val regionName: String,
    val latencyMs: Double
)

@Serializable
data class NetcheckReport(
    val udp: Boolean = false,
    val ipv4: Boolean = false,
    val ipv6: Boolean = false,
    val mappingVariesByDestIP: Boolean = false,
    val upnp: Boolean = false,
    val pmp: Boolean = false,
    val captivePortal: Boolean = false,
    val preferredDERP: Int = 0,
    val derpLatencies: List<DERPRegionLatency> = emptyList(),
    val error: String? = null
)

class NetcheckViewModel : IpnViewModel() {
  private val _reportState = MutableStateFlow<NetcheckReport?>(null)
  val reportState: StateFlow<NetcheckReport?> = _reportState

  private val _isLoading = MutableStateFlow(false)
  val isLoading: StateFlow<Boolean> = _isLoading

  private val json = Json { ignoreUnknownKeys = true }

  init {
    refreshNetcheck()
  }

  fun refreshNetcheck() {
    if (_isLoading.value) return
    _isLoading.value = true
    viewModelScope.launch {
      val rawJson = withContext(Dispatchers.IO) { Libtailscale.runNetcheck() }
      try {
        val parsed = json.decodeFromString<NetcheckReport>(rawJson)
        _reportState.value = parsed
      } catch (e: Exception) {
        _reportState.value = NetcheckReport(error = "Failed to parse report: ${e.message}")
      } finally {
        _isLoading.value = false
      }
    }
  }
}
