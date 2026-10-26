// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.view

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.tailscale.ipn.App
import com.tailscale.ipn.R
import com.tailscale.ipn.ui.util.Lists
import com.tailscale.ipn.ui.viewModel.SOCKS5ListenersViewModel
import java.net.Inet4Address
import java.net.NetworkInterface
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

private const val AUTO_UPSTREAM = "@auto"

private data class WgPeer(
    val name: String,
    val address: String,
    val publicKey: String,
    val endpoint: String,
    val handshakeAgoSec: Long,
    val rx: Long,
    val tx: Long,
)

private data class WgListener(
    val id: String,
    val port: Int,
    val upstream: String,
    val subnet: String,
    val serverAddress: String,
    val publicKey: String,
    val dns: String,
    val dnsMode: String,
    val dnsSummary: String,
    val enabled: Boolean,
    val running: Boolean,
    val lastError: String,
    val peers: List<WgPeer>,
)

private fun parseListeners(json: String): List<WgListener> {
  val arr = JSONArray(json)
  return (0 until arr.length()).map { i ->
    val o = arr.getJSONObject(i)
    val state = mutableMapOf<String, JSONObject>()
    o.optJSONArray("peerState")?.let { ps ->
      for (j in 0 until ps.length()) ps.getJSONObject(j).let {
        state[it.optString("publicKey")] = it
      }
    }
    val peersArr = o.optJSONArray("peers") ?: JSONArray()
    WgListener(
        id = o.getString("id"),
        port = o.optInt("listenPort"),
        upstream = o.optString("upstream"),
        subnet = o.optString("subnet"),
        serverAddress = o.optString("serverAddress"),
        publicKey = o.optString("publicKey"),
        dns = o.optString("dns"),
        dnsMode = o.optString("dnsMode", "phone"),
        dnsSummary =
            if (o.optString("dnsMode") == "direct") "DNS: peers' own servers, forwarded"
            else
                "DNS: answered by this device" +
                    (if (o.optBoolean("dnsEncrypted")) " over DoH"
                    else " (plain DNS: set a DoH resolver in DNS settings)") +
                    (o.optString("peerDns").let { if (it.isNotEmpty()) "; peers use $it" else "" }),
        enabled = o.optBoolean("enabled"),
        running = o.optBoolean("running"),
        lastError = o.optString("lastError"),
        peers =
            (0 until peersArr.length()).map { j ->
              val p = peersArr.getJSONObject(j)
              val s = state[p.optString("publicKey")]
              WgPeer(
                  name = p.optString("name"),
                  address = p.optString("address"),
                  publicKey = p.optString("publicKey"),
                  endpoint = s?.optString("endpoint") ?: "",
                  handshakeAgoSec =
                      if ((s?.optLong("lastHandshakeAtMillis") ?: 0L) > 0)
                          s!!.optLong("lastHandshakeAgoSeconds")
                      else -1,
                  rx = s?.optLong("rxBytes") ?: 0,
                  tx = s?.optLong("txBytes") ?: 0,
              )
            },
    )
  }
}

/** The device's own IPv4 addresses on Wi-Fi, tether and hotspot, for a peer's Endpoint. */
private fun localIPv4Addresses(): List<String> =
    try {
      NetworkInterface.getNetworkInterfaces()
          .toList()
          .filter { it.isUp && !it.isLoopback && !it.name.startsWith("tun") }
          .flatMap { nif -> nif.inetAddresses.toList().map { nif.name to it } }
          .filter { it.second is Inet4Address }
          .sortedBy { (name, _) ->
            when {
              name.startsWith("wlan") -> 0
              name.startsWith("ncm") || name.startsWith("rndis") || name.startsWith("usb") -> 1
              name.startsWith("ap") || name.startsWith("swlan") -> 2
              else -> 3
            }
          }
          .map { it.second.hostAddress ?: "" }
          .filter { it.isNotEmpty() }
    } catch (e: Exception) {
      emptyList()
    }

private fun humanBytes(n: Long): String =
    when {
      n < 1024 -> "$n B"
      n < 1024 * 1024 -> "%.1f KB".format(n / 1024.0)
      n < 1024L * 1024 * 1024 -> "%.1f MB".format(n / 1024.0 / 1024)
      else -> "%.2f GB".format(n / 1024.0 / 1024 / 1024)
    }

/**
 * WireGuard listeners: WireGuard servers on this device (libtailscale/multiproxy/
 * wireguard_listener.go). A peer's traffic leaves through the chosen upstream, or with "Auto" is
 * routed like the device's own: tailnet addresses to their tailnet, everything else the default
 * way. Peers are added here, which shows their config to copy or share.
 */
@Composable
fun WireGuardListenersView(
    backToSettings: BackNavigation,
    upstreamModel: SOCKS5ListenersViewModel = viewModel(),
) {
  val context = LocalContext.current
  val scope = rememberCoroutineScope()
  val routable by upstreamModel.routableUpstreams.collectAsState()
  var listeners by remember { mutableStateOf<List<WgListener>>(emptyList()) }
  var engineMissing by remember { mutableStateOf(false) }
  var error by remember { mutableStateOf<String?>(null) }
  var creating by remember { mutableStateOf<WgListener?>(null) }
  var newListener by remember { mutableStateOf(false) }
  var addingPeerTo by remember { mutableStateOf<WgListener?>(null) }
  var peerConfig by remember { mutableStateOf<String?>(null) }
  var deleting by remember { mutableStateOf<WgListener?>(null) }
  var refresh by remember { mutableStateOf(0) }

  fun engine() = App.get().multiProxySession.engine

  LaunchedEffect(refresh) {
    while (true) {
      val e = engine()
      engineMissing = e == null
      if (e != null) {
        listeners =
            try {
              withContext(Dispatchers.IO) { parseListeners(e.getWireGuardListenersJSON()) }
            } catch (ex: Exception) {
              emptyList()
            }
      }
      delay(2000)
    }
  }

  fun run(block: suspend () -> Unit) {
    scope.launch {
      try {
        withContext(Dispatchers.IO) { block() }
      } catch (ex: Exception) {
        error = ex.message ?: ex.toString()
      }
      refresh++
    }
  }

  fun upstreamLabel(id: String): String =
      if (id == AUTO_UPSTREAM) "Auto (route like this device)"
      else routable.firstOrNull { it.id == id }?.label ?: id

  error?.let { message ->
    AlertDialog(
        onDismissRequest = { error = null },
        title = { Text("WireGuard listener") },
        text = { Text(message) },
        confirmButton = { TextButton(onClick = { error = null }) { Text("OK") } },
    )
  }

  deleting?.let { l ->
    AlertDialog(
        onDismissRequest = { deleting = null },
        title = { Text("Delete listener on UDP ${l.port}?") },
        text = { Text("Its peers can no longer connect; their configs stop working.") },
        confirmButton = {
          TextButton(
              onClick = {
                run { engine()?.deleteWireGuardListener(l.id) }
                deleting = null
              }) {
                Text("Delete")
              }
        },
        dismissButton = { TextButton(onClick = { deleting = null }) { Text("Cancel") } },
    )
  }

  if (newListener || creating != null) {
    val existing = creating
    var port by remember { mutableStateOf(existing?.port?.toString() ?: "51820") }
    var upstream by remember { mutableStateOf(existing?.upstream ?: AUTO_UPSTREAM) }
    var subnet by remember { mutableStateOf(existing?.subnet ?: "10.66.66.0/24") }
    var dns by remember { mutableStateOf(existing?.dns ?: "") }
    var dnsOnPhone by remember { mutableStateOf(existing?.dnsMode != "direct") }
    var menu by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = {
          newListener = false
          creating = null
        },
        title = { Text(if (existing == null) "New WireGuard listener" else "Edit listener") },
        text = {
          Column(
              modifier = Modifier.verticalScroll(rememberScrollState()),
              verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = port,
                    onValueChange = { port = it },
                    label = { Text("UDP port") },
                    singleLine = true)
                TextButton(onClick = { menu = true }) {
                  Text("Upstream: ${upstreamLabel(upstream)}")
                }
                DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                  DropdownMenuItem(
                      text = { Text(upstreamLabel(AUTO_UPSTREAM)) },
                      onClick = {
                        upstream = AUTO_UPSTREAM
                        menu = false
                      })
                  routable.forEach { c ->
                    DropdownMenuItem(
                        text = { Text(c.label) },
                        onClick = {
                          upstream = c.id
                          menu = false
                        })
                  }
                }
                OutlinedTextField(
                    value = subnet,
                    onValueChange = { subnet = it },
                    label = { Text("Tunnel subnet (this device is .1)") },
                    singleLine = true,
                    enabled = existing == null || existing.peers.isEmpty())
                Row {
                  Text(
                      "Answer peers' DNS with this device's resolver (DoH if set; tailnet names " +
                          "too). Off: their port-53 queries are forwarded as they are.",
                      modifier = Modifier.weight(1f),
                      fontSize = MaterialTheme.typography.bodySmall.fontSize)
                  Switch(checked = dnsOnPhone, onCheckedChange = { dnsOnPhone = it })
                }
                OutlinedTextField(
                    value = dns,
                    onValueChange = { dns = it },
                    label = { Text("DNS server in peers' configs (empty: this device)") },
                    singleLine = true)
              }
        },
        confirmButton = {
          TextButton(
              onClick = {
                val p = port.trim().toIntOrNull()
                if (p == null || p !in 1..65535) {
                  error = "Port must be 1-65535"
                } else {
                  run {
                    val e = engine() ?: throw IllegalStateException("Multi-Tailnet is not running")
                    e.saveWireGuardListenerJSON(
                        existing?.id ?: "",
                        p,
                        upstream,
                        subnet.trim(),
                        dns.trim(),
                        if (dnsOnPhone) "phone" else "direct",
                        existing?.enabled ?: true)
                  }
                  newListener = false
                  creating = null
                }
              }) {
                Text("Save")
              }
        },
        dismissButton = {
          TextButton(
              onClick = {
                newListener = false
                creating = null
              }) {
                Text("Cancel")
              }
        },
    )
  }

  addingPeerTo?.let { l ->
    val addrs = remember { localIPv4Addresses() }
    var name by remember { mutableStateOf("") }
    var endpoint by remember { mutableStateOf(addrs.firstOrNull() ?: "") }
    AlertDialog(
        onDismissRequest = { addingPeerTo = null },
        title = { Text("Add a peer") },
        text = {
          Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text("Name, e.g. laptop") },
                singleLine = true)
            OutlinedTextField(
                value = endpoint,
                onValueChange = { endpoint = it },
                label = { Text("This device's address, as the peer reaches it") },
                singleLine = true)
            if (addrs.isNotEmpty()) {
              Text(
                  "This device: ${addrs.joinToString(", ")}",
                  fontSize = MaterialTheme.typography.bodySmall.fontSize,
                  color = MaterialTheme.colorScheme.secondary)
            }
          }
        },
        confirmButton = {
          TextButton(
              onClick = {
                val listenerId = l.id
                scope.launch {
                  try {
                    peerConfig =
                        withContext(Dispatchers.IO) {
                          engine()
                              ?.addWireGuardListenerPeer(listenerId, name.trim(), endpoint.trim())
                        }
                  } catch (ex: Exception) {
                    error = ex.message ?: ex.toString()
                  }
                  refresh++
                }
                addingPeerTo = null
              }) {
                Text("Add")
              }
        },
        dismissButton = { TextButton(onClick = { addingPeerTo = null }) { Text("Cancel") } },
    )
  }

  peerConfig?.let { conf ->
    AlertDialog(
        onDismissRequest = { peerConfig = null },
        title = { Text("Peer config") },
        text = {
          Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
            Text(
                "Import this into the peer's WireGuard app. Its private key is shown only now.",
                fontSize = MaterialTheme.typography.bodySmall.fontSize)
            SelectionContainer { Text(conf, fontFamily = FontFamily.Monospace, fontSize = 11.sp) }
          }
        },
        confirmButton = {
          TextButton(
              onClick = {
                val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("WireGuard config", conf))
              }) {
                Text("Copy")
              }
        },
        dismissButton = {
          Row {
            TextButton(
                onClick = {
                  val send =
                      Intent(Intent.ACTION_SEND).apply {
                        type = "text/plain"
                        putExtra(Intent.EXTRA_TEXT, conf)
                      }
                  context.startActivity(Intent.createChooser(send, "Share WireGuard config"))
                }) {
                  Text("Share")
                }
            TextButton(onClick = { peerConfig = null }) { Text("Done") }
          }
        },
    )
  }

  Scaffold(
      topBar = { Header(titleRes = R.string.wireguard_listeners, onBack = backToSettings) },
      floatingActionButton = {
        FloatingActionButton(onClick = { newListener = true }) {
          Icon(Icons.Default.Add, "Add WireGuard listener")
        }
      },
  ) { innerPadding ->
    LazyColumn(modifier = Modifier.padding(innerPadding)) {
      item("explanation") {
        ListItem(
            headlineContent = {
              Text(
                  "A WireGuard server on this device. Peers (a laptop, another phone) connect on " +
                      "its UDP port and their traffic leaves through the upstream you pick, or " +
                      "with Auto the way this device's own traffic goes: tailnet addresses to " +
                      "their tailnet, everything else the default way.")
            })
      }
      if (engineMissing) {
        item("noengine") {
          ListItem(
              headlineContent = { Text("Start Multi-Tailnet mode to run WireGuard listeners.") })
        }
      }
      item("header") { Lists.SectionDivider("${listeners.size} WireGuard listeners") }
      items(listeners, key = { it.id }) { l ->
        ListItem(
            modifier = Modifier.fillMaxWidth(),
            headlineContent = { Text("UDP ${l.port}", fontWeight = FontWeight.SemiBold) },
            supportingContent = {
              Column {
                val small = MaterialTheme.typography.bodySmall.fontSize
                Text(
                    "${upstreamLabel(l.upstream)} · ${l.subnet}",
                    color = MaterialTheme.colorScheme.secondary,
                    fontSize = small)
                Text(
                    when {
                      !l.enabled -> "Off"
                      l.running -> "Running"
                      else -> "Not running: ${l.lastError}"
                    },
                    color =
                        if (l.enabled && !l.running) MaterialTheme.colorScheme.error
                        else MaterialTheme.colorScheme.secondary,
                    fontSize = small)
                Text(l.dnsSummary, color = MaterialTheme.colorScheme.secondary, fontSize = small)
                Text(
                    "Public key ${l.publicKey}",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 10.sp,
                    color = MaterialTheme.colorScheme.secondary)
                l.peers.forEach { p ->
                  val hs =
                      when {
                        p.handshakeAgoSec < 0 -> "no handshake yet"
                        p.handshakeAgoSec < 180 -> "handshake ${p.handshakeAgoSec}s ago"
                        else -> "last handshake ${p.handshakeAgoSec / 60} min ago"
                      }
                  Text(
                      "• ${p.name} ${p.address}: $hs" +
                          (if (p.endpoint.isNotEmpty()) ", from ${p.endpoint}" else "") +
                          ", ↓${humanBytes(p.tx)} ↑${humanBytes(p.rx)}",
                      fontSize = small)
                }
              }
            },
            trailingContent = {
              Switch(
                  checked = l.enabled,
                  onCheckedChange = { on ->
                    run {
                      engine()
                          ?.saveWireGuardListenerJSON(
                              l.id, l.port, l.upstream, l.subnet, l.dns, l.dnsMode, on)
                    }
                  })
            },
        )
        Row(modifier = Modifier.padding(start = 16.dp, bottom = 8.dp)) {
          TextButton(onClick = { addingPeerTo = l }) { Text("Add peer") }
          TextButton(onClick = { creating = l }) { Text("Edit") }
          TextButton(onClick = { deleting = l }) { Text("Delete") }
        }
        if (l.peers.isNotEmpty()) {
          Row(modifier = Modifier.padding(start = 16.dp, bottom = 8.dp)) {
            l.peers.forEach { p ->
              TextButton(
                  onClick = { run { engine()?.removeWireGuardListenerPeer(l.id, p.publicKey) } }) {
                    Text("Remove ${p.name}")
                  }
            }
          }
        }
        Lists.ItemDivider()
      }
    }
  }
}
