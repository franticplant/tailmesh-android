// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package com.tailscale.ipn.ui.view

import android.graphics.Typeface
import android.graphics.drawable.Drawable
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import com.patrykandpatrick.vico.compose.axis.axisGuidelineComponent
import com.patrykandpatrick.vico.compose.axis.horizontal.rememberBottomAxis
import com.patrykandpatrick.vico.compose.axis.vertical.rememberStartAxis
import com.patrykandpatrick.vico.compose.chart.Chart
import com.patrykandpatrick.vico.compose.chart.column.columnChart
import com.patrykandpatrick.vico.compose.chart.line.lineChart
import com.patrykandpatrick.vico.compose.chart.scroll.rememberChartScrollSpec
import com.patrykandpatrick.vico.compose.component.lineComponent
import com.patrykandpatrick.vico.compose.component.marker.markerComponent
import com.patrykandpatrick.vico.compose.component.shape.shader.verticalGradient
import com.patrykandpatrick.vico.compose.component.shapeComponent
import com.patrykandpatrick.vico.compose.component.textComponent
import com.patrykandpatrick.vico.compose.dimensions.dimensionsOf
import com.patrykandpatrick.vico.compose.m3.style.m3ChartStyle
import com.patrykandpatrick.vico.compose.style.ProvideChartStyle
import com.patrykandpatrick.vico.compose.style.currentChartStyle
import com.patrykandpatrick.vico.core.axis.AxisItemPlacer
import com.patrykandpatrick.vico.core.chart.copy
import com.patrykandpatrick.vico.core.component.shape.Shapes
import com.patrykandpatrick.vico.core.entry.FloatEntry
import com.patrykandpatrick.vico.core.entry.entryModelOf
import com.patrykandpatrick.vico.core.marker.MarkerLabelFormatter
import com.patrykandpatrick.vico.core.scroll.InitialScroll
import com.tailscale.ipn.App
import com.tailscale.ipn.MultiProxySessionCoordinator
import com.tailscale.ipn.UpstreamStatSnapshot
import com.tailscale.ipn.multiproxy.AppNameResolver
import com.tailscale.ipn.multiproxy.db.ObservabilityDatabaseHelper
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.max
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

/**
 * A "Standard" vs "Advanced" telemetry-mode indicator plus four sections
 * (Overview/Tailnets/Apps/Network). Reads only from bounded, already-computed state -
 * MultiProxySessionCoordinator's live StateFlows for "now", and ObservabilityDatabaseHelper's
 * aggregated samples/events for graphs. Nothing here triggers a new measurement; it only displays
 * ones the engine already took (see libtailscale/multiproxy/observability.go).
 *
 * Graphs use Vico (already a project dependency - see PingView.kt), which gives tap-to-inspect
 * markers/tooltips and gradient-filled lines for free instead of a hand-rolled Canvas chart.
 */
private enum class DiagRange(val label: String, val millis: Long) {
  H1("1h", 60L * 60_000),
  H6("6h", 6 * 60L * 60_000),
  H24("24h", 24 * 60L * 60_000),
  D7("7d", 7 * 24 * 60L * 60_000),
}

private enum class DiagSection {
  OVERVIEW,
  UPSTREAMS,
  APPS,
  NETWORK
}

/**
 * How many points a chart draws at most, regardless of how many samples are actually stored for the
 * selected [DiagRange]. Without this, a dense series (e.g. 1s samples kept while the screen is
 * open) plots one point per sample - over a 6h/24h/7d range that's thousands of points, so each
 * on-screen minute ends up stretched wide and just seeing the overall shape means endless
 * horizontal scrolling. This only controls how much of the stored history gets drawn per chart (see
 * [bucketize]); it does not change what [ObservabilityDatabaseHelper] actually stores/prunes.
 */
private enum class GraphResolution(val label: String, val targetPoints: Int) {
  COARSE("Coarse", 60),
  NORMAL("Normal", 150),
  FINE("Fine", 400),
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DiagnosticsView(onNavigateBack: () -> Unit) {
  val context = LocalContext.current
  val snapshot by MultiProxySessionCoordinator.observabilitySnapshot.collectAsState()
  val liveEvents by MultiProxySessionCoordinator.observabilityEvents.collectAsState()
  var section by remember { mutableStateOf(DiagSection.OVERVIEW) }
  var range by remember { mutableStateOf(DiagRange.H1) }
  var resolution by remember { mutableStateOf(GraphResolution.NORMAL) }
  var samples by remember { mutableStateOf<List<ObservabilityDatabaseHelper.Sample>>(emptyList()) }
  var advancedEnabled by remember {
    mutableStateOf(App.get().multiProxySession.engine?.advancedDiagnosticsEnabled() ?: false)
  }
  var captureStatus by remember { mutableStateOf<String?>(null) }
  var showResetDialog by remember { mutableStateOf(false) }
  var dnsLogEnabled by remember { mutableStateOf(false) }
  var dnsSearchQuery by remember { mutableStateOf("") }
  var dnsErrorsOnly by remember { mutableStateOf(false) }

  DisposableEffect(Unit) {
    MultiProxySessionCoordinator.setDiagnosticsUiVisible(true)
    onDispose {
      MultiProxySessionCoordinator.setDiagnosticsUiVisible(false)
      // Belt-and-suspenders: leaving this screen with the toggle still on would mean every
      // DNS query app-wide keeps writing a SQLite row with nothing left to see it - the
      // toggle's own onCheckedChange already turns the engine side off when unchecked, but
      // dispose covers back-navigation without touching the switch.
      App.get().multiProxySession.engine?.setDNSQueryLogEnabled(false)
    }
  }

  LaunchedEffect(range) {
    while (true) {
      val since = System.currentTimeMillis() - range.millis
      samples =
          withContext(Dispatchers.IO) {
            MultiProxySessionCoordinator.observabilitySamplesSince(since)
          }
      delay(2000)
    }
  }

  Scaffold(
      topBar = {
        TopAppBar(
            title = { Text("Diagnostics") },
            navigationIcon = {
              Text("Back", modifier = Modifier.clickable { onNavigateBack() }.padding(8.dp))
            },
        )
      },
  ) { padding ->
    Column(modifier = Modifier.fillMaxSize().padding(padding)) {
      Text(
          if (advancedEnabled) "Telemetry: Advanced" else "Telemetry: Standard",
          style = MaterialTheme.typography.labelMedium,
          modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
      )
      TabRow(selectedTabIndex = section.ordinal) {
        DiagSection.entries.forEach { s ->
          Tab(
              selected = section == s,
              onClick = { section = s },
              text = { Text(s.name.lowercase().replaceFirstChar { it.uppercase() }) },
          )
        }
      }
      Row(modifier = Modifier.padding(horizontal = 8.dp)) {
        DiagRange.entries.forEach { r ->
          FilterChip(
              selected = range == r,
              onClick = { range = r },
              label = { Text(r.label) },
              modifier = Modifier.padding(end = 8.dp),
          )
        }
      }
      Row(
          modifier = Modifier.padding(horizontal = 8.dp).padding(bottom = 4.dp),
          verticalAlignment = Alignment.CenterVertically,
      ) {
        Text(
            "Resolution:",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.secondary,
            modifier = Modifier.padding(end = 8.dp),
        )
        GraphResolution.entries.forEach { r ->
          FilterChip(
              selected = resolution == r,
              onClick = { resolution = r },
              label = { Text(r.label) },
              modifier = Modifier.padding(end = 8.dp),
          )
        }
      }
      LazyColumn(modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
        when (section) {
          DiagSection.OVERVIEW ->
              overviewSection(this, snapshot, samples, liveEvents, resolution, range)
          DiagSection.UPSTREAMS -> upstreamsSection(this, snapshot, range, resolution)
          DiagSection.APPS -> appsSection(this, snapshot, range, resolution)
          DiagSection.NETWORK ->
              networkSection(
                  this,
                  liveEvents,
                  dnsLogEnabled,
                  onDnsLogEnabledChange = {
                    dnsLogEnabled = it
                    App.get().multiProxySession.engine?.setDNSQueryLogEnabled(it)
                  },
                  dnsSearchQuery = dnsSearchQuery,
                  onDnsSearchQueryChange = { dnsSearchQuery = it },
                  dnsErrorsOnly = dnsErrorsOnly,
                  onDnsErrorsOnlyChange = { dnsErrorsOnly = it },
              )
        }
        item {
          Spacer(modifier = Modifier.height(16.dp))
          HorizontalDivider()
          Spacer(modifier = Modifier.height(8.dp))
          Text("Advanced diagnostics", style = MaterialTheme.typography.titleMedium)
          Text(
              "Off by default. When off: no continuous profiling, no trace collection, " +
                  "no extra runtime cost. When on: higher-frequency samples and the " +
                  "captures below become available.",
              style = MaterialTheme.typography.bodySmall,
          )
          Row(
              verticalAlignment = Alignment.CenterVertically,
              modifier = Modifier.padding(vertical = 8.dp)) {
                Switch(
                    checked = advancedEnabled,
                    onCheckedChange = {
                      advancedEnabled = it
                      App.get().multiProxySession.engine?.setAdvancedDiagnostics(it)
                    },
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(if (advancedEnabled) "Enabled" else "Disabled")
              }
          if (advancedEnabled) {
            Button(
                onClick = {
                  val engine = App.get().multiProxySession.engine
                  val out =
                      File(context.cacheDir, "cpu_profile_${System.currentTimeMillis()}.pprof")
                  try {
                    engine?.captureCPUProfileToFile(out.absolutePath, 30)
                    captureStatus = "CPU profile saved: ${out.name}"
                  } catch (e: Exception) {
                    captureStatus = "CPU profile capture failed: ${e.message}"
                  }
                }) {
                  Text("Capture 30-second CPU profile")
                }
            Spacer(modifier = Modifier.height(4.dp))
            Button(
                onClick = {
                  val engine = App.get().multiProxySession.engine
                  val out =
                      File(context.cacheDir, "heap_profile_${System.currentTimeMillis()}.pprof")
                  try {
                    engine?.captureHeapProfileToFile(out.absolutePath)
                    captureStatus = "Heap profile saved: ${out.name}"
                  } catch (e: Exception) {
                    captureStatus = "Heap profile capture failed: ${e.message}"
                  }
                }) {
                  Text("Capture heap profile")
                }
            Spacer(modifier = Modifier.height(4.dp))
            Button(
                onClick = {
                  val engine = App.get().multiProxySession.engine
                  val out = File(context.cacheDir, "goroutines_${System.currentTimeMillis()}.txt")
                  try {
                    engine?.captureGoroutineDumpToFile(out.absolutePath)
                    captureStatus = "Goroutine dump saved: ${out.name}"
                  } catch (e: Exception) {
                    captureStatus = "Goroutine dump failed: ${e.message}"
                  }
                }) {
                  Text("Capture goroutine dump")
                }
          }
          Spacer(modifier = Modifier.height(4.dp))
          OutlinedButton(
              onClick = {
                val out =
                    File(context.cacheDir, "diagnostics_bundle_${System.currentTimeMillis()}.json")
                try {
                  MultiProxySessionCoordinator.exportDiagnosticsBundle(out, range.millis)
                  captureStatus = "Diagnostics bundle saved: ${out.name}"
                } catch (e: Exception) {
                  captureStatus = "Bundle export failed: ${e.message}"
                }
              }) {
                Text("Export diagnostics bundle (${range.label})")
              }
          Spacer(modifier = Modifier.height(4.dp))
          OutlinedButton(onClick = { showResetDialog = true }) { Text("Reset stats…") }
          captureStatus?.let {
            Spacer(modifier = Modifier.height(4.dp))
            Text(it, style = MaterialTheme.typography.bodySmall)
          }
          Spacer(modifier = Modifier.height(24.dp))
        }
      }
    }
  }

  if (showResetDialog) {
    ResetStatsDialog(
        currentRange = range,
        onDismiss = { showResetDialog = false },
        onConfirm = { resetDataplane, resetApps, resetUpstreams, resetHistory, historySinceMillis ->
          MultiProxySessionCoordinator.resetObservability(
              resetDataplane = resetDataplane,
              resetApps = resetApps,
              resetUpstreams = resetUpstreams,
              resetHistorySinceMillis = historySinceMillis,
              resetHistory = resetHistory,
          )
          showResetDialog = false
          captureStatus = "Stats reset"
        },
    )
  }
}

/**
 * Scope-selectable "reset stats" dialog: which live counter groups to zero, and whether/how much
 * persisted history to drop. History supports "reset last X" (only rows newer than X ago are
 * dropped) as well as clearing everything - live counters always reset in full since they're
 * cumulative-since-VPN-start with no time axis to scope against (see
 * Engine.ResetObservabilityCounters's doc comment).
 */
@Composable
private fun ResetStatsDialog(
    currentRange: DiagRange,
    onDismiss: () -> Unit,
    onConfirm:
        (
            resetDataplane: Boolean,
            resetApps: Boolean,
            resetUpstreams: Boolean,
            resetHistory: Boolean,
            historySinceMillis: Long?) -> Unit,
) {
  var resetDataplane by remember { mutableStateOf(true) }
  var resetApps by remember { mutableStateOf(true) }
  var resetUpstreams by remember { mutableStateOf(true) }
  var resetHistory by remember { mutableStateOf(true) }
  var historyScopeAll by remember { mutableStateOf(true) }
  var historyRange by remember { mutableStateOf(currentRange) }

  AlertDialog(
      onDismissRequest = onDismiss,
      title = { Text("Reset stats") },
      text = {
        Column {
          Text(
              "Live counters reset to zero immediately and in full. History can be cleared " +
                  "entirely or just the most recent window.",
              style = MaterialTheme.typography.bodySmall,
          )
          Spacer(modifier = Modifier.height(8.dp))
          ResetCheckboxRow("Dataplane counters (TUN/DNS/attribution)", resetDataplane) {
            resetDataplane = it
          }
          ResetCheckboxRow("Per-app counters", resetApps) { resetApps = it }
          ResetCheckboxRow("Per-upstream counters", resetUpstreams) { resetUpstreams = it }
          ResetCheckboxRow("History (graphs and event log)", resetHistory) { resetHistory = it }
          if (resetHistory) {
            Column(modifier = Modifier.padding(start = 32.dp)) {
              Row(verticalAlignment = Alignment.CenterVertically) {
                RadioButton(selected = historyScopeAll, onClick = { historyScopeAll = true })
                Text("All time", style = MaterialTheme.typography.bodySmall)
              }
              Row(verticalAlignment = Alignment.CenterVertically) {
                RadioButton(selected = !historyScopeAll, onClick = { historyScopeAll = false })
                Text("Last:", style = MaterialTheme.typography.bodySmall)
                Spacer(modifier = Modifier.width(8.dp))
                DiagRange.entries.forEach { r ->
                  FilterChip(
                      selected = !historyScopeAll && historyRange == r,
                      onClick = {
                        historyScopeAll = false
                        historyRange = r
                      },
                      label = { Text(r.label) },
                      modifier = Modifier.padding(end = 4.dp),
                  )
                }
              }
            }
          }
        }
      },
      confirmButton = {
        TextButton(
            onClick = {
              val since =
                  if (!resetHistory) null
                  else if (historyScopeAll) null
                  else System.currentTimeMillis() - historyRange.millis
              onConfirm(resetDataplane, resetApps, resetUpstreams, resetHistory, since)
            }) {
              Text("Reset")
            }
      },
      dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
  )
}

@Composable
private fun ResetCheckboxRow(label: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
  Row(verticalAlignment = Alignment.CenterVertically) {
    Checkbox(checked = checked, onCheckedChange = onCheckedChange)
    Text(label, style = MaterialTheme.typography.bodySmall)
  }
}

// ---------------------------------------------------------------------------
// Charting
// ---------------------------------------------------------------------------

/**
 * Buckets timestamped points into at most [targetPoints] evenly-spaced buckets spanning the series'
 * own time range, averaging within each bucket. See [GraphResolution]'s doc comment for why this
 * exists. A no-op when there's already fewer points than the budget.
 */
private fun bucketize(points: List<Pair<Long, Float>>, targetPoints: Int): List<Pair<Long, Float>> {
  if (points.size <= targetPoints || points.size < 2) return points
  val start = points.first().first
  val end = points.last().first
  val bucketMillis = ((end - start) / targetPoints).coerceAtLeast(1)
  val out = mutableListOf<Pair<Long, Float>>()
  var bucketStart = start
  var sum = 0f
  var count = 0
  var lastTs = start
  for ((ts, v) in points) {
    if (ts - bucketStart >= bucketMillis && count > 0) {
      out.add(lastTs to sum / count)
      bucketStart = ts
      sum = 0f
      count = 0
    }
    sum += v
    count++
    lastTs = ts
  }
  if (count > 0) out.add(lastTs to sum / count)
  return out
}

/** Per-sample-interval deltas of a cumulative series, keyed by the later sample's timestamp. */
private fun <T> deltaSeries(
    items: List<T>,
    tsOf: (T) -> Long,
    valueOf: (T) -> Float
): List<Pair<Long, Float>> {
  if (items.size < 2) return emptyList()
  return (1 until items.size).map { i ->
    tsOf(items[i]) to (valueOf(items[i]) - valueOf(items[i - 1])).coerceAtLeast(0f)
  }
}

/** [points] as the (entries, timestamps) pair [InteractiveLineChart] wants. */
private fun chartSeries(points: List<Pair<Long, Float>>): Pair<List<FloatEntry>, List<Long>> =
    points.mapIndexed { i, (_, v) -> FloatEntry(i.toFloat(), v) } to points.map { it.first }

/**
 * A gradient-filled, tap-to-inspect line chart. `formatValue` controls what the tooltip and axis
 * show (e.g. "42.3%" vs "1.2 MB/s") - the chart itself only ever deals in plain floats.
 *
 * `timestamps` is a parallel array to `entries` (same size, oldest-first) used only to label the
 * bottom axis with real clock times - the chart still plots on the entries' own index-based x
 * values. The chart always opens scrolled to its right edge (the most recent sample / "now") rather
 * than the leftmost/oldest data, since that's what a live diagnostics graph should default to; the
 * horizontal scroll only ever reveals data already confined to whatever range the caller queried
 * the history for (see `range`/`sinceMillis` at each call site) - scrolling left just reveals more
 * of that same bounded window, it does not fetch older data.
 */
@Composable
private fun InteractiveLineChart(
    entries: List<FloatEntry>,
    timestamps: List<Long>,
    color: Color,
    modifier: Modifier = Modifier,
    formatValue: (Float) -> String = { "%.1f".format(it) },
    // Per-interval deltas (traffic, dial counts) are discrete events, not a continuously varying
    // quantity - a connected line implies a smooth ramp between samples that isn't there, which is
    // exactly what reads as "nothing for a while, then a sudden spike" when most of the traffic in
    // a bucket lands in one sample. Rendering those as bars instead of a line doesn't change the
    // data or add any cost (same bucketized points, just a different Vico chart type) - it just
    // stops implying an interpolation that never happened. Continuously-varying metrics (CPU%,
    // instantaneous gauges) should stay lines.
    asRate: Boolean = false,
    // Identifies which time range/data window this chart is showing. rememberChartScrollSpec's
    // own remember has no keys of its own, so without this the scroll x-offset from whatever
    // range was selected before survives untouched across a range switch - it's a raw pixel/index
    // offset into the old (differently-sized) content, so against the new content it either points
    // nowhere near the right edge or gets clamped to the start, which is what reads as the chart
    // "jumping left" instead of staying scrolled to the newest sample. Keying the scroll spec's
    // remember on this forces it to reinitialize to InitialScroll.End whenever the range changes.
    resetKey: Any? = Unit,
) {
  if (entries.size < 2) {
    Box(
        modifier =
            modifier.background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(8.dp)),
        contentAlignment = Alignment.Center,
    ) {
      Text(
          "Not enough data yet",
          style = MaterialTheme.typography.bodySmall,
          color = MaterialTheme.colorScheme.onSurfaceVariant,
      )
    }
    return
  }
  val model = entryModelOf(entries)
  ProvideChartStyle(chartStyle = m3ChartStyle()) {
    val defaultLines = currentChartStyle.lineChart.lines
    val gradient =
        remember(color) {
          verticalGradient(arrayOf(color.copy(alpha = 0.35f), color.copy(alpha = 0f)))
        }
    val chartLines =
        remember(color, defaultLines) {
          listOf(
              defaultLines
                  .first()
                  .copy(
                      lineColor = color.toArgb(),
                      lineThicknessDp = 2.5f,
                      lineBackgroundShader = gradient,
                  ))
        }
    val labelComponent =
        textComponent(
            color = Color.White,
            background = shapeComponent(shape = Shapes.pillShape, color = color),
            padding = dimensionsOf(start = 8.dp, top = 4.dp, end = 8.dp, bottom = 4.dp),
            typeface = Typeface.MONOSPACE,
        )
    val indicator = shapeComponent(shape = CircleShape, color = color)
    val guideline = lineComponent(color = color.copy(alpha = 0.3f), thickness = 1.dp)
    val formatter =
        remember(formatValue) {
          MarkerLabelFormatter { markedEntries, _ ->
            markedEntries.joinToString { formatValue(it.entry.y) }
          }
        }
    val markerComp =
        markerComponent(label = labelComponent, indicator = indicator, guideline = guideline)
            .apply { labelFormatter = formatter }
    val timeFmt = remember { SimpleDateFormat("HH:mm", Locale.getDefault()) }
    val scrollSpec =
        key(resetKey) {
          rememberChartScrollSpec<com.patrykandpatrick.vico.core.entry.ChartEntryModel>(
              isScrollEnabled = true,
              initialScroll = InitialScroll.End,
          )
        }
    val columns =
        listOf(
            lineComponent(
                color = color,
                thickness = 6.dp,
                shape = Shapes.roundedCornerShape(40),
            ))
    Chart(
        chart = if (asRate) columnChart(columns = columns) else lineChart(lines = chartLines),
        model = model,
        modifier = modifier,
        marker = markerComp,
        chartScrollSpec = scrollSpec,
        startAxis =
            rememberStartAxis(
                valueFormatter = { value, _ -> formatValue(value) },
                itemPlacer = remember { AxisItemPlacer.Vertical.default(maxItemCount = 4) },
                label =
                    textComponent(
                        color = MaterialTheme.colorScheme.secondary, typeface = Typeface.MONOSPACE),
                guideline =
                    axisGuidelineComponent(color = MaterialTheme.colorScheme.secondaryContainer),
            ),
        bottomAxis =
            rememberBottomAxis(
                itemPlacer =
                    remember {
                      AxisItemPlacer.Horizontal.default(spacing = max(1, entries.size / 5))
                    },
                label =
                    textComponent(
                        color = MaterialTheme.colorScheme.secondary, typeface = Typeface.MONOSPACE),
                valueFormatter = { value, _ ->
                  timestamps.getOrNull(value.toInt())?.let { timeFmt.format(Date(it)) } ?: ""
                },
                guideline =
                    axisGuidelineComponent(color = MaterialTheme.colorScheme.secondaryContainer),
            ),
    )
  }
}

// ---------------------------------------------------------------------------
// Upstream display names
// ---------------------------------------------------------------------------

/**
 * Resolves a raw upstream id (e.g. "regular-2e2c", "exitnode-ab12", "@direct") to a human-legible
 * name, generic across every upstream kind: non-Tailnet upstreams (SOCKS5/WireGuard/exit node)
 * carry their own [Upstream.label][com.tailscale.ipn.multiproxy.db.Upstream.label]; Tailnet
 * upstreams are looked up by the same id in
 * [ProfileRepository][com.tailscale.ipn.multiproxy.db.ProfileRepository.displayName]. Falls back to
 * the raw id itself if neither repository knows it (e.g. it was just removed).
 */
private fun upstreamDisplayName(id: String): String {
  if (id.isEmpty()) return id
  if (id == "@direct") return "Direct"
  val session = App.get().multiProxySession
  session.upstreamRepository.getImmediate(id)?.let { if (it.label.isNotBlank()) return it.label }
  session.profileRepository.getProfileImmediate(id)?.let {
    if (it.displayName.isNotBlank()) return it.displayName
  }
  return id
}

/**
 * "Human name (raw-id)" when they differ, otherwise just the id - for wherever a raw id is shown.
 */
private fun upstreamDisplayLabel(id: String): String {
  if (id.isEmpty()) return id
  val name = upstreamDisplayName(id)
  return if (name != id) "$name ($id)" else id
}

/**
 * Human-readable form of Engine.peerPathFor's raw values ("derp:fra" -> "relayed via fra", etc).
 */
private fun peerPathLabel(raw: String): String =
    when {
      raw == "direct" -> "direct"
      raw.startsWith("derp:") -> "relayed via ${raw.removePrefix("derp:")}"
      raw == "no-path" -> "no path"
      raw == "wireguard:established" -> "handshake established"
      raw == "wireguard:no-handshake" -> "no handshake yet"
      raw == "wireguard" -> "wireguard"
      raw == "socks5" -> "socks5"
      raw == "direct-bypass" -> "bypasses the VPN entirely"
      else -> raw
    }

private fun formatBytesPerSample(v: Float): String {
  val bytes = v.toDouble()
  return when {
    bytes >= 1_000_000 -> "%.1f MB".format(bytes / 1_000_000)
    bytes >= 1_000 -> "%.1f KB".format(bytes / 1_000)
    else -> "%.0f B".format(bytes)
  }
}

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------

private fun overviewSection(
    scope: LazyListScope,
    snapshot: com.tailscale.ipn.ObservabilitySnapshot,
    samples: List<ObservabilityDatabaseHelper.Sample>,
    events: List<com.tailscale.ipn.ObservabilityEvent>,
    resolution: GraphResolution,
    range: DiagRange,
) {
  scope.item {
    Text(
        "Process",
        style = MaterialTheme.typography.titleMedium,
        modifier = Modifier.padding(top = 12.dp))
    StatRow(
        "CPU",
        "${"%.1f".format(snapshot.process.cpuPercent)}% (${"%.2f".format(snapshot.process.cpuSeconds)}s total, real kernel accounting)")
    StatRow(
        "Processing time / GiB",
        "${"%.2f".format(snapshot.process.cpuSecondsPerGiB)} CPU-s/GiB (derived, not per-app)")
    StatRow(
        "Go heap",
        "${snapshot.process.goHeapAllocBytes / 1024 / 1024} MiB alloc, ${snapshot.process.goroutineCount} goroutines")
    StatRow("Engine uptime", "${snapshot.process.engineUptimeSeconds}s")
    Spacer(modifier = Modifier.height(8.dp))
    Text("Dataplane (TUN)", style = MaterialTheme.typography.titleMedium)
    StatRow(
        "RX", "${snapshot.dataplane.tunRxBytes} bytes / ${snapshot.dataplane.tunRxPackets} pkts")
    StatRow(
        "TX", "${snapshot.dataplane.tunTxBytes} bytes / ${snapshot.dataplane.tunTxPackets} pkts")
    StatRow(
        "DNS",
        "${snapshot.dataplane.dnsQueries} queries, ${snapshot.dataplane.dnsFailures} failures")
    StatRow("VPN restarts", "${snapshot.dataplane.vpnRestarts}")
    if (snapshot.dataplane.attributionFailures > 0 ||
        snapshot.dataplane.dnsAttributionFailClosed > 0 ||
        snapshot.dataplane.dnsForwardFailures > 0) {
      Spacer(modifier = Modifier.height(8.dp))
      Column(
          modifier =
              Modifier.fillMaxWidth()
                  .background(MaterialTheme.colorScheme.errorContainer, RoundedCornerShape(8.dp))
                  .padding(12.dp),
      ) {
        Text(
            "Per-app routing attribution",
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onErrorContainer,
        )
        StatRow(
            "Flows that fell back to a broader rule",
            "${snapshot.dataplane.attributionFailures}",
            color = MaterialTheme.colorScheme.onErrorContainer,
        )
        StatRow(
            "DNS queries refused (fail-closed)",
            "${snapshot.dataplane.dnsAttributionFailClosed}",
            color = MaterialTheme.colorScheme.onErrorContainer,
        )
        if (snapshot.dataplane.dnsForwardFailures > 0) {
          StatRow(
              "DNS queries that reached an upstream but got no answer",
              "${snapshot.dataplane.dnsForwardFailures}",
              color = MaterialTheme.colorScheme.onErrorContainer,
          )
          Text(
              "That upstream's own network is likely dropping or blocking DNS (common with " +
                  "VPN/WireGuard providers that only allow DNS to their own resolver). Try " +
                  "setting that app's DNS to \"Direct\" or another upstream.",
              style = MaterialTheme.typography.bodySmall,
              color = MaterialTheme.colorScheme.onErrorContainer,
          )
        }
      }
    }
    Spacer(modifier = Modifier.height(16.dp))
    Text("CPU %", style = MaterialTheme.typography.titleMedium)
    val (cpuEntries, cpuTimestamps) =
        remember(samples, resolution) {
          chartSeries(
              bucketize(samples.map { it.ts to it.cpuPercent.toFloat() }, resolution.targetPoints))
        }
    InteractiveLineChart(
        entries = cpuEntries,
        timestamps = cpuTimestamps,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.fillMaxWidth().height(160.dp).padding(vertical = 8.dp),
        formatValue = { "%.1f%%".format(it) },
        resetKey = range,
    )
    Text("TUN throughput (bytes/sample)", style = MaterialTheme.typography.titleMedium)
    val (tunEntries, tunTimestamps) =
        remember(samples, resolution) {
          chartSeries(
              bucketize(
                  deltaSeries(samples, { it.ts }, { (it.tunRxBytes + it.tunTxBytes).toFloat() }),
                  resolution.targetPoints))
        }
    InteractiveLineChart(
        entries = tunEntries,
        timestamps = tunTimestamps,
        color = MaterialTheme.colorScheme.tertiary,
        modifier = Modifier.fillMaxWidth().height(160.dp).padding(vertical = 8.dp),
        formatValue = ::formatBytesPerSample,
        asRate = true,
        resetKey = range,
    )
  }
  scope.item {
    Spacer(modifier = Modifier.height(8.dp))
    Text("Recent events", style = MaterialTheme.typography.titleMedium)
  }
  scope.items(events.takeLast(30).reversed()) { e ->
    Text(
        "${e.eventType} ${if (e.upstreamId.isNotEmpty()) "(${upstreamDisplayLabel(e.upstreamId)}) " else ""}${e.previousState}->${e.newState}",
        style = MaterialTheme.typography.bodySmall,
        modifier = Modifier.padding(vertical = 2.dp),
    )
  }
}

private fun upstreamsSection(
    scope: LazyListScope,
    snapshot: com.tailscale.ipn.ObservabilitySnapshot,
    range: DiagRange,
    resolution: GraphResolution,
) {
  val runtimeStates = MultiProxySessionCoordinator.runtimeStates.value
  val upstreamStats = MultiProxySessionCoordinator.upstreamStats.value
  // The complete set of upstreams to show, regardless of kind: tailnets and exit nodes come from
  // the 1s runtime-state poll (runtimeStates); SOCKS5/WireGuard/exit-node rows the user configured
  // come from UpstreamRepository (a tailnet/exit-node id may appear in both, hence distinct());
  // upstreamStats.keys catches anything with recorded stats but not in either list, e.g. "@direct"
  // or an upstream that was since removed but whose last-known stats are still worth showing.
  val configuredIds = App.get().multiProxySession.upstreamRepository.getAllImmediate().map { it.id }
  val ids =
      (runtimeStates.keys + configuredIds + upstreamStats.keys).distinct().sortedBy {
        upstreamDisplayName(it)
      }

  scope.item {
    Text(
        "Upstreams",
        style = MaterialTheme.typography.titleMedium,
        modifier = Modifier.padding(top = 12.dp))
    Text(
        "Every configured upstream gets the same generic tracking - tailnets, exit nodes, " +
            "SOCKS5, WireGuard and direct. Tap one to graph its traffic and see which apps are " +
            "using it.",
        style = MaterialTheme.typography.bodySmall,
    )
  }
  if (ids.isEmpty()) {
    scope.item {
      Text(
          "No upstreams configured yet.",
          style = MaterialTheme.typography.bodySmall,
          modifier = Modifier.padding(vertical = 8.dp),
      )
    }
    return
  }
  scope.items(ids) { id ->
    UpstreamRow(
        id, runtimeStates[id], upstreamStats[id], upstreamStats, snapshot, range, resolution)
    HorizontalDivider()
  }
}

/**
 * Walks a chained upstream's `via` links to the end, e.g. "wg145 -> proxy-eu -> Direct", instead of
 * showing only the immediate parent. Pure in-memory lookups over data already fetched for this
 * screen - no extra engine calls - capped at a handful of hops as a defensive bound against a cycle
 * the engine should already reject at registration (see chain.go's checkChainLocked), so a bug
 * there shows a truncated chain instead of hanging the UI.
 */
private fun resolveChain(id: String, stats: Map<String, UpstreamStatSnapshot>): List<String> {
  val chain = mutableListOf(id)
  var current = id
  var hops = 0
  while (hops < 8) {
    val via = stats[current]?.via?.takeIf { it.isNotEmpty() } ?: break
    if (via in chain) break
    chain.add(via)
    current = via
    hops++
  }
  return chain
}

@Composable
private fun UpstreamRow(
    id: String,
    state: String?,
    stat: UpstreamStatSnapshot?,
    allStats: Map<String, UpstreamStatSnapshot>,
    snapshot: com.tailscale.ipn.ObservabilitySnapshot,
    range: DiagRange,
    resolution: GraphResolution,
) {
  var expanded by remember(id) { mutableStateOf(false) }
  var history by
      remember(id, range) {
        mutableStateOf<List<ObservabilityDatabaseHelper.UpstreamSample>>(emptyList())
      }
  val displayName = remember(id) { upstreamDisplayName(id) }

  // The per-app breakdown for this upstream is an "advanced" analysis - it's cheap to compute
  // (a filter over an already-in-memory list, no new engine call), but it's still only computed
  // while this row is actually expanded, matching the on-demand pattern used everywhere else in
  // this screen rather than running for every collapsed upstream on every recomposition.
  val appBreakdown by
      remember(id, expanded, snapshot) {
        derivedStateOf {
          if (!expanded) emptyList()
          else
              snapshot.apps
                  .mapNotNull { app ->
                    app.byUpstream.find { it.upstreamId == id }?.let { app.uid to it }
                  }
                  .sortedByDescending { it.second.bytesIn + it.second.bytesOut }
        }
      }

  LaunchedEffect(expanded, range) {
    if (!expanded) return@LaunchedEffect
    while (expanded) {
      val since = System.currentTimeMillis() - range.millis
      history =
          withContext(Dispatchers.IO) {
            MultiProxySessionCoordinator.upstreamSamplesSince(id, since)
          }
      delay(2000)
    }
  }

  Column(
      modifier =
          Modifier.fillMaxWidth().clickable { expanded = !expanded }.padding(vertical = 8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
          Column(modifier = Modifier.weight(1f)) {
            Text(
                if (displayName != id) "$displayName" else id,
                style = MaterialTheme.typography.bodyLarge)
            if (displayName != id) {
              Text(
                  id,
                  style = MaterialTheme.typography.labelSmall,
                  color = MaterialTheme.colorScheme.secondary)
            }
            val stateLabel =
                state ?: stat?.let { if (it.ready) "READY" else "NOT READY" } ?: "unknown"
            Text(
                "state: $stateLabel" +
                    (stat?.kind?.takeIf { it.isNotBlank() }?.let { "  kind: $it" } ?: ""),
                style = MaterialTheme.typography.bodySmall,
            )
            if (stat != null) {
              Text(
                  "dials: ${stat.dialAttempts} ok=${stat.dialSuccesses} fail=${stat.dialFailures} " +
                      "notReady=${stat.notReadyCount}  bytes in/out: ${stat.bytesIn}/${stat.bytesOut}",
                  style = MaterialTheme.typography.bodySmall,
              )
              Text(
                  "active flows: tcp=${stat.activeTcp} udp=${stat.activeUdp}  " +
                      "total flows: tcp=${stat.tcpFlowsTotal} udp=${stat.udpFlowsTotal}" +
                      if (stat.lastLatencyMs > 0) "  last dial: ${stat.lastLatencyMs} ms" else "",
                  style = MaterialTheme.typography.bodySmall,
              )
              if (stat.peerPath.isNotEmpty() && stat.peerPath != "unknown") {
                Text(
                    "peer: ${peerPathLabel(stat.peerPath)}",
                    style = MaterialTheme.typography.bodySmall,
                    color =
                        if (stat.peerPath.startsWith("derp:") ||
                            stat.peerPath.contains("no-handshake")) {
                          MaterialTheme.colorScheme.tertiary
                        } else {
                          MaterialTheme.colorScheme.secondary
                        },
                )
              }
              if (stat.via.isNotEmpty()) {
                val chain = remember(id, allStats) { resolveChain(id, allStats) }
                Text(
                    "chain: " + chain.joinToString(" -> ") { upstreamDisplayLabel(it) },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
              }
              if (stat.dnsQueriesForwarded > 0 || stat.dnsQueriesFailed > 0) {
                Text(
                    "DNS via this upstream: ${stat.dnsQueriesForwarded} ok" +
                        if (stat.dnsQueriesFailed > 0) ", ${stat.dnsQueriesFailed} failed" else "",
                    style = MaterialTheme.typography.bodySmall,
                    color =
                        if (stat.dnsQueriesFailed > 0) MaterialTheme.colorScheme.error
                        else MaterialTheme.colorScheme.secondary,
                )
              }
              if (stat.lastError.isNotEmpty()) {
                Text(
                    "last error: ${stat.lastError}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
              }
            }
          }
          Text(if (expanded) "▲" else "▼", style = MaterialTheme.typography.bodySmall)
        }
        if (expanded) {
          Spacer(modifier = Modifier.height(8.dp))
          Text("Traffic over time", style = MaterialTheme.typography.titleSmall)
          val (trafficEntries, trafficTimestamps) =
              remember(history, resolution) {
                chartSeries(
                    bucketize(
                        deltaSeries(history, { it.ts }, { (it.bytesIn + it.bytesOut).toFloat() }),
                        resolution.targetPoints))
              }
          InteractiveLineChart(
              entries = trafficEntries,
              timestamps = trafficTimestamps,
              color = MaterialTheme.colorScheme.primary,
              modifier = Modifier.fillMaxWidth().height(140.dp),
              formatValue = ::formatBytesPerSample,
              asRate = true,
              resetKey = range,
          )
          if (appBreakdown.isNotEmpty()) {
            Spacer(modifier = Modifier.height(12.dp))
            Text("App consumption distribution", style = MaterialTheme.typography.titleSmall)
            val context = LocalContext.current
            val total =
                appBreakdown.sumOf { it.second.bytesIn + it.second.bytesOut }.coerceAtLeast(1)
            appBreakdown.take(10).forEach { (uid, usage) ->
              val label = remember(uid) { AppNameResolver.labelFor(context, uid) }
              val used = usage.bytesIn + usage.bytesOut
              val fraction = (used.toFloat() / total.toFloat()).coerceIn(0f, 1f)
              Column(modifier = Modifier.padding(vertical = 4.dp)) {
                Row(
                    horizontalArrangement = Arrangement.SpaceBetween,
                    modifier = Modifier.fillMaxWidth()) {
                      Text(label, style = MaterialTheme.typography.bodySmall)
                      Text(
                          "${formatBytesPerSample(used.toFloat())} (${"%.0f".format(fraction * 100)}%)",
                          style = MaterialTheme.typography.bodySmall,
                      )
                    }
                LinearProgressIndicator(
                    progress = fraction,
                    modifier = Modifier.fillMaxWidth().height(6.dp).clip(RoundedCornerShape(3.dp)),
                    color = MaterialTheme.colorScheme.primary,
                )
              }
            }
          }
        }
      }
}

private fun appsSection(
    scope: LazyListScope,
    snapshot: com.tailscale.ipn.ObservabilitySnapshot,
    range: DiagRange,
    resolution: GraphResolution,
) {
  scope.item {
    Text(
        "Per-app traffic",
        style = MaterialTheme.typography.titleMedium,
        modifier = Modifier.padding(top = 12.dp))
    Text(
        "Byte and flow counts are exact. Per-app CPU and battery use are not shown - not " +
            "precisely measurable by default. Tap an app to graph its traffic over time.",
        style = MaterialTheme.typography.bodySmall,
    )
  }
  scope.items(snapshot.apps.sortedByDescending { it.bytesIn + it.bytesOut }, key = { it.uid }) { app
    ->
    AppRow(app, range, resolution)
    HorizontalDivider()
  }
}

@Composable
private fun AppRow(
    app: com.tailscale.ipn.UIDStatsInfo,
    range: DiagRange,
    resolution: GraphResolution
) {
  val context = LocalContext.current
  var expanded by remember(app.uid) { mutableStateOf(false) }
  var history by
      remember(app.uid, range) {
        mutableStateOf<List<ObservabilityDatabaseHelper.AppSample>>(emptyList())
      }
  val label = remember(app.uid) { AppNameResolver.labelFor(context, app.uid) }
  val icon: Drawable? = remember(app.uid) { AppNameResolver.iconFor(context, app.uid) }

  LaunchedEffect(expanded, range) {
    if (!expanded) return@LaunchedEffect
    while (expanded) {
      val since = System.currentTimeMillis() - range.millis
      history =
          withContext(Dispatchers.IO) {
            MultiProxySessionCoordinator.appSamplesSince(app.uid, since)
          }
      delay(2000)
    }
  }

  Column(
      modifier =
          Modifier.fillMaxWidth().clickable { expanded = !expanded }.padding(vertical = 8.dp),
  ) {
    Row(verticalAlignment = Alignment.CenterVertically) {
      if (icon != null) {
        Image(
            bitmap = icon.toBitmap(width = 96, height = 96).asImageBitmap(),
            contentDescription = null,
            modifier = Modifier.size(32.dp).clip(CircleShape),
        )
      } else {
        Box(
            modifier =
                Modifier.size(32.dp)
                    .clip(CircleShape)
                    .background(MaterialTheme.colorScheme.surfaceVariant),
        )
      }
      Spacer(modifier = Modifier.width(12.dp))
      Column(modifier = Modifier.weight(1f)) {
        Text(label, style = MaterialTheme.typography.bodyLarge)
        Text(
            "in/out: ${app.bytesIn}/${app.bytesOut} bytes  tcp=${app.tcpFlows} udp=${app.udpFlows}" +
                if (app.lastUpstream.isNotEmpty()) "  via ${upstreamDisplayLabel(app.lastUpstream)}"
                else "",
            style = MaterialTheme.typography.bodySmall,
        )
        if (app.byUpstream.size > 1) {
          Text(
              "by upstream: " +
                  app.byUpstream
                      .sortedByDescending { it.bytesIn + it.bytesOut }
                      .joinToString("  ") {
                        "${upstreamDisplayName(it.upstreamId)}=${formatBytesPerSample((it.bytesIn + it.bytesOut).toFloat())}"
                      },
              style = MaterialTheme.typography.bodySmall,
              color = MaterialTheme.colorScheme.secondary,
          )
        }
      }
      Text(if (expanded) "▲" else "▼", style = MaterialTheme.typography.bodySmall)
    }
    if (expanded) {
      Spacer(modifier = Modifier.height(8.dp))
      val (entries, timestamps) =
          remember(history, resolution) {
            chartSeries(
                bucketize(
                    deltaSeries(history, { it.ts }, { (it.bytesIn + it.bytesOut).toFloat() }),
                    resolution.targetPoints))
          }
      InteractiveLineChart(
          entries = entries,
          timestamps = timestamps,
          color = MaterialTheme.colorScheme.secondary,
          modifier = Modifier.fillMaxWidth().height(140.dp),
          formatValue = ::formatBytesPerSample,
          asRate = true,
          resetKey = range,
      )
    }
  }
}

private val networkTimestampFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

private fun networkSection(
    scope: LazyListScope,
    events: List<com.tailscale.ipn.ObservabilityEvent>,
    dnsLogEnabled: Boolean,
    onDnsLogEnabledChange: (Boolean) -> Unit,
    dnsSearchQuery: String,
    onDnsSearchQueryChange: (String) -> Unit,
    dnsErrorsOnly: Boolean,
    onDnsErrorsOnlyChange: (Boolean) -> Unit,
) {
  scope.item {
    Text(
        "Network source",
        style = MaterialTheme.typography.titleMedium,
        modifier = Modifier.padding(top = 12.dp))
    Text(
        "Interface: ${com.tailscale.ipn.NetworkChangeCallback.cachedDefaultInterfaceName ?: "none"}",
        style = MaterialTheme.typography.bodyMedium,
    )
    Spacer(modifier = Modifier.height(8.dp))
    Text("Network transitions", style = MaterialTheme.typography.titleMedium)
  }
  scope.items(events.filter { it.eventType == "NETWORK_SOURCE_CHANGED" }.takeLast(30).reversed()) {
      e ->
    Text(
        "${networkTimestampFormat.format(Date(e.timestampMillis))}  ${e.previousState} -> ${e.newState}",
        style = MaterialTheme.typography.bodySmall,
        modifier = Modifier.padding(vertical = 2.dp))
  }
  scope.item {
    Spacer(modifier = Modifier.height(16.dp))
    HorizontalDivider()
    Spacer(modifier = Modifier.height(8.dp))
    Text("DNS query log", style = MaterialTheme.typography.titleMedium)
    Text(
        "Off by default - logs every DNS lookup app-wide (which upstream it went through and " +
            "the outcome: synthetic answer, forwarded ok/failed, blocked, fail-closed, ambiguous). " +
            "Useful for tracking down a query leaking to the wrong upstream, but writes a row " +
            "per query while on, so turn it off again once you've caught what you're looking for. " +
            "Timestamps line up with the network transitions above, so a burst of DNS failures " +
            "right after a transition is visible at a glance.",
        style = MaterialTheme.typography.bodySmall,
    )
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.padding(vertical = 8.dp)) {
          Switch(checked = dnsLogEnabled, onCheckedChange = onDnsLogEnabledChange)
          Spacer(modifier = Modifier.width(8.dp))
          Text(if (dnsLogEnabled) "Enabled" else "Disabled")
        }
  }
  if (dnsLogEnabled) {
    scope.item {
      OutlinedTextField(
          value = dnsSearchQuery,
          onValueChange = onDnsSearchQueryChange,
          modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
          placeholder = { Text("Search query name, upstream, or app uid") },
          leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
          singleLine = true,
      )
    }
    scope.item {
      Row(modifier = Modifier.padding(vertical = 4.dp)) {
        FilterChip(
            selected = dnsErrorsOnly,
            onClick = { onDnsErrorsOnlyChange(!dnsErrorsOnly) },
            label = { Text("Errors only") },
        )
      }
    }
    val dnsEvents =
        events
            .filter { it.eventType == "DNS_QUERY" }
            .filter { e ->
              !dnsErrorsOnly ||
                  e.newState.contains("fail") ||
                  e.newState == "blocked" ||
                  e.newState == "ambiguous"
            }
            .filter { e ->
              dnsSearchQuery.isBlank() ||
                  e.previousState.contains(dnsSearchQuery, ignoreCase = true) ||
                  upstreamDisplayLabel(e.upstreamId).contains(dnsSearchQuery, ignoreCase = true) ||
                  e.appUid.toString() == dnsSearchQuery.trim()
            }
            .takeLast(200)
            .reversed()
    if (dnsEvents.isEmpty()) {
      scope.item {
        Text(
            "No DNS queries match.",
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(vertical = 4.dp))
      }
    } else {
      scope.items(dnsEvents) { e ->
        Text(
            "${networkTimestampFormat.format(Date(e.timestampMillis))}  ${e.previousState} (${e.networkSource})  " +
                "${if (e.upstreamId.isNotEmpty()) upstreamDisplayLabel(e.upstreamId) else "device"} -> ${e.newState}" +
                (if (e.appUid > 0) "  uid=${e.appUid}" else ""),
            style = MaterialTheme.typography.bodySmall,
            color =
                if (e.newState.contains("fail") ||
                    e.newState == "blocked" ||
                    e.newState == "ambiguous") {
                  MaterialTheme.colorScheme.error
                } else {
                  Color.Unspecified
                },
            modifier = Modifier.padding(vertical = 2.dp),
        )
      }
    }
  }
}

@Composable
private fun StatRow(label: String, value: String, color: Color = Color.Unspecified) {
  Row(
      modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
      horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = color)
        Text(value, style = MaterialTheme.typography.bodyMedium, color = color)
      }
}
