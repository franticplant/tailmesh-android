// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.view

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import com.tailscale.ipn.BuildConfig
import com.tailscale.ipn.MultiProxySessionCoordinator
import com.tailscale.ipn.PerfCounters
import com.tailscale.ipn.R
import com.tailscale.ipn.remote.RemoteControl
import com.tailscale.ipn.remote.RemoteShell
import java.io.File
import java.text.SimpleDateFormat
import java.time.OffsetDateTime
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import libtailscale.Libtailscale
import org.json.JSONObject

/** One line in the log viewer, whatever log it came from. */
data class LogRow(val key: Long, val timeMillis: Long, val source: String, val text: String)

/** The logs the viewer can show, one per tab. */
enum class LogKind(val titleRes: Int) {
  APP(R.string.logs_tab_app),
  EVENTS(R.string.logs_tab_events),
  ACCESS(R.string.logs_tab_access),
  SHELL(R.string.logs_tab_shell),
}

private const val MAX_ROWS = 20_000

/**
 * The log viewer: live app and engine logs, observability events, the remote-control access log and
 * (development builds) the shell log, with search, source filters, following the newest line, and
 * export.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun LogsView(onBack: () -> Unit, initial: LogKind = LogKind.APP) {
  val kinds = LogKind.entries.filter { it != LogKind.SHELL || BuildConfig.DEV_TOOLS }
  var kind by rememberSaveable { mutableStateOf(initial) }
  val context = LocalContext.current
  val scope = rememberCoroutineScope()

  // Rows of the current tab, oldest first.
  val rows = remember(kind) { mutableStateListOf<LogRow>() }
  var paused by remember { mutableStateOf(false) }

  var query by rememberSaveable { mutableStateOf("") }
  var regex by rememberSaveable { mutableStateOf(false) }
  var filterMode by rememberSaveable { mutableStateOf(true) } // false: highlight and jump
  var hiddenSources by remember(kind) { mutableStateOf(setOf<String>()) }
  var expanded by remember(kind) { mutableStateOf(setOf<Long>()) }
  var menuOpen by remember { mutableStateOf(false) }

  // ---- loading -------------------------------------------------------------
  LaunchedEffect(kind, paused) {
    if (paused) return@LaunchedEffect
    when (kind) {
      LogKind.APP -> {
        // Buffers from now on in release builds (development builds already do from start).
        Libtailscale.captureRemoteLogsFromStart()
        var next = rows.lastOrNull()?.key ?: 0L
        while (true) {
          PerfCounters.inc("kt.ui.logsPoll")
          val fresh = withContext(Dispatchers.IO) { readAppLogs(next) }
          if (fresh.isNotEmpty()) {
            rows.addAll(fresh)
            next = fresh.last().key
            if (rows.size > MAX_ROWS) rows.removeRange(0, rows.size - MAX_ROWS)
          }
          delay(1000)
        }
      }
      LogKind.EVENTS ->
          MultiProxySessionCoordinator.observabilityEvents.collect { events ->
            val mapped = events.mapIndexed { i, e -> eventRow(i.toLong(), e) }
            if (mapped != rows.toList()) {
              rows.clear()
              rows.addAll(mapped)
            }
          }
      LogKind.ACCESS ->
          while (true) {
            val all = withContext(Dispatchers.IO) { readAccessRows() }
            if (all.size != rows.size || all.lastOrNull() != rows.lastOrNull()) {
              rows.clear()
              rows.addAll(all)
            }
            delay(2000)
          }
      LogKind.SHELL ->
          while (true) {
            val all = withContext(Dispatchers.IO) { readShellRows() }
            if (all.size != rows.size || all.lastOrNull() != rows.lastOrNull()) {
              rows.clear()
              rows.addAll(all)
            }
            delay(2000)
          }
    }
  }

  // ---- search and filters -------------------------------------------------
  val matcher: ((String) -> List<IntRange>)? = remember(query, regex) { buildMatcher(query, regex) }
  val sources by remember(kind) { derivedStateOf { rows.map { it.source }.distinct().sorted() } }
  val visible by
      remember(kind, matcher, filterMode, hiddenSources) {
        derivedStateOf {
          rows.filter { r ->
            r.source !in hiddenSources &&
                (matcher == null ||
                    !filterMode ||
                    matcher(r.text).isNotEmpty() ||
                    matcher(r.source).isNotEmpty())
          }
        }
      }
  // In highlight mode: indexes into visible of the rows that match, for next/previous.
  val matchIndexes by
      remember(kind, matcher, filterMode, hiddenSources) {
        derivedStateOf {
          if (matcher == null || filterMode) emptyList()
          else visible.indices.filter { matcher(visible[it].text).isNotEmpty() }
        }
      }
  var currentMatch by remember(query, regex, filterMode) { mutableStateOf(-1) }

  // ---- following the newest line -------------------------------------------
  val listState = rememberLazyListState()
  val atBottom by derivedStateOf {
    val info = listState.layoutInfo
    val last = info.visibleItemsInfo.lastOrNull()?.index ?: -1
    last >= info.totalItemsCount - 2
  }
  var follow by remember(kind) { mutableStateOf(true) }
  var unseen by remember(kind) { mutableStateOf(0) }
  LaunchedEffect(listState) {
    snapshotFlow { listState.isScrollInProgress to atBottom }
        .collect { (scrolling, bottom) ->
          if (scrolling) follow = bottom
          if (bottom) {
            follow = true
            unseen = 0
          }
        }
  }
  LaunchedEffect(visible.size) {
    if (visible.isEmpty()) return@LaunchedEffect
    if (follow && currentMatch < 0) listState.scrollToItem(visible.lastIndex) else unseen += 1
  }

  // ---- export ---------------------------------------------------------------
  val saveLauncher =
      rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri
        ->
        if (uri == null) return@rememberLauncherForActivityResult
        val text = exportText(visible)
        scope.launch(Dispatchers.IO) {
          context.contentResolver.openOutputStream(uri)?.use { it.write(text.toByteArray()) }
        }
      }

  Scaffold(
      topBar = {
        Header(
            titleRes = R.string.logs,
            onBack = onBack,
            actions = {
              TextButton(onClick = { paused = !paused }) {
                Text(stringResource(if (paused) R.string.logs_resume else R.string.logs_pause))
              }
              IconButton(onClick = { menuOpen = true }) {
                Icon(Icons.Default.MoreVert, contentDescription = null)
              }
              DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.logs_share, visible.size)) },
                    onClick = {
                      menuOpen = false
                      shareLog(context, kind, visible)
                    })
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.logs_save, visible.size)) },
                    onClick = {
                      menuOpen = false
                      saveLauncher.launch(exportName(kind))
                    })
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.logs_copy_all, visible.size)) },
                    onClick = {
                      menuOpen = false
                      copy(context, exportText(visible))
                    })
                if (kind == LogKind.APP)
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.logs_clear_view)) },
                        onClick = {
                          menuOpen = false
                          // The buffer is shared with remote control; only the view is cleared.
                          val last = rows.lastOrNull()
                          rows.clear()
                          last?.let { rows.add(it.copy(text = "--- cleared ---", source = "")) }
                        })
              }
            })
      },
      floatingActionButton = {
        if (!atBottom && visible.isNotEmpty()) {
          ExtendedFloatingActionButton(
              onClick = {
                follow = true
                unseen = 0
                currentMatch = -1
                scope.launch { listState.animateScrollToItem(visible.lastIndex) }
              },
              icon = { Icon(Icons.Default.KeyboardArrowDown, contentDescription = null) },
              text = {
                Text(
                    if (unseen > 0) stringResource(R.string.logs_new_lines, unseen)
                    else stringResource(R.string.logs_latest))
              })
        }
      }) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
          ScrollableTabRow(selectedTabIndex = kinds.indexOf(kind), edgePadding = 8.dp) {
            kinds.forEach { k ->
              Tab(
                  selected = k == kind,
                  onClick = { kind = k },
                  text = { Text(stringResource(k.titleRes)) })
            }
          }

          // Search row.
          Row(
              Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp),
              verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                    placeholder = { Text(stringResource(R.string.logs_search)) },
                    leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
                    trailingIcon = {
                      if (query.isNotEmpty())
                          IconButton(onClick = { query = "" }) {
                            Icon(Icons.Default.Clear, contentDescription = null)
                          }
                    },
                    isError = query.isNotEmpty() && matcher == null,
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                    textStyle = MaterialTheme.typography.bodyMedium)
                if (!filterMode && matchIndexes.isNotEmpty()) {
                  Text(
                      "${if (currentMatch >= 0) currentMatch + 1 else 0}/${matchIndexes.size}",
                      style = MaterialTheme.typography.labelMedium,
                      modifier = Modifier.padding(horizontal = 4.dp))
                  IconButton(
                      onClick = {
                        currentMatch =
                            if (currentMatch <= 0) matchIndexes.lastIndex else currentMatch - 1
                        follow = false
                        scope.launch { listState.scrollToItem(matchIndexes[currentMatch]) }
                      }) {
                        Icon(Icons.Default.KeyboardArrowUp, contentDescription = null)
                      }
                  IconButton(
                      onClick = {
                        currentMatch = (currentMatch + 1) % matchIndexes.size
                        follow = false
                        scope.launch { listState.scrollToItem(matchIndexes[currentMatch]) }
                      }) {
                        Icon(Icons.Default.KeyboardArrowDown, contentDescription = null)
                      }
                }
              }

          // Mode and source chips.
          LazyRow(Modifier.fillMaxWidth().padding(horizontal = 8.dp)) {
            item {
              FilterChip(
                  selected = filterMode,
                  onClick = { filterMode = !filterMode },
                  label = {
                    Text(
                        stringResource(
                            if (filterMode) R.string.logs_mode_filter
                            else R.string.logs_mode_highlight))
                  })
              Spacer(Modifier.width(6.dp))
              FilterChip(
                  selected = regex,
                  onClick = { regex = !regex },
                  label = { Text(stringResource(R.string.logs_regex)) })
              Spacer(Modifier.width(12.dp))
            }
            items(sources.filter { it.isNotEmpty() }) { src ->
              FilterChip(
                  selected = src !in hiddenSources,
                  onClick = {
                    hiddenSources =
                        if (src in hiddenSources) hiddenSources - src else hiddenSources + src
                  },
                  label = { Text(src) })
              Spacer(Modifier.width(6.dp))
            }
          }

          Text(
              stringResource(R.string.logs_count, visible.size, rows.size) +
                  if (paused) " · " + stringResource(R.string.logs_paused) else "",
              style = MaterialTheme.typography.labelSmall,
              color = MaterialTheme.colorScheme.onSurfaceVariant,
              modifier = Modifier.padding(horizontal = 12.dp, vertical = 2.dp))

          Box(Modifier.fillMaxSize()) {
            if (visible.isEmpty()) {
              Text(
                  stringResource(
                      if (rows.isEmpty()) R.string.logs_empty else R.string.logs_no_matches),
                  modifier = Modifier.align(Alignment.Center).padding(24.dp),
                  color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            LazyColumn(state = listState, modifier = Modifier.fillMaxSize()) {
              itemsIndexed(visible, key = { _, r -> r.key }) { i, r ->
                val isCurrent = currentMatch >= 0 && matchIndexes.getOrNull(currentMatch) == i
                LogLine(
                    row = r,
                    ranges = matcher?.invoke(r.text).orEmpty(),
                    expanded = r.key in expanded,
                    current = isCurrent,
                    onClick = {
                      expanded = if (r.key in expanded) expanded - r.key else expanded + r.key
                    },
                    onLongClick = { copy(context, exportLine(r)) })
              }
            }
          }
        }
      }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun LogLine(
    row: LogRow,
    ranges: List<IntRange>,
    expanded: Boolean,
    current: Boolean,
    onClick: () -> Unit,
    onLongClick: () -> Unit,
) {
  val highlight = MaterialTheme.colorScheme.tertiaryContainer
  val text: AnnotatedString =
      remember(row.text, ranges, highlight) {
        buildAnnotatedString {
          var at = 0
          for (r in ranges) {
            if (r.first < at || r.last >= row.text.length) continue
            append(row.text.substring(at, r.first))
            withStyle(SpanStyle(background = highlight, fontWeight = FontWeight.Bold)) {
              append(row.text.substring(r.first, r.last + 1))
            }
            at = r.last + 1
          }
          append(row.text.substring(at))
        }
      }
  Row(
      Modifier.fillMaxWidth()
          .then(
              if (current) Modifier.background(MaterialTheme.colorScheme.secondaryContainer)
              else Modifier)
          .combinedClickable(onClick = onClick, onLongClick = onLongClick)
          .padding(horizontal = 8.dp, vertical = 2.dp)) {
        Text(
            timeFormat.get()!!.format(Date(row.timeMillis)),
            fontFamily = FontFamily.Monospace,
            fontSize = 11.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.width(6.dp))
        Text(
            row.source.take(8),
            fontFamily = FontFamily.Monospace,
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            color = sourceColor(row.source),
            modifier = Modifier.width(64.dp),
            maxLines = 1,
            overflow = TextOverflow.Clip)
        Text(
            text,
            fontFamily = FontFamily.Monospace,
            fontSize = 11.sp,
            lineHeight = 14.sp,
            maxLines = if (expanded) Int.MAX_VALUE else 3,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f))
      }
}

private val timeFormat = ThreadLocal.withInitial { SimpleDateFormat("HH:mm:ss.SSS", Locale.ROOT) }

private val palette =
    listOf(
        Color(0xFF2E7D32),
        Color(0xFF1565C0),
        Color(0xFF6A1B9A),
        Color(0xFFEF6C00),
        Color(0xFF00838F),
        Color(0xFFAD1457),
    )

/** A stable colour per source name, so "go" and "app" are told apart at a glance. */
private fun sourceColor(source: String): Color =
    palette[(source.hashCode() and 0x7fffffff) % palette.size]

/**
 * The match ranges of [query] in a line: case-insensitive substring, or a regular expression. Null
 * when there is no query, or the expression does not compile (the field shows an error).
 */
private fun buildMatcher(query: String, regex: Boolean): ((String) -> List<IntRange>)? {
  if (query.isEmpty()) return null
  if (regex) {
    val re =
        try {
          Regex(query, RegexOption.IGNORE_CASE)
        } catch (e: Exception) {
          return null
        }
    return { line ->
      re.findAll(line).filter { !it.range.isEmpty() }.map { it.range }.take(50).toList()
    }
  }
  return { line ->
    val out = ArrayList<IntRange>()
    var i = line.indexOf(query, ignoreCase = true)
    while (i >= 0 && out.size < 50) {
      out.add(i until i + query.length)
      i = line.indexOf(query, i + query.length, ignoreCase = true)
    }
    out
  }
}

// ---- loaders ------------------------------------------------------------------

private fun parseTime(s: String): Long =
    try {
      OffsetDateTime.parse(s).toInstant().toEpochMilli()
    } catch (e: Exception) {
      0L
    }

private fun readAppLogs(after: Long): List<LogRow> {
  val o = JSONObject(Libtailscale.appLogsJSON(after, 5000))
  val arr = o.optJSONArray("lines") ?: return emptyList()
  return (0 until arr.length()).map { i ->
    val l = arr.getJSONObject(i)
    LogRow(
        l.getLong("seq"),
        parseTime(l.optString("time")),
        l.optString("source"),
        l.optString("text"))
  }
}

private fun eventRow(i: Long, e: com.tailscale.ipn.ObservabilityEvent): LogRow {
  val parts = buildList {
    if (e.upstreamId.isNotEmpty()) add(e.upstreamId)
    if (e.appUid >= 0) add("uid=${e.appUid}")
    if (e.previousState.isNotEmpty() || e.newState.isNotEmpty())
        add("${e.previousState} -> ${e.newState}")
    if (e.networkSource.isNotEmpty()) add("net=${e.networkSource}")
    if (e.metadataJSON.isNotEmpty() && e.metadataJSON != "{}") add(e.metadataJSON)
  }
  return LogRow(i, e.timestampMillis, e.eventType, parts.joinToString("  "))
}

private fun readAccessRows(): List<LogRow> =
    RemoteControl.readAccessLog(2000).mapIndexed { i, a ->
      LogRow(
          i.toLong(),
          parseTime(a.time),
          a.action.substringBefore(' ').substringBefore('.').ifEmpty { "access" },
          buildString {
            append(a.action)
            append("  ")
            append(a.status)
            if (a.client.isNotEmpty()) append("  ${a.client}")
            append("  ${a.remote}")
            if (a.error.isNotEmpty()) append("  error: ${a.error}")
          })
    }

private fun readShellRows(): List<LogRow> =
    RemoteShell.readLog(2000).map { e ->
      LogRow(
          e.seq,
          parseTime(e.time),
          e.kind,
          buildString {
            append("#${e.seq} ")
            if (e.cmd.isNotEmpty()) append("$ ${e.cmd}  ")
            e.exit?.let { append("exit $it  ") }
            if (e.client.isNotEmpty()) append("${e.client}  ")
            if (e.note.isNotEmpty()) append(e.note)
            append("  [${e.hash.take(12)}]")
          })
    }

// ---- export -------------------------------------------------------------------

private fun exportLine(r: LogRow): String =
    "${timeFormat.get()!!.format(Date(r.timeMillis))} ${r.source} ${r.text}"

private fun exportText(rows: List<LogRow>): String =
    rows.joinToString("\n", postfix = "\n") { exportLine(it) }

private fun exportName(kind: LogKind): String =
    "tailmesh-${kind.name.lowercase()}-${SimpleDateFormat("yyyyMMdd-HHmmss", Locale.ROOT).format(Date())}.txt"

private fun copy(context: Context, text: String) {
  val cm = context.getSystemService(ClipboardManager::class.java)
  cm.setPrimaryClip(ClipData.newPlainText("Tailmesh log", text))
  Toast.makeText(context, R.string.logs_copied, Toast.LENGTH_SHORT).show()
}

private fun shareLog(context: Context, kind: LogKind, rows: List<LogRow>) {
  val dir = File(context.cacheDir, "logs").apply { mkdirs() }
  dir.listFiles()?.forEach { it.delete() } // only the latest export is kept
  val file = File(dir, exportName(kind))
  file.writeText(exportText(rows))
  val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
  val intent =
      Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_STREAM, uri)
        putExtra(Intent.EXTRA_SUBJECT, file.name)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
      }
  context.startActivity(Intent.createChooser(intent, file.name))
}
