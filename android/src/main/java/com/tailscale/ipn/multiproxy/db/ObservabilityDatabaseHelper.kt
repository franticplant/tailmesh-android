// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package com.tailscale.ipn.multiproxy.db

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/**
 * Bounded local storage for the observability feature's time-series samples and discrete events.
 *
 * Deliberately a separate database from [TailnetDatabaseHelper] rather than added tables there:
 * this data is disposable (losing it costs nothing but some graph history), is written far more
 * often (once per sample tick, not once per user action), and its retention/pruning policy is
 * unrelated to profile/upstream configuration's lifecycle. Plain SQLite via SQLiteOpenHelper,
 * matching the existing project convention (TailnetDatabaseHelper) rather than introducing Room
 * for what is, in the end, two simple tables with a handful of columns.
 *
 * Retention (see [prune]):
 *  - Samples: kept at ~1-minute resolution for the most recent [SAMPLE_FULL_RES_MILLIS] (6h),
 *    downsampled to 15-minute resolution beyond that, and dropped entirely beyond
 *    [SAMPLE_MAX_AGE_MILLIS] (7 days). Downsampling keeps one row per 15-minute bucket (the last
 *    sample observed in that bucket) rather than averaging, which is cheap (a DELETE, not a
 *    recompute) and good enough for a "what happened around here" graph at that zoom level - see
 *    docs/multi_tailnet_proxy_app/observability.md for the tradeoff.
 *  - Events: kept for [EVENT_MAX_AGE_MILLIS] (7 days), capped at [EVENT_MAX_ROWS] regardless of
 *    age so a pathological flapping condition cannot grow the table unboundedly between prune
 *    calls.
 */
class ObservabilityDatabaseHelper(context: Context) :
    SQLiteOpenHelper(context, DATABASE_NAME, null, DATABASE_VERSION) {

  companion object {
    const val DATABASE_NAME = "multiproxy_observability.db"
    const val DATABASE_VERSION = 3

    const val TABLE_SAMPLES = "samples"
    const val COL_TS = "ts"
    const val COL_CPU_PERCENT = "cpu_percent"
    const val COL_CPU_SECONDS = "cpu_seconds"
    const val COL_HEAP_BYTES = "heap_bytes"
    const val COL_GOROUTINES = "goroutines"
    const val COL_TUN_RX_BYTES = "tun_rx_bytes"
    const val COL_TUN_TX_BYTES = "tun_tx_bytes"
    const val COL_DNS_FAILURES = "dns_failures"

    const val TABLE_EVENTS = "events"
    const val COL_EVENT_TYPE = "event_type"
    const val COL_UPSTREAM_ID = "upstream_id"
    const val COL_APP_UID = "app_uid"
    const val COL_NETWORK_SOURCE = "network_source"
    const val COL_PREV_STATE = "prev_state"
    const val COL_NEW_STATE = "new_state"
    const val COL_META = "meta"

    const val SAMPLE_FULL_RES_MILLIS = 6L * 60 * 60 * 1000 // 6h
    const val SAMPLE_DOWNSAMPLE_BUCKET_MILLIS = 15L * 60 * 1000 // 15m
    const val SAMPLE_MAX_AGE_MILLIS = 7L * 24 * 60 * 60 * 1000 // 7d
    const val EVENT_MAX_AGE_MILLIS = 7L * 24 * 60 * 60 * 1000 // 7d
    const val EVENT_MAX_ROWS = 5000

    const val TABLE_APP_SAMPLES = "app_samples"
    const val COL_BYTES_IN = "bytes_in"
    const val COL_BYTES_OUT = "bytes_out"
    const val COL_TCP_FLOWS = "tcp_flows"
    const val COL_UDP_FLOWS = "udp_flows"

    // How many of the busiest apps get a row written per sampler tick. Per-app
    // history is opt-in-by-usage (only apps that are actually generating
    // traffic have any row at all, via uidRegistry - see observability.go),
    // but a device with many simultaneously-active apps could still turn
    // this into an unbounded per-tick write fanout, so it's additionally
    // capped to the busiest apps that tick - which are also the only ones a
    // per-app graph is useful for.
    const val APP_SAMPLE_MAX_PER_TICK = 20

    // Per-upstream history, generic across upstream kinds (Tailnet/regular, exit node, SOCKS5,
    // WireGuard, @direct) - the same UpstreamStatSnapshot the Proxies & tunnels screen already
    // polls, just persisted at the observability sampler's own cadence so the Tailnets tab can
    // graph it instead of only showing a live number. See upstreamSamplesSince/insertUpstreamSamples.
    const val TABLE_UPSTREAM_SAMPLES = "upstream_samples"
    const val COL_UPSTREAM_ID_COL = "upstream_id"
    const val COL_DIAL_ATTEMPTS = "dial_attempts"
    const val COL_DIAL_SUCCESSES = "dial_successes"
    const val COL_DIAL_FAILURES = "dial_failures"
    const val UPSTREAM_SAMPLE_MAX_PER_TICK = 30
  }

  override fun onCreate(db: SQLiteDatabase) {
    db.execSQL(
        """
        CREATE TABLE $TABLE_SAMPLES (
          $COL_TS INTEGER PRIMARY KEY,
          $COL_CPU_PERCENT REAL,
          $COL_CPU_SECONDS REAL,
          $COL_HEAP_BYTES INTEGER,
          $COL_GOROUTINES INTEGER,
          $COL_TUN_RX_BYTES INTEGER,
          $COL_TUN_TX_BYTES INTEGER,
          $COL_DNS_FAILURES INTEGER
        )
        """
            .trimIndent())
    db.execSQL(
        """
        CREATE TABLE $TABLE_EVENTS (
          _id INTEGER PRIMARY KEY AUTOINCREMENT,
          $COL_TS INTEGER,
          $COL_EVENT_TYPE TEXT,
          $COL_UPSTREAM_ID TEXT,
          $COL_APP_UID INTEGER,
          $COL_NETWORK_SOURCE TEXT,
          $COL_PREV_STATE TEXT,
          $COL_NEW_STATE TEXT,
          $COL_META TEXT
        )
        """
            .trimIndent())
    db.execSQL("CREATE INDEX idx_events_ts ON $TABLE_EVENTS($COL_TS)")
    createAppSamplesTable(db)
    createUpstreamSamplesTable(db)
  }

  private fun createAppSamplesTable(db: SQLiteDatabase) {
    db.execSQL(
        """
        CREATE TABLE $TABLE_APP_SAMPLES (
          _id INTEGER PRIMARY KEY AUTOINCREMENT,
          $COL_TS INTEGER,
          $COL_APP_UID INTEGER,
          $COL_BYTES_IN INTEGER,
          $COL_BYTES_OUT INTEGER,
          $COL_TCP_FLOWS INTEGER,
          $COL_UDP_FLOWS INTEGER
        )
        """
            .trimIndent())
    db.execSQL("CREATE INDEX idx_app_samples_uid_ts ON $TABLE_APP_SAMPLES($COL_APP_UID, $COL_TS)")
  }

  private fun createUpstreamSamplesTable(db: SQLiteDatabase) {
    db.execSQL(
        """
        CREATE TABLE $TABLE_UPSTREAM_SAMPLES (
          _id INTEGER PRIMARY KEY AUTOINCREMENT,
          $COL_TS INTEGER,
          $COL_UPSTREAM_ID_COL TEXT,
          $COL_BYTES_IN INTEGER,
          $COL_BYTES_OUT INTEGER,
          $COL_DIAL_ATTEMPTS INTEGER,
          $COL_DIAL_SUCCESSES INTEGER,
          $COL_DIAL_FAILURES INTEGER
        )
        """
            .trimIndent())
    db.execSQL(
        "CREATE INDEX idx_upstream_samples_id_ts ON $TABLE_UPSTREAM_SAMPLES($COL_UPSTREAM_ID_COL, $COL_TS)")
  }

  override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
    if (oldVersion < 2) {
      createAppSamplesTable(db)
    }
    if (oldVersion < 3) {
      createUpstreamSamplesTable(db)
    }
  }

  data class Sample(
      val ts: Long,
      val cpuPercent: Double,
      val cpuSeconds: Double,
      val heapBytes: Long,
      val goroutines: Int,
      val tunRxBytes: Long,
      val tunTxBytes: Long,
      val dnsFailures: Long,
  )

  data class AppSample(
      val ts: Long,
      val appUid: Int,
      val bytesIn: Long,
      val bytesOut: Long,
      val tcpFlows: Long,
      val udpFlows: Long,
  )

  data class UpstreamSample(
      val ts: Long,
      val upstreamId: String,
      val bytesIn: Long,
      val bytesOut: Long,
      val dialAttempts: Long,
      val dialSuccesses: Long,
      val dialFailures: Long,
  )

  data class Event(
      val ts: Long,
      val eventType: String,
      val upstreamId: String,
      val appUid: Int,
      val networkSource: String,
      val prevState: String,
      val newState: String,
      val meta: String,
  )

  fun insertSample(s: Sample) {
    val values =
        ContentValues().apply {
          put(COL_TS, s.ts)
          put(COL_CPU_PERCENT, s.cpuPercent)
          put(COL_CPU_SECONDS, s.cpuSeconds)
          put(COL_HEAP_BYTES, s.heapBytes)
          put(COL_GOROUTINES, s.goroutines)
          put(COL_TUN_RX_BYTES, s.tunRxBytes)
          put(COL_TUN_TX_BYTES, s.tunTxBytes)
          put(COL_DNS_FAILURES, s.dnsFailures)
        }
    // Sampling ticks are already at least a second apart, but a
    // conflict (e.g. two rapid diagnostics-screen-visibility toggles
    // both landing a sample in the same millisecond) should replace
    // rather than crash the sampler.
    writableDatabase.insertWithOnConflict(
        TABLE_SAMPLES, null, values, SQLiteDatabase.CONFLICT_REPLACE)
  }

  /**
   * Writes one row per app for this sampler tick, capped to the busiest
   * [APP_SAMPLE_MAX_PER_TICK] apps by total bytes - see that constant's doc
   * comment. `samples` is expected already sorted or unsorted; this sorts and
   * truncates itself so callers don't need to.
   */
  fun insertAppSamples(ts: Long, samples: List<AppSample>) {
    val top = samples.sortedByDescending { it.bytesIn + it.bytesOut }.take(APP_SAMPLE_MAX_PER_TICK)
    if (top.isEmpty()) return
    val db = writableDatabase
    db.beginTransaction()
    try {
      for (s in top) {
        val values =
            ContentValues().apply {
              put(COL_TS, ts)
              put(COL_APP_UID, s.appUid)
              put(COL_BYTES_IN, s.bytesIn)
              put(COL_BYTES_OUT, s.bytesOut)
              put(COL_TCP_FLOWS, s.tcpFlows)
              put(COL_UDP_FLOWS, s.udpFlows)
            }
        db.insert(TABLE_APP_SAMPLES, null, values)
      }
      db.setTransactionSuccessful()
    } finally {
      db.endTransaction()
    }
  }

  /** Per-app samples for one UID since sinceMillis, oldest first - what the per-app graph reads. */
  fun appSamplesSince(appUid: Int, sinceMillis: Long): List<AppSample> {
    val out = mutableListOf<AppSample>()
    readableDatabase
        .rawQuery(
            "SELECT $COL_TS, $COL_APP_UID, $COL_BYTES_IN, $COL_BYTES_OUT, $COL_TCP_FLOWS, $COL_UDP_FLOWS " +
                "FROM $TABLE_APP_SAMPLES WHERE $COL_APP_UID = ? AND $COL_TS >= ? ORDER BY $COL_TS ASC",
            arrayOf(appUid.toString(), sinceMillis.toString()))
        .use { c ->
          while (c.moveToNext()) {
            out.add(
                AppSample(
                    ts = c.getLong(0),
                    appUid = c.getInt(1),
                    bytesIn = c.getLong(2),
                    bytesOut = c.getLong(3),
                    tcpFlows = c.getLong(4),
                    udpFlows = c.getLong(5),
                ))
          }
        }
    return out
  }

  /** Distinct app UIDs with any recorded history since sinceMillis, for the Apps tab's picker. */
  fun appUidsSince(sinceMillis: Long): List<Int> {
    val out = mutableListOf<Int>()
    readableDatabase
        .rawQuery(
            "SELECT DISTINCT $COL_APP_UID FROM $TABLE_APP_SAMPLES WHERE $COL_TS >= ?",
            arrayOf(sinceMillis.toString()))
        .use { c ->
          while (c.moveToNext()) out.add(c.getInt(0))
        }
    return out
  }

  /** Writes one row per upstream for this sampler tick - mirrors insertAppSamples. */
  fun insertUpstreamSamples(ts: Long, samples: List<UpstreamSample>) {
    val top = samples.take(UPSTREAM_SAMPLE_MAX_PER_TICK)
    if (top.isEmpty()) return
    val db = writableDatabase
    db.beginTransaction()
    try {
      for (s in top) {
        val values =
            ContentValues().apply {
              put(COL_TS, ts)
              put(COL_UPSTREAM_ID_COL, s.upstreamId)
              put(COL_BYTES_IN, s.bytesIn)
              put(COL_BYTES_OUT, s.bytesOut)
              put(COL_DIAL_ATTEMPTS, s.dialAttempts)
              put(COL_DIAL_SUCCESSES, s.dialSuccesses)
              put(COL_DIAL_FAILURES, s.dialFailures)
            }
        db.insert(TABLE_UPSTREAM_SAMPLES, null, values)
      }
      db.setTransactionSuccessful()
    } finally {
      db.endTransaction()
    }
  }

  /** Per-upstream samples for one upstream id since sinceMillis, oldest first. */
  fun upstreamSamplesSince(upstreamId: String, sinceMillis: Long): List<UpstreamSample> {
    val out = mutableListOf<UpstreamSample>()
    readableDatabase
        .rawQuery(
            "SELECT $COL_TS, $COL_UPSTREAM_ID_COL, $COL_BYTES_IN, $COL_BYTES_OUT, $COL_DIAL_ATTEMPTS, $COL_DIAL_SUCCESSES, $COL_DIAL_FAILURES " +
                "FROM $TABLE_UPSTREAM_SAMPLES WHERE $COL_UPSTREAM_ID_COL = ? AND $COL_TS >= ? ORDER BY $COL_TS ASC",
            arrayOf(upstreamId, sinceMillis.toString()))
        .use { c ->
          while (c.moveToNext()) {
            out.add(
                UpstreamSample(
                    ts = c.getLong(0),
                    upstreamId = c.getString(1) ?: "",
                    bytesIn = c.getLong(2),
                    bytesOut = c.getLong(3),
                    dialAttempts = c.getLong(4),
                    dialSuccesses = c.getLong(5),
                    dialFailures = c.getLong(6),
                ))
          }
        }
    return out
  }

  fun insertEvent(e: Event) {
    val values =
        ContentValues().apply {
          put(COL_TS, e.ts)
          put(COL_EVENT_TYPE, e.eventType)
          put(COL_UPSTREAM_ID, e.upstreamId)
          put(COL_APP_UID, e.appUid)
          put(COL_NETWORK_SOURCE, e.networkSource)
          put(COL_PREV_STATE, e.prevState)
          put(COL_NEW_STATE, e.newState)
          put(COL_META, e.meta)
        }
    writableDatabase.insert(TABLE_EVENTS, null, values)
  }

  /** Samples with ts >= sinceMillis, oldest first - what the graphs read. */
  fun samplesSince(sinceMillis: Long): List<Sample> {
    val out = mutableListOf<Sample>()
    readableDatabase
        .rawQuery(
            "SELECT $COL_TS, $COL_CPU_PERCENT, $COL_CPU_SECONDS, $COL_HEAP_BYTES, $COL_GOROUTINES, $COL_TUN_RX_BYTES, $COL_TUN_TX_BYTES, $COL_DNS_FAILURES " +
                "FROM $TABLE_SAMPLES WHERE $COL_TS >= ? ORDER BY $COL_TS ASC",
            arrayOf(sinceMillis.toString()))
        .use { c ->
          while (c.moveToNext()) {
            out.add(
                Sample(
                    ts = c.getLong(0),
                    cpuPercent = c.getDouble(1),
                    cpuSeconds = c.getDouble(2),
                    heapBytes = c.getLong(3),
                    goroutines = c.getInt(4),
                    tunRxBytes = c.getLong(5),
                    tunTxBytes = c.getLong(6),
                    dnsFailures = c.getLong(7),
                ))
          }
        }
    return out
  }

  /** Events with ts >= sinceMillis, oldest first - for the event log and graph overlays. */
  fun eventsSince(sinceMillis: Long): List<Event> {
    val out = mutableListOf<Event>()
    readableDatabase
        .rawQuery(
            "SELECT $COL_TS, $COL_EVENT_TYPE, $COL_UPSTREAM_ID, $COL_APP_UID, $COL_NETWORK_SOURCE, $COL_PREV_STATE, $COL_NEW_STATE, $COL_META " +
                "FROM $TABLE_EVENTS WHERE $COL_TS >= ? ORDER BY $COL_TS ASC",
            arrayOf(sinceMillis.toString()))
        .use { c ->
          while (c.moveToNext()) {
            out.add(
                Event(
                    ts = c.getLong(0),
                    eventType = c.getString(1) ?: "",
                    upstreamId = c.getString(2) ?: "",
                    appUid = c.getInt(3),
                    networkSource = c.getString(4) ?: "",
                    prevState = c.getString(5) ?: "",
                    newState = c.getString(6) ?: "",
                    meta = c.getString(7) ?: "",
                ))
          }
        }
    return out
  }

  /**
   * "Reset stats" support for persisted history: [sinceMillis] null clears every row in all
   * three tables; otherwise only rows newer than [sinceMillis] are dropped ("reset last X" -
   * older history is left alone, since the ask is to clear recent noise, not the whole record).
   */
  fun resetHistory(sinceMillis: Long?) {
    val db = writableDatabase
    db.beginTransaction()
    try {
      if (sinceMillis == null) {
        db.execSQL("DELETE FROM $TABLE_SAMPLES")
        db.execSQL("DELETE FROM $TABLE_EVENTS")
        db.execSQL("DELETE FROM $TABLE_APP_SAMPLES")
        db.execSQL("DELETE FROM $TABLE_UPSTREAM_SAMPLES")
      } else {
        db.execSQL("DELETE FROM $TABLE_SAMPLES WHERE $COL_TS >= ?", arrayOf(sinceMillis))
        db.execSQL("DELETE FROM $TABLE_EVENTS WHERE $COL_TS >= ?", arrayOf(sinceMillis))
        db.execSQL("DELETE FROM $TABLE_APP_SAMPLES WHERE $COL_TS >= ?", arrayOf(sinceMillis))
        db.execSQL("DELETE FROM $TABLE_UPSTREAM_SAMPLES WHERE $COL_TS >= ?", arrayOf(sinceMillis))
      }
      db.setTransactionSuccessful()
    } finally {
      db.endTransaction()
    }
  }

  /**
   * Bounds table growth: drops samples older than [SAMPLE_MAX_AGE_MILLIS], downsamples
   * older-than-[SAMPLE_FULL_RES_MILLIS] samples to one row per 15-minute bucket, and drops events
   * older than [EVENT_MAX_AGE_MILLIS] or beyond [EVENT_MAX_ROWS] total. Cheap enough to call on
   * every sampler tick (a handful of DELETEs against indexed/PK columns) but the caller only needs
   * to call it at a low cadence (e.g. once a minute) - see ObservabilitySampler.
   */
  fun prune(nowMillis: Long) {
    val db = writableDatabase
    db.beginTransaction()
    try {
      db.execSQL(
          "DELETE FROM $TABLE_SAMPLES WHERE $COL_TS < ?",
          arrayOf(nowMillis - SAMPLE_MAX_AGE_MILLIS))

      // Downsample the region between max-age and full-res: keep only the
      // latest row observed in each 15-minute bucket, delete the rest. This
      // runs as a single DELETE using a self-join on the bucket's max ts,
      // so it costs one pass over the (already small, since older rows were
      // just capped above) table rather than a row-by-row loop.
      val downsampleCutoff = nowMillis - SAMPLE_FULL_RES_MILLIS
      db.execSQL(
          """
          DELETE FROM $TABLE_SAMPLES
          WHERE $COL_TS < ?
          AND $COL_TS NOT IN (
            SELECT MAX($COL_TS) FROM $TABLE_SAMPLES
            WHERE $COL_TS < ?
            GROUP BY $COL_TS / $SAMPLE_DOWNSAMPLE_BUCKET_MILLIS
          )
          """
              .trimIndent(),
          arrayOf(downsampleCutoff, downsampleCutoff))

      db.execSQL(
          "DELETE FROM $TABLE_EVENTS WHERE $COL_TS < ?",
          arrayOf(nowMillis - EVENT_MAX_AGE_MILLIS))
      db.execSQL(
          "DELETE FROM $TABLE_EVENTS WHERE _id NOT IN (SELECT _id FROM $TABLE_EVENTS ORDER BY _id DESC LIMIT $EVENT_MAX_ROWS)")

      db.execSQL(
          "DELETE FROM $TABLE_APP_SAMPLES WHERE $COL_TS < ?",
          arrayOf(nowMillis - SAMPLE_MAX_AGE_MILLIS))

      db.execSQL(
          "DELETE FROM $TABLE_UPSTREAM_SAMPLES WHERE $COL_TS < ?",
          arrayOf(nowMillis - SAMPLE_MAX_AGE_MILLIS))

      db.setTransactionSuccessful()
    } finally {
      db.endTransaction()
    }
  }
}
