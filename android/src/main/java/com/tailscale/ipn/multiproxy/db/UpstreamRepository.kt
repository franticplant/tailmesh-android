// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.multiproxy.db

import android.content.ContentValues
import android.content.Context
import com.tailscale.ipn.util.TSLog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext

/**
 * Stores the non-Tailnet upstreams the user has configured.
 *
 * Mirrors [ProfileRepository]: a StateFlow the UI observes, refreshed after every write, with reads
 * served from memory.
 */
class UpstreamRepository(context: Context) {
  private val dbHelper = TailnetDatabaseHelper(context)
  private val _upstreams = MutableStateFlow<List<Upstream>>(emptyList())
  val upstreams: StateFlow<List<Upstream>> = _upstreams.asStateFlow()

  init {
    refresh()
  }

  private fun refresh() {
    val list = mutableListOf<Upstream>()
    dbHelper.readableDatabase
        .query(
            TailnetDatabaseHelper.TABLE_UPSTREAMS,
            null,
            null,
            null,
            null,
            null,
            "${TailnetDatabaseHelper.COL_CREATED_AT} ASC",
        )
        .use { cursor ->
          while (cursor.moveToNext()) {
            fun string(column: String) = cursor.getString(cursor.getColumnIndexOrThrow(column))
            fun long(column: String) = cursor.getLong(cursor.getColumnIndexOrThrow(column))

            val id = string(TailnetDatabaseHelper.COL_UPSTREAM_ID)
            val kindName = string(TailnetDatabaseHelper.COL_UPSTREAM_KIND)
            // A row whose kind this build does not recognise is skipped rather than
            // crashing the read: a downgrade after a future version added a kind
            // would otherwise make every upstream unreadable.
            val kind = UpstreamKind.fromStorage(kindName)
            if (kind == null) {
              TSLog.d(TAG, "ignoring upstream $id with unknown kind $kindName")
              continue
            }
            list +=
                Upstream(
                    id = id,
                    kind = kind,
                    label = string(TailnetDatabaseHelper.COL_UPSTREAM_LABEL),
                    via = string(TailnetDatabaseHelper.COL_UPSTREAM_VIA),
                    enabled =
                        cursor.getInt(
                            cursor.getColumnIndexOrThrow(TailnetDatabaseHelper.COL_ENABLED)) == 1,
                    createdAt = long(TailnetDatabaseHelper.COL_CREATED_AT),
                    updatedAt = long(TailnetDatabaseHelper.COL_UPDATED_AT),
                    sourceTailnetId = string(TailnetDatabaseHelper.COL_UPSTREAM_SOURCE_TAILNET),
                    peerAddr = string(TailnetDatabaseHelper.COL_UPSTREAM_PEER_ADDR),
                )
          }
        }
    _upstreams.value = list
  }

  /**
   * Inserts or replaces an upstream outright, exactly as given - used for upstreams the caller
   * always constructs whole (e.g. [saveExitNode]'s freshly-`UUID.randomUUID()`'d rows, which have
   * no prior row to preserve anything from). Editing an existing config-bearing upstream should go
   * through [saveConfig] instead, which protects fields like `enabled` from being reverted by a
   * concurrent write.
   */
  suspend fun save(upstream: Upstream) =
      withContext(Dispatchers.IO) {
        val updated = upstream.copy(updatedAt = System.currentTimeMillis())
        dbHelper.writableDatabase.replaceOrThrow(
            TailnetDatabaseHelper.TABLE_UPSTREAMS, null, values(updated))
        refresh()
      }

  /**
   * Inserts a new config-bearing upstream (SOCKS5/WireGuard), or edits an existing one's
   * kind/label/via - preserving its `enabled` state and original `createdAt` across the edit.
   *
   * The existing row is read fresh from the database, inside the same transaction as the write -
   * not from the in-memory [_upstreams] snapshot - so a [setEnabled] call for the same id racing
   * this edit can't have its change silently reverted by a stale-snapshot merge. Same reasoning as
   * AppBindingRepository.upsert's doc comment.
   */
  suspend fun saveConfig(id: String, kind: UpstreamKind, label: String, via: String) =
      withContext(Dispatchers.IO) {
        val db = dbHelper.writableDatabase
        val now = System.currentTimeMillis()
        db.beginTransaction()
        try {
          val existing =
              db.query(
                      TailnetDatabaseHelper.TABLE_UPSTREAMS,
                      arrayOf(
                          TailnetDatabaseHelper.COL_ENABLED, TailnetDatabaseHelper.COL_CREATED_AT),
                      "${TailnetDatabaseHelper.COL_UPSTREAM_ID} = ?",
                      arrayOf(id),
                      null,
                      null,
                      null)
                  .use { cursor ->
                    if (!cursor.moveToFirst()) null
                    else
                        Pair(
                            cursor.getInt(
                                cursor.getColumnIndexOrThrow(TailnetDatabaseHelper.COL_ENABLED)) ==
                                1,
                            cursor.getLong(
                                cursor.getColumnIndexOrThrow(TailnetDatabaseHelper.COL_CREATED_AT)))
                  }
          val upstream =
              Upstream(
                  id = id,
                  kind = kind,
                  label = label.ifBlank { id },
                  via = via,
                  enabled = existing?.first ?: true,
                  createdAt = existing?.second ?: now,
                  updatedAt = now,
              )
          db.replaceOrThrow(TailnetDatabaseHelper.TABLE_UPSTREAMS, null, values(upstream))
          db.setTransactionSuccessful()
        } finally {
          db.endTransaction()
        }
        refresh()
      }

  /**
   * Deletes an upstream, and clears any chaining and app bindings that pointed at it.
   *
   * Leaving a dangling `via` or binding behind would not be unsafe - both fail closed in Go - but
   * it would leave the UI showing a chain through something that no longer exists.
   */
  suspend fun delete(id: String) =
      withContext(Dispatchers.IO) {
        val db = dbHelper.writableDatabase
        db.beginTransaction()
        try {
          db.delete(
              TailnetDatabaseHelper.TABLE_UPSTREAMS,
              "${TailnetDatabaseHelper.COL_UPSTREAM_ID} = ?",
              arrayOf(id))
          db.update(
              TailnetDatabaseHelper.TABLE_UPSTREAMS,
              ContentValues().apply { put(TailnetDatabaseHelper.COL_UPSTREAM_VIA, "") },
              "${TailnetDatabaseHelper.COL_UPSTREAM_VIA} = ?",
              arrayOf(id))
          db.delete(
              TailnetDatabaseHelper.TABLE_APP_BINDINGS,
              "${TailnetDatabaseHelper.COL_BINDING_UPSTREAM} = ?",
              arrayOf(id))
          db.setTransactionSuccessful()
        } finally {
          db.endTransaction()
        }
        refresh()
      }

  suspend fun setEnabled(id: String, enabled: Boolean) =
      withContext(Dispatchers.IO) {
        dbHelper.writableDatabase.update(
            TailnetDatabaseHelper.TABLE_UPSTREAMS,
            ContentValues().apply {
              put(TailnetDatabaseHelper.COL_ENABLED, if (enabled) 1 else 0)
              put(TailnetDatabaseHelper.COL_UPDATED_AT, System.currentTimeMillis())
            },
            "${TailnetDatabaseHelper.COL_UPSTREAM_ID} = ?",
            arrayOf(id))
        refresh()
      }

  fun getImmediate(id: String): Upstream? = _upstreams.value.find { it.id == id }

  fun getAllImmediate(): List<Upstream> = _upstreams.value

  /** The enabled upstreams, ordered so that every chain parent precedes its children. */
  fun registrationOrder(): List<Upstream> = orderByChain(_upstreams.value.filter { it.enabled })

  private fun values(upstream: Upstream) =
      ContentValues().apply {
        put(TailnetDatabaseHelper.COL_UPSTREAM_ID, upstream.id)
        put(TailnetDatabaseHelper.COL_UPSTREAM_KIND, upstream.kind.name)
        put(TailnetDatabaseHelper.COL_UPSTREAM_LABEL, upstream.label)
        put(TailnetDatabaseHelper.COL_UPSTREAM_VIA, upstream.via)
        put(TailnetDatabaseHelper.COL_UPSTREAM_SOURCE_TAILNET, upstream.sourceTailnetId)
        put(TailnetDatabaseHelper.COL_UPSTREAM_PEER_ADDR, upstream.peerAddr)
        put(TailnetDatabaseHelper.COL_ENABLED, if (upstream.enabled) 1 else 0)
        put(TailnetDatabaseHelper.COL_CREATED_AT, upstream.createdAt)
        put(TailnetDatabaseHelper.COL_UPDATED_AT, upstream.updatedAt)
      }

  companion object {
    private const val TAG = "UpstreamRepository"
  }
}
