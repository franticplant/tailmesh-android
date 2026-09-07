// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.multiproxy.db

import android.content.ContentValues
import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext

/**
 * Stores the user's configured inbound SOCKS5 listeners.
 *
 * Mirrors [UpstreamRepository]: a StateFlow the UI observes, refreshed after every write, reads
 * served from memory. The engine holds none of this across restarts (or a listener's own
 * add/remove-in-response-to-upstream-toggle cycle, see UpstreamPolicyApplier) - this repository is
 * the durable source of truth that gets reconciled into a running engine, the same role
 * [UpstreamRepository] plays for upstreams.
 */
class SOCKS5ListenerRepository(context: Context) {
  private val dbHelper = TailnetDatabaseHelper(context)
  private val _listeners = MutableStateFlow<List<SOCKS5ListenerRecord>>(emptyList())
  val listeners: StateFlow<List<SOCKS5ListenerRecord>> = _listeners.asStateFlow()

  init {
    refresh()
  }

  private fun refresh() {
    val list = mutableListOf<SOCKS5ListenerRecord>()
    dbHelper.readableDatabase
        .query(
            TailnetDatabaseHelper.TABLE_SOCKS5_LISTENERS,
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
            fun int(column: String) = cursor.getInt(cursor.getColumnIndexOrThrow(column))

            list +=
                SOCKS5ListenerRecord(
                    id = string(TailnetDatabaseHelper.COL_LISTENER_ID),
                    bindAddr = string(TailnetDatabaseHelper.COL_LISTENER_BIND_ADDR),
                    port = int(TailnetDatabaseHelper.COL_LISTENER_PORT),
                    upstream = string(TailnetDatabaseHelper.COL_LISTENER_UPSTREAM),
                    hasAuth = int(TailnetDatabaseHelper.COL_LISTENER_HAS_AUTH) == 1,
                    enabled = int(TailnetDatabaseHelper.COL_ENABLED) == 1,
                    createdAt = long(TailnetDatabaseHelper.COL_CREATED_AT),
                    updatedAt = long(TailnetDatabaseHelper.COL_UPDATED_AT),
                )
          }
        }
    _listeners.value = list
  }

  /**
   * Inserts a new listener, or edits an existing one's bind address/port/upstream/auth presence -
   * preserving its `enabled` state and original `createdAt` across the edit, the same "read the
   * existing row inside the write's own transaction" pattern as [UpstreamRepository.saveConfig],
   * and for the same reason: a concurrent [setEnabled] call for the same id must not be reverted by
   * a stale in-memory snapshot.
   */
  suspend fun saveConfig(
      id: String,
      bindAddr: String,
      port: Int,
      upstream: String,
      hasAuth: Boolean,
  ) =
      withContext(Dispatchers.IO) {
        val db = dbHelper.writableDatabase
        val now = System.currentTimeMillis()
        db.beginTransaction()
        try {
          val existing =
              db.query(
                      TailnetDatabaseHelper.TABLE_SOCKS5_LISTENERS,
                      arrayOf(
                          TailnetDatabaseHelper.COL_ENABLED, TailnetDatabaseHelper.COL_CREATED_AT),
                      "${TailnetDatabaseHelper.COL_LISTENER_ID} = ?",
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
          val record =
              SOCKS5ListenerRecord(
                  id = id,
                  bindAddr = bindAddr,
                  port = port,
                  upstream = upstream,
                  hasAuth = hasAuth,
                  enabled = existing?.first ?: true,
                  createdAt = existing?.second ?: now,
                  updatedAt = now,
              )
          db.replaceOrThrow(TailnetDatabaseHelper.TABLE_SOCKS5_LISTENERS, null, values(record))
          db.setTransactionSuccessful()
        } finally {
          db.endTransaction()
        }
        refresh()
      }

  suspend fun setEnabled(id: String, enabled: Boolean) =
      withContext(Dispatchers.IO) {
        dbHelper.writableDatabase.update(
            TailnetDatabaseHelper.TABLE_SOCKS5_LISTENERS,
            ContentValues().apply {
              put(TailnetDatabaseHelper.COL_ENABLED, if (enabled) 1 else 0)
              put(TailnetDatabaseHelper.COL_UPDATED_AT, System.currentTimeMillis())
            },
            "${TailnetDatabaseHelper.COL_LISTENER_ID} = ?",
            arrayOf(id))
        refresh()
      }

  suspend fun delete(id: String) =
      withContext(Dispatchers.IO) {
        dbHelper.writableDatabase.delete(
            TailnetDatabaseHelper.TABLE_SOCKS5_LISTENERS,
            "${TailnetDatabaseHelper.COL_LISTENER_ID} = ?",
            arrayOf(id))
        refresh()
      }

  fun getImmediate(id: String): SOCKS5ListenerRecord? = _listeners.value.find { it.id == id }

  fun getAllImmediate(): List<SOCKS5ListenerRecord> = _listeners.value

  private fun values(record: SOCKS5ListenerRecord) =
      ContentValues().apply {
        put(TailnetDatabaseHelper.COL_LISTENER_ID, record.id)
        put(TailnetDatabaseHelper.COL_LISTENER_BIND_ADDR, record.bindAddr)
        put(TailnetDatabaseHelper.COL_LISTENER_PORT, record.port)
        put(TailnetDatabaseHelper.COL_LISTENER_UPSTREAM, record.upstream)
        put(TailnetDatabaseHelper.COL_LISTENER_HAS_AUTH, if (record.hasAuth) 1 else 0)
        put(TailnetDatabaseHelper.COL_ENABLED, if (record.enabled) 1 else 0)
        put(TailnetDatabaseHelper.COL_CREATED_AT, record.createdAt)
        put(TailnetDatabaseHelper.COL_UPDATED_AT, record.updatedAt)
      }

  companion object {
    private const val TAG = "SOCKS5ListenerRepository"
  }
}
