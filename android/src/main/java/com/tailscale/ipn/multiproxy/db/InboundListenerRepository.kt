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
 * Stores the user's configured tailnet-facing inbound listeners.
 *
 * Mirrors [SOCKS5ListenerRepository]: a StateFlow the UI observes, refreshed after every write,
 * reads served from memory. The engine holds none of this across restarts - this repository is the
 * durable source of truth that [com.tailscale.ipn.multiproxy.UpstreamPolicyApplier] reconciles into
 * a running engine.
 */
class InboundListenerRepository(context: Context) {
  private val dbHelper = TailnetDatabaseHelper(context)
  private val _listeners = MutableStateFlow<List<InboundListenerRecord>>(emptyList())
  val listeners: StateFlow<List<InboundListenerRecord>> = _listeners.asStateFlow()

  init {
    refresh()
  }

  private fun refresh() {
    val list = mutableListOf<InboundListenerRecord>()
    dbHelper.readableDatabase
        .query(
            TailnetDatabaseHelper.TABLE_INBOUND_LISTENERS,
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
                InboundListenerRecord(
                    id = string(TailnetDatabaseHelper.COL_LISTENER_ID),
                    upstream = string(TailnetDatabaseHelper.COL_IB_UPSTREAM),
                    listenPort = int(TailnetDatabaseHelper.COL_IB_LISTEN_PORT),
                    localTarget = string(TailnetDatabaseHelper.COL_IB_LOCAL_TARGET),
                    proxyProtocol = int(TailnetDatabaseHelper.COL_IB_PROXY_PROTOCOL) == 1,
                    enabled = int(TailnetDatabaseHelper.COL_ENABLED) == 1,
                    createdAt = long(TailnetDatabaseHelper.COL_CREATED_AT),
                    updatedAt = long(TailnetDatabaseHelper.COL_UPDATED_AT),
                )
          }
        }
    _listeners.value = list
  }

  /**
   * Inserts a new listener, or edits an existing one - preserving its `enabled` state and original
   * `createdAt` across the edit, the same "read the existing row inside the write's own
   * transaction" pattern as [SOCKS5ListenerRepository.saveConfig].
   */
  suspend fun saveConfig(
      id: String,
      upstream: String,
      listenPort: Int,
      localTarget: String,
      proxyProtocol: Boolean,
  ) =
      withContext(Dispatchers.IO) {
        val db = dbHelper.writableDatabase
        val now = System.currentTimeMillis()
        db.beginTransaction()
        try {
          val existing =
              db.query(
                      TailnetDatabaseHelper.TABLE_INBOUND_LISTENERS,
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
              InboundListenerRecord(
                  id = id,
                  upstream = upstream,
                  listenPort = listenPort,
                  localTarget = localTarget,
                  proxyProtocol = proxyProtocol,
                  enabled = existing?.first ?: true,
                  createdAt = existing?.second ?: now,
                  updatedAt = now,
              )
          db.replaceOrThrow(TailnetDatabaseHelper.TABLE_INBOUND_LISTENERS, null, values(record))
          db.setTransactionSuccessful()
        } finally {
          db.endTransaction()
        }
        refresh()
      }

  suspend fun setEnabled(id: String, enabled: Boolean) =
      withContext(Dispatchers.IO) {
        dbHelper.writableDatabase.update(
            TailnetDatabaseHelper.TABLE_INBOUND_LISTENERS,
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
            TailnetDatabaseHelper.TABLE_INBOUND_LISTENERS,
            "${TailnetDatabaseHelper.COL_LISTENER_ID} = ?",
            arrayOf(id))
        refresh()
      }

  fun getImmediate(id: String): InboundListenerRecord? = _listeners.value.find { it.id == id }

  fun getAllImmediate(): List<InboundListenerRecord> = _listeners.value

  private fun values(record: InboundListenerRecord) =
      ContentValues().apply {
        put(TailnetDatabaseHelper.COL_LISTENER_ID, record.id)
        put(TailnetDatabaseHelper.COL_IB_UPSTREAM, record.upstream)
        put(TailnetDatabaseHelper.COL_IB_LISTEN_PORT, record.listenPort)
        put(TailnetDatabaseHelper.COL_IB_LOCAL_TARGET, record.localTarget)
        put(TailnetDatabaseHelper.COL_IB_PROXY_PROTOCOL, if (record.proxyProtocol) 1 else 0)
        put(TailnetDatabaseHelper.COL_ENABLED, if (record.enabled) 1 else 0)
        put(TailnetDatabaseHelper.COL_CREATED_AT, record.createdAt)
        put(TailnetDatabaseHelper.COL_UPDATED_AT, record.updatedAt)
      }
}
