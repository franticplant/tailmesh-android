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
 * Stores which upstream each app's traffic should take.
 *
 * A missing binding is not "no upstream" - it means the app is unbound and routed by whatever the
 * default is, which is today's behaviour. Only an explicit binding changes anything, so an app the
 * user has never touched is unaffected by this feature existing.
 */
class AppBindingRepository(context: Context) {
  private val dbHelper = TailnetDatabaseHelper(context)
  private val _bindings = MutableStateFlow<Map<String, String>>(emptyMap())

  /** Package name to upstream id, for every app the user has explicitly bound. */
  val bindings: StateFlow<Map<String, String>> = _bindings.asStateFlow()

  init {
    refresh()
  }

  private fun refresh() {
    val map = mutableMapOf<String, String>()
    dbHelper.readableDatabase
        .query(TailnetDatabaseHelper.TABLE_APP_BINDINGS, null, null, null, null, null, null)
        .use { cursor ->
          val packageIndex =
              cursor.getColumnIndexOrThrow(TailnetDatabaseHelper.COL_BINDING_PACKAGE)
          val upstreamIndex =
              cursor.getColumnIndexOrThrow(TailnetDatabaseHelper.COL_BINDING_UPSTREAM)
          while (cursor.moveToNext()) {
            map[cursor.getString(packageIndex)] = cursor.getString(upstreamIndex)
          }
        }
    _bindings.value = map
  }

  /** Binds an app to an upstream, replacing any existing binding for it. */
  suspend fun bind(packageName: String, upstreamId: String) =
      withContext(Dispatchers.IO) {
        val now = System.currentTimeMillis()
        dbHelper.writableDatabase.replaceOrThrow(
            TailnetDatabaseHelper.TABLE_APP_BINDINGS,
            null,
            ContentValues().apply {
              put(TailnetDatabaseHelper.COL_BINDING_PACKAGE, packageName)
              put(TailnetDatabaseHelper.COL_BINDING_UPSTREAM, upstreamId)
              put(TailnetDatabaseHelper.COL_CREATED_AT, now)
              put(TailnetDatabaseHelper.COL_UPDATED_AT, now)
            })
        refresh()
      }

  /** Removes an app's binding, returning it to the default route. */
  suspend fun unbind(packageName: String) =
      withContext(Dispatchers.IO) {
        dbHelper.writableDatabase.delete(
            TailnetDatabaseHelper.TABLE_APP_BINDINGS,
            "${TailnetDatabaseHelper.COL_BINDING_PACKAGE} = ?",
            arrayOf(packageName))
        refresh()
      }

  fun getAllImmediate(): Map<String, String> = _bindings.value
}
