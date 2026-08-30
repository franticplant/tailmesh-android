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
 * Stores which upstream each app's traffic - and, optionally, its DNS lookups - should take.
 *
 * A missing binding is not "no upstream" - it means the app is unbound and routed by whatever the
 * default is, which is today's behaviour. Only an explicit binding changes anything, so an app the
 * user has never touched is unaffected by this feature existing.
 */
class AppBindingRepository(context: Context) {
  private val dbHelper = TailnetDatabaseHelper(context)
  private val _bindings = MutableStateFlow<Map<String, AppBinding>>(emptyMap())

  /** Package name to its full binding, for every app the user has explicitly bound. */
  val bindings: StateFlow<Map<String, AppBinding>> = _bindings.asStateFlow()

  init {
    refresh()
  }

  private fun refresh() {
    val map = mutableMapOf<String, AppBinding>()
    dbHelper.readableDatabase
        .query(TailnetDatabaseHelper.TABLE_APP_BINDINGS, null, null, null, null, null, null)
        .use { cursor ->
          val packageIndex = cursor.getColumnIndexOrThrow(TailnetDatabaseHelper.COL_BINDING_PACKAGE)
          val upstreamIndex =
              cursor.getColumnIndexOrThrow(TailnetDatabaseHelper.COL_BINDING_UPSTREAM)
          val dnsUpstreamIndex =
              cursor.getColumnIndexOrThrow(TailnetDatabaseHelper.COL_BINDING_DNS_UPSTREAM)
          val tunnelLanIndex =
              cursor.getColumnIndexOrThrow(TailnetDatabaseHelper.COL_BINDING_TUNNEL_LAN)
          val createdIndex = cursor.getColumnIndexOrThrow(TailnetDatabaseHelper.COL_CREATED_AT)
          val updatedIndex = cursor.getColumnIndexOrThrow(TailnetDatabaseHelper.COL_UPDATED_AT)
          while (cursor.moveToNext()) {
            val packageName = cursor.getString(packageIndex)
            map[packageName] =
                AppBinding(
                    packageName = packageName,
                    upstreamId = cursor.getString(upstreamIndex),
                    dnsUpstreamId = cursor.getString(dnsUpstreamIndex),
                    tunnelLan = cursor.getInt(tunnelLanIndex) == 1,
                    createdAt = cursor.getLong(createdIndex),
                    updatedAt = cursor.getLong(updatedIndex),
                )
          }
        }
    _bindings.value = map
  }

  /**
   * Writes one column of a package's binding row, preserving whatever else is already there (or
   * defaulting a new row's other column to empty). Both [bind] and [setDNSUpstream] go through this
   * so that setting one never silently clears the other - a plain column-keyed INSERT OR REPLACE
   * would otherwise wipe out a DNS override every time the data route changes.
   *
   * The "existing" read happens from the database itself, inside the same transaction as the
   * write - not from the in-memory [_bindings] snapshot - so that two calls for the same package
   * racing each other (bind() and setDNSUpstream() fired in quick succession) can't both read the
   * same stale snapshot and have the second write clobber the first's change; SQLite's own
   * transaction serialization is what actually closes that window.
   */
  private suspend fun upsert(packageName: String, apply: ContentValues.() -> Unit) =
      withContext(Dispatchers.IO) {
        val db = dbHelper.writableDatabase
        val now = System.currentTimeMillis()
        db.beginTransaction()
        try {
          val existing =
              db.query(
                      TailnetDatabaseHelper.TABLE_APP_BINDINGS,
                      null,
                      "${TailnetDatabaseHelper.COL_BINDING_PACKAGE} = ?",
                      arrayOf(packageName),
                      null,
                      null,
                      null)
                  .use { cursor ->
                    if (!cursor.moveToFirst()) null
                    else
                        AppBinding(
                            packageName = packageName,
                            upstreamId =
                                cursor.getString(
                                    cursor.getColumnIndexOrThrow(
                                        TailnetDatabaseHelper.COL_BINDING_UPSTREAM)),
                            dnsUpstreamId =
                                cursor.getString(
                                    cursor.getColumnIndexOrThrow(
                                        TailnetDatabaseHelper.COL_BINDING_DNS_UPSTREAM)),
                            tunnelLan =
                                cursor.getInt(
                                    cursor.getColumnIndexOrThrow(
                                        TailnetDatabaseHelper.COL_BINDING_TUNNEL_LAN)) == 1,
                            createdAt =
                                cursor.getLong(
                                    cursor.getColumnIndexOrThrow(
                                        TailnetDatabaseHelper.COL_CREATED_AT)),
                        )
                  }
          val values =
              ContentValues().apply {
                put(TailnetDatabaseHelper.COL_BINDING_PACKAGE, packageName)
                put(TailnetDatabaseHelper.COL_BINDING_UPSTREAM, existing?.upstreamId ?: "")
                put(TailnetDatabaseHelper.COL_BINDING_DNS_UPSTREAM, existing?.dnsUpstreamId ?: "")
                put(
                    TailnetDatabaseHelper.COL_BINDING_TUNNEL_LAN,
                    if (existing?.tunnelLan == true) 1 else 0)
                put(TailnetDatabaseHelper.COL_CREATED_AT, existing?.createdAt ?: now)
                put(TailnetDatabaseHelper.COL_UPDATED_AT, now)
              }
          values.apply()
          db.replaceOrThrow(TailnetDatabaseHelper.TABLE_APP_BINDINGS, null, values)
          db.setTransactionSuccessful()
        } finally {
          db.endTransaction()
        }
        refresh()
      }

  /** Binds an app to an upstream, preserving any DNS override already set for it. */
  suspend fun bind(packageName: String, upstreamId: String) =
      upsert(packageName) { put(TailnetDatabaseHelper.COL_BINDING_UPSTREAM, upstreamId) }

  /**
   * Sets (or, with an empty id, clears) an app's DNS override, independent of its data route. Only
   * takes effect while the app also has a non-empty upstream binding - see
   * COL_BINDING_DNS_UPSTREAM's doc comment - but is stored regardless, so choosing a data route
   * later picks the override back up rather than requiring it to be re-entered.
   */
  suspend fun setDNSUpstream(packageName: String, dnsUpstreamId: String) =
      upsert(packageName) { put(TailnetDatabaseHelper.COL_BINDING_DNS_UPSTREAM, dnsUpstreamId) }

  /**
   * Sets whether this app's LAN-destined traffic should keep following its own upstream binding
   * even while the global "keep LAN traffic direct" setting is on. Only takes effect while the app
   * also has a non-empty upstream binding - see COL_BINDING_TUNNEL_LAN's doc comment - but is
   * stored regardless, same as [setDNSUpstream].
   */
  suspend fun setTunnelLAN(packageName: String, tunnelLan: Boolean) =
      upsert(packageName) {
        put(TailnetDatabaseHelper.COL_BINDING_TUNNEL_LAN, if (tunnelLan) 1 else 0)
      }

  /** Removes an app's binding entirely - both its data route and any DNS override. */
  suspend fun unbind(packageName: String) =
      withContext(Dispatchers.IO) {
        dbHelper.writableDatabase.delete(
            TailnetDatabaseHelper.TABLE_APP_BINDINGS,
            "${TailnetDatabaseHelper.COL_BINDING_PACKAGE} = ?",
            arrayOf(packageName))
        refresh()
      }

  fun getAllImmediate(): Map<String, AppBinding> = _bindings.value
}
