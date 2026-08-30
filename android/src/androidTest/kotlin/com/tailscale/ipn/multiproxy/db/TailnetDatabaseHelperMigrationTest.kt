// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.multiproxy.db

import android.database.sqlite.SQLiteDatabase
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * TailnetDatabaseHelper implements AutoCloseable, not Closeable, so Kotlin's [use] extension (which
 * requires Closeable) does not apply to it directly - this wraps it in an equivalent try/finally
 * instead.
 */
private inline fun <R> withHelper(
    context: android.content.Context,
    block: (TailnetDatabaseHelper) -> R
): R {
  val helper = TailnetDatabaseHelper(context)
  try {
    return block(helper)
  } finally {
    helper.close()
  }
}

/**
 * Runs [TailnetDatabaseHelper]'s real onCreate/onUpgrade against a real on-device SQLite database,
 * starting from every historical schema version this app has ever shipped. These are regression
 * tests for a real bug class hit twice in this codebase's history: an onUpgrade branch that shares
 * a CREATE TABLE constant with the current schema, so an older device jumping straight to the
 * latest version runs both the old branch and a newer `ALTER TABLE ADD COLUMN` branch in the same
 * call and fails with "duplicate column name" - see CREATE_UPSTREAMS_V3 and CREATE_APP_BINDINGS_V3
 * in TailnetDatabaseHelper.kt.
 */
@RunWith(AndroidJUnit4::class)
class TailnetDatabaseHelperMigrationTest {
  private val context = InstrumentationRegistry.getInstrumentation().targetContext

  @Before
  @After
  fun cleanDatabase() {
    context.deleteDatabase(TailnetDatabaseHelper.DATABASE_NAME)
  }

  private fun dbPath() = context.getDatabasePath(TailnetDatabaseHelper.DATABASE_NAME).path

  /** Creates a raw database at [version] with exactly the shape that version originally shipped. */
  private fun createRawDatabaseAtVersion(version: Int) {
    val db = SQLiteDatabase.openOrCreateDatabase(dbPath(), null)
    db.use {
      it.execSQL(
          """
            CREATE TABLE ${TailnetDatabaseHelper.TABLE_PROFILES} (
                ${TailnetDatabaseHelper.COL_ID} TEXT PRIMARY KEY,
                ${TailnetDatabaseHelper.COL_DISPLAY_NAME} TEXT NOT NULL,
                ${TailnetDatabaseHelper.COL_ENABLED} INTEGER NOT NULL,
                ${TailnetDatabaseHelper.COL_PROV_STATE} TEXT NOT NULL,
                ${TailnetDatabaseHelper.COL_CREATED_AT} INTEGER NOT NULL,
                ${TailnetDatabaseHelper.COL_UPDATED_AT} INTEGER NOT NULL
            )
          """
              .trimIndent())
      if (version >= 2) {
        // A real device at version >= 2 always has these columns - they are the whole v1->v2
        // migration - so a fixture claiming to start at version >= 2 must include them too,
        // or it describes a state no real device could ever be in.
        it.execSQL(
            "ALTER TABLE ${TailnetDatabaseHelper.TABLE_PROFILES} ADD COLUMN " +
                "${TailnetDatabaseHelper.COL_SOURCE_PROFILE_ID} TEXT")
        it.execSQL(
            "ALTER TABLE ${TailnetDatabaseHelper.TABLE_PROFILES} ADD COLUMN " +
                "${TailnetDatabaseHelper.COL_OWNER} TEXT NOT NULL DEFAULT 'IDLE'")
        it.execSQL(
            "ALTER TABLE ${TailnetDatabaseHelper.TABLE_PROFILES} ADD COLUMN " +
                "${TailnetDatabaseHelper.COL_STANDARD_SELECTED} INTEGER NOT NULL DEFAULT 0")
        it.execSQL(
            "ALTER TABLE ${TailnetDatabaseHelper.TABLE_PROFILES} ADD COLUMN " +
                "${TailnetDatabaseHelper.COL_MIGRATION_VERSION} INTEGER NOT NULL DEFAULT 1")
      }
      if (version >= 3) {
        it.execSQL(
            """
              CREATE TABLE ${TailnetDatabaseHelper.TABLE_UPSTREAMS} (
                  ${TailnetDatabaseHelper.COL_UPSTREAM_ID} TEXT PRIMARY KEY,
                  ${TailnetDatabaseHelper.COL_UPSTREAM_KIND} TEXT NOT NULL,
                  ${TailnetDatabaseHelper.COL_UPSTREAM_LABEL} TEXT NOT NULL,
                  ${TailnetDatabaseHelper.COL_UPSTREAM_VIA} TEXT NOT NULL DEFAULT '',
                  ${TailnetDatabaseHelper.COL_ENABLED} INTEGER NOT NULL DEFAULT 1,
                  ${TailnetDatabaseHelper.COL_CREATED_AT} INTEGER NOT NULL,
                  ${TailnetDatabaseHelper.COL_UPDATED_AT} INTEGER NOT NULL
              )
            """
                .trimIndent())
        it.execSQL(
            """
              CREATE TABLE ${TailnetDatabaseHelper.TABLE_APP_BINDINGS} (
                  ${TailnetDatabaseHelper.COL_BINDING_PACKAGE} TEXT PRIMARY KEY,
                  ${TailnetDatabaseHelper.COL_BINDING_UPSTREAM} TEXT NOT NULL,
                  ${TailnetDatabaseHelper.COL_CREATED_AT} INTEGER NOT NULL,
                  ${TailnetDatabaseHelper.COL_UPDATED_AT} INTEGER NOT NULL
              )
            """
                .trimIndent())
      }
      if (version >= 4) {
        it.execSQL(
            "ALTER TABLE ${TailnetDatabaseHelper.TABLE_UPSTREAMS} ADD COLUMN " +
                "${TailnetDatabaseHelper.COL_UPSTREAM_SOURCE_TAILNET} TEXT NOT NULL DEFAULT ''")
        it.execSQL(
            "ALTER TABLE ${TailnetDatabaseHelper.TABLE_UPSTREAMS} ADD COLUMN " +
                "${TailnetDatabaseHelper.COL_UPSTREAM_PEER_ADDR} TEXT NOT NULL DEFAULT ''")
      }
      if (version >= 5) {
        it.execSQL(
            "ALTER TABLE ${TailnetDatabaseHelper.TABLE_APP_BINDINGS} ADD COLUMN " +
                "${TailnetDatabaseHelper.COL_BINDING_DNS_UPSTREAM} TEXT NOT NULL DEFAULT ''")
      }
      it.version = version
    }
  }

  private fun columnNames(db: SQLiteDatabase, table: String): Set<String> {
    val names = mutableSetOf<String>()
    db.rawQuery("PRAGMA table_info($table)", null).use { cursor ->
      val nameIndex = cursor.getColumnIndexOrThrow("name")
      while (cursor.moveToNext()) names.add(cursor.getString(nameIndex))
    }
    return names
  }

  private fun assertFinalSchema(db: SQLiteDatabase) {
    assertEquals(TailnetDatabaseHelper.DATABASE_VERSION, db.version)
    assertTrue(
        columnNames(db, TailnetDatabaseHelper.TABLE_UPSTREAMS)
            .containsAll(
                setOf(
                    TailnetDatabaseHelper.COL_UPSTREAM_SOURCE_TAILNET,
                    TailnetDatabaseHelper.COL_UPSTREAM_PEER_ADDR)))
    assertTrue(
        columnNames(db, TailnetDatabaseHelper.TABLE_APP_BINDINGS)
            .containsAll(
                setOf(
                    TailnetDatabaseHelper.COL_BINDING_DNS_UPSTREAM,
                    TailnetDatabaseHelper.COL_BINDING_TUNNEL_LAN)))
    assertTrue(
        columnNames(db, TailnetDatabaseHelper.TABLE_PROFILES)
            .containsAll(
                setOf(
                    TailnetDatabaseHelper.COL_SOURCE_PROFILE_ID,
                    TailnetDatabaseHelper.COL_OWNER,
                    TailnetDatabaseHelper.COL_STANDARD_SELECTED,
                    TailnetDatabaseHelper.COL_MIGRATION_VERSION)))
  }

  @Test
  fun freshInstall_createsCurrentSchemaDirectly() {
    withHelper(context) { helper -> assertFinalSchema(helper.writableDatabase) }
  }

  @Test
  fun upgradeFromVersion1_appliesEveryMigrationBranchInOneCall() {
    createRawDatabaseAtVersion(1)
    withHelper(context) { helper -> assertFinalSchema(helper.writableDatabase) }
  }

  @Test
  fun upgradeFromVersion2_appliesEveryMigrationBranchInOneCall() {
    // v2 has the profiles-table columns v1->v2 adds, but not yet the upstreams/app_bindings
    // tables (those arrive at v3) - the same starting shape createRawDatabaseAtVersion(1) plus
    // the migration this test is not itself trying to isolate, so drive it through the real
    // v1 raw DB and version stamp instead of hand-duplicating the v2 shape.
    createRawDatabaseAtVersion(1)
    SQLiteDatabase.openOrCreateDatabase(dbPath(), null).use { db ->
      db.execSQL(
          "ALTER TABLE ${TailnetDatabaseHelper.TABLE_PROFILES} ADD COLUMN " +
              "${TailnetDatabaseHelper.COL_SOURCE_PROFILE_ID} TEXT")
      db.execSQL(
          "ALTER TABLE ${TailnetDatabaseHelper.TABLE_PROFILES} ADD COLUMN " +
              "${TailnetDatabaseHelper.COL_OWNER} TEXT NOT NULL DEFAULT 'IDLE'")
      db.execSQL(
          "ALTER TABLE ${TailnetDatabaseHelper.TABLE_PROFILES} ADD COLUMN " +
              "${TailnetDatabaseHelper.COL_STANDARD_SELECTED} INTEGER NOT NULL DEFAULT 0")
      db.execSQL(
          "ALTER TABLE ${TailnetDatabaseHelper.TABLE_PROFILES} ADD COLUMN " +
              "${TailnetDatabaseHelper.COL_MIGRATION_VERSION} INTEGER NOT NULL DEFAULT 1")
      db.version = 2
    }
    withHelper(context) { helper -> assertFinalSchema(helper.writableDatabase) }
  }

  /**
   * The exact shape that caused a real "duplicate column name" crash before it was fixed (commit
   * dd185aa): a device at v3 (upstreams/app_bindings exist, but without the v4/v5 columns) jumping
   * straight to the current version in one onUpgrade call.
   */
  @Test
  fun upgradeFromVersion3_appliesV4AndV5BranchesInOneCallWithoutDuplicateColumnError() {
    createRawDatabaseAtVersion(3)
    withHelper(context) { helper -> assertFinalSchema(helper.writableDatabase) }
  }

  @Test
  fun upgradeFromVersion4_appliesV5AndV6BranchesInOneCall() {
    createRawDatabaseAtVersion(4)
    withHelper(context) { helper -> assertFinalSchema(helper.writableDatabase) }
  }

  @Test
  fun upgradeFromVersion5_appliesOnlyTheV6Branch() {
    createRawDatabaseAtVersion(5)
    withHelper(context) { helper -> assertFinalSchema(helper.writableDatabase) }
  }

  @Test
  fun upgradeFromVersion3_preservesExistingRows() {
    createRawDatabaseAtVersion(3)
    SQLiteDatabase.openOrCreateDatabase(dbPath(), null).use { db ->
      db.execSQL(
          "INSERT INTO ${TailnetDatabaseHelper.TABLE_UPSTREAMS} " +
              "(${TailnetDatabaseHelper.COL_UPSTREAM_ID}, ${TailnetDatabaseHelper.COL_UPSTREAM_KIND}, " +
              "${TailnetDatabaseHelper.COL_UPSTREAM_LABEL}, ${TailnetDatabaseHelper.COL_CREATED_AT}, " +
              "${TailnetDatabaseHelper.COL_UPDATED_AT}) VALUES ('u1', 'SOCKS5', 'test', 1000, 1000)")
      db.execSQL(
          "INSERT INTO ${TailnetDatabaseHelper.TABLE_APP_BINDINGS} " +
              "(${TailnetDatabaseHelper.COL_BINDING_PACKAGE}, ${TailnetDatabaseHelper.COL_BINDING_UPSTREAM}, " +
              "${TailnetDatabaseHelper.COL_CREATED_AT}, ${TailnetDatabaseHelper.COL_UPDATED_AT}) " +
              "VALUES ('com.example.app', 'u1', 1000, 1000)")
    }
    withHelper(context) { helper ->
      val db = helper.writableDatabase
      db.rawQuery(
              "SELECT ${TailnetDatabaseHelper.COL_UPSTREAM_SOURCE_TAILNET}, " +
                  "${TailnetDatabaseHelper.COL_UPSTREAM_PEER_ADDR} FROM " +
                  "${TailnetDatabaseHelper.TABLE_UPSTREAMS} WHERE " +
                  "${TailnetDatabaseHelper.COL_UPSTREAM_ID} = 'u1'",
              null)
          .use { cursor ->
            assertTrue(cursor.moveToFirst())
            assertEquals("", cursor.getString(0))
            assertEquals("", cursor.getString(1))
          }
      db.rawQuery(
              "SELECT ${TailnetDatabaseHelper.COL_BINDING_DNS_UPSTREAM}, " +
                  "${TailnetDatabaseHelper.COL_BINDING_TUNNEL_LAN} FROM " +
                  "${TailnetDatabaseHelper.TABLE_APP_BINDINGS} WHERE " +
                  "${TailnetDatabaseHelper.COL_BINDING_PACKAGE} = 'com.example.app'",
              null)
          .use { cursor ->
            assertTrue(cursor.moveToFirst())
            assertEquals("", cursor.getString(0))
            assertEquals(0, cursor.getInt(1))
          }
    }
  }
}
