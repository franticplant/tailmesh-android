package com.tailscale.ipn.multiproxy.db

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

class TailnetDatabaseHelper(context: Context) : SQLiteOpenHelper(context, DATABASE_NAME, null, DATABASE_VERSION) {
    companion object {
        const val DATABASE_NAME = "multiproxy_profiles.db"
        const val DATABASE_VERSION = 4
        const val TABLE_PROFILES = "profiles"
        const val COL_ID = "id"
        const val COL_DISPLAY_NAME = "display_name"
        const val COL_ENABLED = "enabled"
        const val COL_PROV_STATE = "provisioning_state"
        const val COL_CREATED_AT = "created_at"
        const val COL_UPDATED_AT = "updated_at"
        const val COL_SOURCE_PROFILE_ID = "source_profile_id"
        const val COL_OWNER = "owner"
        const val COL_STANDARD_SELECTED = "standard_selected"
        const val COL_MIGRATION_VERSION = "migration_version"

        // Non-Tailnet upstreams: SOCKS5 proxies and WireGuard tunnels.
        //
        // Only the non-secret parts of an upstream live here. Its configuration -
        // which for WireGuard contains a private key, and for SOCKS5 may contain a
        // password - is held in EncryptedSharedPreferences by UpstreamSecretStore,
        // so nothing sensitive is written to this database.
        const val TABLE_UPSTREAMS = "upstreams"
        const val COL_UPSTREAM_ID = "id"
        const val COL_UPSTREAM_KIND = "kind"
        const val COL_UPSTREAM_LABEL = "label"
        const val COL_UPSTREAM_VIA = "via"
        // Only set for kind=EXITNODE: which existing tailnet the peer was picked
        // from (informational - the exit-node upstream has its own dedicated node
        // identity by then, see upstream_exitnode.go) and that peer's Tailscale IP.
        const val COL_UPSTREAM_SOURCE_TAILNET = "source_tailnet_id"
        const val COL_UPSTREAM_PEER_ADDR = "peer_addr"

        // Per-app upstream selection, keyed by package name rather than UID
        // because a UID is only stable until the app is reinstalled, whereas the
        // user's choice is about the app.
        const val TABLE_APP_BINDINGS = "app_bindings"
        const val COL_BINDING_PACKAGE = "package_name"
        const val COL_BINDING_UPSTREAM = "upstream_id"

        private const val CREATE_UPSTREAMS = """
            CREATE TABLE IF NOT EXISTS $TABLE_UPSTREAMS (
                $COL_UPSTREAM_ID TEXT PRIMARY KEY,
                $COL_UPSTREAM_KIND TEXT NOT NULL,
                $COL_UPSTREAM_LABEL TEXT NOT NULL,
                $COL_UPSTREAM_VIA TEXT NOT NULL DEFAULT '',
                $COL_UPSTREAM_SOURCE_TAILNET TEXT NOT NULL DEFAULT '',
                $COL_UPSTREAM_PEER_ADDR TEXT NOT NULL DEFAULT '',
                $COL_ENABLED INTEGER NOT NULL DEFAULT 1,
                $COL_CREATED_AT INTEGER NOT NULL,
                $COL_UPDATED_AT INTEGER NOT NULL
            )
        """

        private const val CREATE_APP_BINDINGS = """
            CREATE TABLE IF NOT EXISTS $TABLE_APP_BINDINGS (
                $COL_BINDING_PACKAGE TEXT PRIMARY KEY,
                $COL_BINDING_UPSTREAM TEXT NOT NULL,
                $COL_CREATED_AT INTEGER NOT NULL,
                $COL_UPDATED_AT INTEGER NOT NULL
            )
        """
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("""
            CREATE TABLE $TABLE_PROFILES (
                $COL_ID TEXT PRIMARY KEY,
                $COL_DISPLAY_NAME TEXT NOT NULL,
                $COL_ENABLED INTEGER NOT NULL,
                $COL_PROV_STATE TEXT NOT NULL,
                $COL_CREATED_AT INTEGER NOT NULL,
                $COL_UPDATED_AT INTEGER NOT NULL,
                $COL_SOURCE_PROFILE_ID TEXT UNIQUE,
                $COL_OWNER TEXT NOT NULL DEFAULT 'IDLE',
                $COL_STANDARD_SELECTED INTEGER NOT NULL DEFAULT 0,
                $COL_MIGRATION_VERSION INTEGER NOT NULL DEFAULT 1
            )
        """.trimIndent())
        db.execSQL(CREATE_UPSTREAMS.trimIndent())
        db.execSQL(CREATE_APP_BINDINGS.trimIndent())
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        if (oldVersion < 2) {
            db.beginTransaction()
            try {
                db.execSQL("ALTER TABLE $TABLE_PROFILES ADD COLUMN $COL_SOURCE_PROFILE_ID TEXT")
                db.execSQL("ALTER TABLE $TABLE_PROFILES ADD COLUMN $COL_OWNER TEXT NOT NULL DEFAULT 'IDLE'")
                db.execSQL("ALTER TABLE $TABLE_PROFILES ADD COLUMN $COL_STANDARD_SELECTED INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE $TABLE_PROFILES ADD COLUMN $COL_MIGRATION_VERSION INTEGER NOT NULL DEFAULT 1")
                db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS profiles_source_profile_id ON $TABLE_PROFILES($COL_SOURCE_PROFILE_ID)")
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
        }
        if (oldVersion < 3) {
            // Both tables are new rather than altered, so this is the whole
            // migration: no data to move, and IF NOT EXISTS keeps it idempotent.
            db.beginTransaction()
            try {
                db.execSQL(CREATE_UPSTREAMS.trimIndent())
                db.execSQL(CREATE_APP_BINDINGS.trimIndent())
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
        }
        if (oldVersion < 4) {
            // Adds the two columns an EXITNODE-kind upstream needs; every existing
            // row (SOCKS5, WireGuard) gets the column with its '' default, which
            // reads as "not applicable" rather than requiring a nullable type.
            db.beginTransaction()
            try {
                db.execSQL("ALTER TABLE $TABLE_UPSTREAMS ADD COLUMN $COL_UPSTREAM_SOURCE_TAILNET TEXT NOT NULL DEFAULT ''")
                db.execSQL("ALTER TABLE $TABLE_UPSTREAMS ADD COLUMN $COL_UPSTREAM_PEER_ADDR TEXT NOT NULL DEFAULT ''")
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
        }
    }
}
