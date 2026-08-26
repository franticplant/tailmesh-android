package com.tailscale.ipn.multiproxy.db

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

class TailnetDatabaseHelper(context: Context) : SQLiteOpenHelper(context, DATABASE_NAME, null, DATABASE_VERSION) {
    companion object {
        const val DATABASE_NAME = "multiproxy_profiles.db"
        const val DATABASE_VERSION = 2
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
    }
}
