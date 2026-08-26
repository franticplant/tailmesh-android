package com.tailscale.ipn.multiproxy.db

import android.content.ContentValues
import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.util.UUID

class ProfileRepository(context: Context) {
    private val dbHelper = TailnetDatabaseHelper(context)
    private val _profiles = MutableStateFlow<List<TailnetProfile>>(emptyList())
    val profiles: StateFlow<List<TailnetProfile>> = _profiles.asStateFlow()

    init { refreshProfiles() }

    private fun refreshProfiles() {
        val list = mutableListOf<TailnetProfile>()
        dbHelper.readableDatabase.query(
            TailnetDatabaseHelper.TABLE_PROFILES, null, null, null, null, null,
            "${TailnetDatabaseHelper.COL_CREATED_AT} ASC",
        ).use { cursor ->
            while (cursor.moveToNext()) {
                fun string(column: String) = cursor.getString(cursor.getColumnIndexOrThrow(column))
                fun int(column: String) = cursor.getInt(cursor.getColumnIndexOrThrow(column))
                val sourceIndex = cursor.getColumnIndexOrThrow(TailnetDatabaseHelper.COL_SOURCE_PROFILE_ID)
                list += TailnetProfile(
                    id = string(TailnetDatabaseHelper.COL_ID),
                    displayName = string(TailnetDatabaseHelper.COL_DISPLAY_NAME),
                    enabled = int(TailnetDatabaseHelper.COL_ENABLED) == 1,
                    provisioningState = ProvisioningState.valueOf(string(TailnetDatabaseHelper.COL_PROV_STATE)),
                    createdAt = cursor.getLong(cursor.getColumnIndexOrThrow(TailnetDatabaseHelper.COL_CREATED_AT)),
                    updatedAt = cursor.getLong(cursor.getColumnIndexOrThrow(TailnetDatabaseHelper.COL_UPDATED_AT)),
                    sourceProfileId = if (cursor.isNull(sourceIndex)) null else cursor.getString(sourceIndex),
                    owner = UpstreamOwner.valueOf(string(TailnetDatabaseHelper.COL_OWNER)),
                    standardSelected = int(TailnetDatabaseHelper.COL_STANDARD_SELECTED) == 1,
                    migrationVersion = int(TailnetDatabaseHelper.COL_MIGRATION_VERSION),
                )
            }
        }
        _profiles.value = list
    }

    suspend fun createProfile(displayName: String): TailnetProfile = create(
        TailnetProfile(
            id = UUID.randomUUID().toString(), displayName = displayName, enabled = false,
            provisioningState = ProvisioningState.UNPROVISIONED,
            createdAt = System.currentTimeMillis(), updatedAt = System.currentTimeMillis(),
        ),
    )

    suspend fun importRegularProfile(profileId: String, displayName: String): TailnetProfile = withContext(Dispatchers.IO) {
        _profiles.value.firstOrNull { it.sourceProfileId == profileId } ?: create(
            TailnetProfile(
                id = "regular-$profileId", displayName = displayName, enabled = false,
                provisioningState = ProvisioningState.READY,
                createdAt = System.currentTimeMillis(), updatedAt = System.currentTimeMillis(),
                sourceProfileId = profileId,
            ),
        )
    }

    private suspend fun create(profile: TailnetProfile): TailnetProfile = withContext(Dispatchers.IO) {
        dbHelper.writableDatabase.insertOrThrow(TailnetDatabaseHelper.TABLE_PROFILES, null, values(profile))
        refreshProfiles()
        profile
    }

    suspend fun updateProfile(profile: TailnetProfile) = withContext(Dispatchers.IO) {
        val updated = profile.copy(updatedAt = System.currentTimeMillis())
        dbHelper.writableDatabase.update(
            TailnetDatabaseHelper.TABLE_PROFILES, values(updated),
            "${TailnetDatabaseHelper.COL_ID} = ?", arrayOf(updated.id),
        )
        refreshProfiles()
    }

    suspend fun deleteProfile(id: String) = withContext(Dispatchers.IO) {
        dbHelper.writableDatabase.delete(
            TailnetDatabaseHelper.TABLE_PROFILES,
            "${TailnetDatabaseHelper.COL_ID} = ?", arrayOf(id),
        )
        refreshProfiles()
    }

    fun getProfileImmediate(id: String): TailnetProfile? = _profiles.value.find { it.id == id }
    fun getProfilesImmediate(): List<TailnetProfile> = _profiles.value

    private fun values(profile: TailnetProfile) = ContentValues().apply {
        put(TailnetDatabaseHelper.COL_ID, profile.id)
        put(TailnetDatabaseHelper.COL_DISPLAY_NAME, profile.displayName)
        put(TailnetDatabaseHelper.COL_ENABLED, if (profile.enabled) 1 else 0)
        put(TailnetDatabaseHelper.COL_PROV_STATE, profile.provisioningState.name)
        put(TailnetDatabaseHelper.COL_CREATED_AT, profile.createdAt)
        put(TailnetDatabaseHelper.COL_UPDATED_AT, profile.updatedAt)
        if (profile.sourceProfileId == null) putNull(TailnetDatabaseHelper.COL_SOURCE_PROFILE_ID)
        else put(TailnetDatabaseHelper.COL_SOURCE_PROFILE_ID, profile.sourceProfileId)
        put(TailnetDatabaseHelper.COL_OWNER, profile.owner.name)
        put(TailnetDatabaseHelper.COL_STANDARD_SELECTED, if (profile.standardSelected) 1 else 0)
        put(TailnetDatabaseHelper.COL_MIGRATION_VERSION, profile.migrationVersion)
    }
}
