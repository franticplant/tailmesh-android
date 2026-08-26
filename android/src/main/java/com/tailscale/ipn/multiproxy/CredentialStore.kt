package com.tailscale.ipn.multiproxy

import android.content.SharedPreferences

class CredentialStore(private val encryptedPrefs: SharedPreferences) {

    fun saveAuthKey(profileId: String, authKey: String) {
        encryptedPrefs.edit().putString("auth_key_$profileId", authKey).apply()
    }

    fun getAuthKey(profileId: String): String? {
        return encryptedPrefs.getString("auth_key_$profileId", null)
    }

    fun deleteAuthKey(profileId: String) {
        encryptedPrefs.edit().remove("auth_key_$profileId").apply()
    }
}
