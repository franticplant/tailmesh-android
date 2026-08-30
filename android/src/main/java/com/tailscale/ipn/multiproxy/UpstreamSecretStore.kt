// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.multiproxy

import android.content.SharedPreferences
import org.json.JSONObject

/**
 * Holds upstream configurations, which are secrets.
 *
 * A WireGuard config contains a private key and a SOCKS5 one may contain a password, so the whole
 * configuration blob is kept here rather than split between the database and this store. Splitting
 * it would mean a WireGuard config lived half in each, with the reassembly - and the chance of
 * writing a key to the wrong half - repeated at every call site.
 *
 * Backed by the same EncryptedSharedPreferences instance as [CredentialStore]; the key prefixes
 * keep the two from colliding.
 */
class UpstreamSecretStore(private val encryptedPrefs: SharedPreferences) {

  /**
   * Stores an upstream's configuration JSON, in the form the corresponding `Add*Upstream` binding
   * expects.
   */
  fun saveConfig(upstreamId: String, configJson: String) {
    encryptedPrefs.edit().putString(key(upstreamId), configJson).apply()
  }

  fun getConfig(upstreamId: String): String? = encryptedPrefs.getString(key(upstreamId), null)

  fun deleteConfig(upstreamId: String) {
    encryptedPrefs.edit().remove(key(upstreamId)).apply()
  }

  /**
   * Strips a stored exit-node upstream's bootstrap `authKey` back out of its config JSON, leaving
   * every other field untouched.
   *
   * An exit-node's auth key is only needed for its first login; once its dedicated tsnet identity
   * has actually reached Running, the key is dead weight - re-registering it on a later VPN rebuild
   * reuses the persisted state directory and never reads the key again (see
   * `libtailscale/multiproxy/upstream_exitnode.go`'s `AddExitNodeUpstream` doc comment). Callers
   * should only call this once a live state poll has confirmed Running, not merely that
   * registration succeeded - a stuck `NeedsMachineAuth`/`NeedsLogin` identity still needs the key
   * to complete login on a future attempt.
   */
  fun clearAuthKey(upstreamId: String) {
    val configJson = getConfig(upstreamId) ?: return
    val obj =
        try {
          JSONObject(configJson)
        } catch (e: Exception) {
          return
        }
    if (obj.optString("authKey").isEmpty()) return
    obj.put("authKey", "")
    saveConfig(upstreamId, obj.toString())
  }

  private fun key(upstreamId: String) = "upstream_config_$upstreamId"
}
