// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.multiproxy

import android.content.SharedPreferences

/**
 * Holds upstream configurations, which are secrets.
 *
 * A WireGuard config contains a private key and a SOCKS5 one may contain a password, so the whole
 * configuration blob is kept here rather than split between the database and this store. Splitting
 * it would mean a WireGuard config lived half in each, with the reassembly - and the chance of
 * writing a key to the wrong half - repeated at every call site.
 *
 * Backed by the same EncryptedSharedPreferences instance as [CredentialStore]; the key prefixes keep
 * the two from colliding.
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

  private fun key(upstreamId: String) = "upstream_config_$upstreamId"
}
