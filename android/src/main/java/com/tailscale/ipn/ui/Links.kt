// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui

object Links {
  // Tailscale-hosted service endpoints. These remain service-specific references and are not
  // Tailmesh project ownership claims.
  const val DEFAULT_CONTROL_URL = "https://controlplane.tailscale.com"
  const val SERVER_URL = "https://login.tailscale.com"
  const val ADMIN_URL = SERVER_URL + "/admin"
  const val SIGNIN_URL = "https://tailscale.com/login"
  const val PRIVACY_POLICY_URL = "https://tailscale.com/privacy-policy/"
  const val TERMS_URL = "https://tailscale.com/terms"
  const val DOCS_URL = "https://tailscale.com/kb/"
  const val START_GUIDE_URL = "https://tailscale.com/kb/1017/install/"
  const val DELETE_ACCOUNT_URL =
      "https://login.tailscale.com/login?next_url=%2Fadmin%2Fsettings%2Fgeneral"
  const val TAILNET_LOCK_KB_URL = "https://tailscale.com/kb/1226/tailnet-lock/"
  const val KEY_EXPIRY_KB_URL = "https://tailscale.com/kb/1028/key-expiry/"
  const val INSTALL_TAILSCALE_KB_URL = "https://tailscale.com/kb/installation/"
  const val INSTALL_UNSTABLE_KB_URL = "https://tailscale.com/kb/1083/install-unstable"
  const val MAGICDNS_KB_URL = "https://tailscale.com/kb/1081/magicdns"
  const val TROUBLESHOOTING_KB_URL = "https://tailscale.com/kb/1023/troubleshooting"
  const val SUPPORT_URL = "https://tailscale.com/contact/support#support-form"
  const val TAILDROP_KB_URL = "https://tailscale.com/kb/1106/taildrop"
  const val TAILFS_KB_URL = "https://tailscale.com/kb/1106/taildrop"
  const val SUBNET_ROUTERS_KB_URL = "https://tailscale.com/kb/1019/subnets"

  // Tailmesh project resources.
  const val PROJECT_URL = "https://github.com/franticplant/tailmesh-android"
  const val PROJECT_ISSUES_URL = PROJECT_URL + "/issues"
  const val LICENSES_URL = PROJECT_URL + "/blob/main/THIRD_PARTY_NOTICES.md"
}
