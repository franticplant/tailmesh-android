// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.multiproxy

import android.content.Context
import android.net.ConnectivityManager
import android.net.InetAddresses
import android.os.Process
import android.system.OsConstants
import com.tailscale.ipn.util.TSLog
import java.net.InetSocketAddress
import libtailscale.MultiProxyUIDResolver

/**
 * Attributes a flow to the application that opened it.
 *
 * The multiproxy datapath reads raw IP packets off the TUN, which carry no notion of a process, so
 * per-app policy rules need an out-of-band lookup. [ConnectivityManager.getConnectionOwnerUid] is
 * that lookup: it takes the same 5-tuple the gVisor forwarder request already has.
 *
 * The platform only answers this for the app that currently holds the VPN, which is us while
 * Multi-Tailnet mode is running.
 *
 * Every failure path returns [UNKNOWN_UID] rather than throwing. An unattributed flow can only ever
 * match a broader rule, never a narrower one, so a failed lookup degrades safely.
 */
class AppUidResolver(context: Context) : MultiProxyUIDResolver {

  private val connectivityManager =
      context.applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE)
          as? ConnectivityManager

  /**
   * Set once the platform has refused a lookup in a way that will not change - a missing service,
   * or a SecurityException because we are not the active VPN. Retrying per flow would burn a JNI
   * round trip and a framework call on every connection for no benefit.
   */
  @Volatile private var disabled = false

  override fun resolveUID(
      protocol: String,
      srcIP: String,
      srcPort: Int,
      dstIP: String,
      dstPort: Int
  ): Int {
    if (disabled) return UNKNOWN_UID
    val cm =
        connectivityManager
            ?: run {
              disabled = true
              return UNKNOWN_UID
            }

    val ipProtocol =
        when (protocol.lowercase()) {
          "tcp" -> OsConstants.IPPROTO_TCP
          "udp" -> OsConstants.IPPROTO_UDP
          else -> return UNKNOWN_UID
        }

    return try {
      // getConnectionOwnerUid names the ends from the querying app's point of view: "local" is the
      // socket's own address, which for the flow we intercepted is the originating app's source.
      //
      // srcIP/dstIP are always already-literal IP strings (the Go side never passes a hostname
      // here) - InetAddresses.parseNumericAddress parses one directly, with no DNS-capable
      // fallback path, unlike InetAddress.getByName, which runs every call through
      // hostname-or-literal detection and validation built for the general case even though a
      // literal is guaranteed here. This lookup is racing against a socket's port being reused by
      // a different app (see resolveAppUID's doc comment on the Go side), so shaving real, if
      // modest, time off every call here narrows that race a little further, for free.
      val local = InetSocketAddress(InetAddresses.parseNumericAddress(srcIP), srcPort)
      val remote = InetSocketAddress(InetAddresses.parseNumericAddress(dstIP), dstPort)

      when (val uid = cm.getConnectionOwnerUid(ipProtocol, local, remote)) {
        Process.INVALID_UID -> UNKNOWN_UID
        // Our own upstream sockets are not interesting to attribute, and reporting them would let a
        // rule written for "the VPN app" capture traffic it is merely carrying.
        Process.myUid() -> UNKNOWN_UID
        else -> uid
      }
    } catch (e: SecurityException) {
      // Raised when we are not the active VPN. That does not resolve itself mid-session.
      TSLog.d(TAG, "getConnectionOwnerUid denied; per-app rules will not match: $e")
      disabled = true
      UNKNOWN_UID
    } catch (e: Exception) {
      // An unresolvable address or a transient framework failure. Not fatal, not worth disabling.
      UNKNOWN_UID
    }
  }

  companion object {
    private const val TAG = "AppUidResolver"

    /** Matches multiproxy.UnknownAppUID and android.os.Process.INVALID_UID. */
    const val UNKNOWN_UID = -1
  }
}
