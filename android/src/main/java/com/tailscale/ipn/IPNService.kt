// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package com.tailscale.ipn
import com.tailscale.ipn.multiproxy.db.ProfileRepository
import com.tailscale.ipn.multiproxy.AppUidResolver
import com.tailscale.ipn.multiproxy.CredentialStore
import com.tailscale.ipn.multiproxy.RoutingSettings
import com.tailscale.ipn.multiproxy.UpstreamPolicyApplier
import com.tailscale.ipn.multiproxy.UpstreamSecretStore
import com.tailscale.ipn.multiproxy.db.AppBindingRepository
import com.tailscale.ipn.multiproxy.db.TailnetProfile
import com.tailscale.ipn.multiproxy.db.UpstreamOwner
import com.tailscale.ipn.multiproxy.db.UpstreamRepository
import kotlinx.coroutines.launch
import libtailscale.Libtailscale

import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import com.tailscale.ipn.mdm.MDMSettings
import com.tailscale.ipn.ui.model.Ipn
import com.tailscale.ipn.ui.notifier.Notifier
import com.tailscale.ipn.util.TSLog
import java.util.UUID
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock


enum class VpnRuntimeMode {
    STOPPED, STANDARD, MULTIPROXY
}

class MultiProxySession(val app: App) {
    var engine: libtailscale.MultiProxyEngine? = null
    var activeFd: Int = -1
    var activePfd: ParcelFileDescriptor? = null

    val profileRepository = ProfileRepository(app)
    val credentialStore = CredentialStore(app.getEncryptedPrefs())

    // Non-Tailnet upstreams and the per-app routing policy. The engine keeps none
    // of this across restarts, so these are the source of truth and
    // upstreamPolicyApplier is what reconciles a fresh engine with them.
    val upstreamRepository = UpstreamRepository(app)
    val appBindingRepository = AppBindingRepository(app)
    val upstreamSecretStore = UpstreamSecretStore(app.getEncryptedPrefs())
    val routingSettings = RoutingSettings(app)
    val upstreamPolicyApplier = UpstreamPolicyApplier(
        app, upstreamRepository, appBindingRepository, upstreamSecretStore, routingSettings)

    // The network's own DNS server, refreshed whenever the underlying
    // network changes. Used as the non-tailnet DNS fallback only when the
    // user hasn't selected a public DoH resolver - see applyUpstreamDNS.
    private var lastUnderlyingDns: String = ""

    fun onUnderlyingDnsChanged(dns: String) {
        lastUnderlyingDns = dns
        applyUpstreamDNS()
    }

    // applyUpstreamDNS recomputes and pushes the non-tailnet DNS fallback
    // used by this Multi-Tailnet session: the user's selected public DoH
    // resolver if one is set (same preference the Standard-mode backend
    // reads via Libtailscale.applyDNSSettings - see DNSSettingsViewModel),
    // otherwise the underlying network's own DNS server. Unlike Standard
    // mode, Multi-Tailnet's DNS server is a from-scratch implementation
    // (multiproxy/dns.go) with no link to the regular backend's DNS
    // manager, so this preference has to be applied here explicitly rather
    // than reusing that mechanism.
    fun applyUpstreamDNS() {
        val dohUrl = app.decryptFromPref(
            com.tailscale.ipn.ui.viewModel.DNSSettingsViewModel.PUBLIC_DOH_URL_KEY,
        )?.trim().orEmpty()
        val resolved = if (dohUrl.isNotEmpty()) dohUrl else lastUnderlyingDns
        // Diagnostic for validation_and_gaps.md #78: this can run with
        // lastUnderlyingDns still empty right after a restart, if it runs
        // before NetworkChangeCallback has replayed the current network's
        // LinkProperties to the freshly re-registered callback - which would
        // leave general (non-tailnet) DNS broken until/unless something
        // calls this again with a real value. This line makes that visible
        // in logcat instead of having to infer it.
        TSLog.d("MultiProxySession", "applyUpstreamDNS: dohUrl='$dohUrl' lastUnderlyingDns='$lastUnderlyingDns' -> resolved='$resolved' engine=${engine != null}")
        // Always hand the underlying resolver over as well, even when a DoH URL
        // wins below: the engine needs a non-synthetic resolver to look up the
        // DoH server's own hostname, which it cannot ask our own DNS server to
        // do without deadlocking on that same query.
        if (lastUnderlyingDns.isNotEmpty()) {
            engine?.setBootstrapDNS(lastUnderlyingDns)
        }
        engine?.setUpstreamDNS(resolved)
    }


    fun reconstructEngine(serviceScope: kotlinx.coroutines.CoroutineScope) {
        serviceScope.launch {
            val profiles = profileRepository.profiles.value
            profiles.forEach { profile ->
                val authKey = credentialStore.getAuthKey(profile.id) ?: ""
                try {
                    engine?.addTailnet(profile.id, authKey, profile.enabled)
                    if (profile.enabled && authKey.isNotEmpty()) {
                        // After first provision, we can optionally clear the auth key
                        // credentialStore.deleteAuthKey(profile.id)
                        // We will test if tsnet persists it!
                    }
                } catch (e: Exception) {
                    TSLog.e("MultiProxySession", "Failed to reconstruct profile ${profile.id}: ${e.message}")
                }
            }
        }
    }
}

open class IPNService : VpnService(), libtailscale.IPNService {
  private val TAG = "IPNService"
  private val randomID: String = UUID.randomUUID().toString()
  private lateinit var app: App
  val scope = CoroutineScope(Dispatchers.IO)
  private var closed = false

  private val transitionMutex = Mutex()
  private var activeMode = VpnRuntimeMode.STOPPED
  
  // Used only for MULTIPROXY
  companion object {
    const val ACTION_START_VPN = "com.tailscale.ipn.START_VPN"
    const val ACTION_STOP_VPN = "com.tailscale.ipn.STOP_VPN"
    const val ACTION_RESTART_VPN = "com.tailscale.ipn.RESTART_VPN"
    const val ACTION_START_FOREGROUND_ONLY = "com.tailscale.ipn.START_FOREGROUND_ONLY"
    const val ACTION_START_MULTIPROXY = "com.tailscale.ipn.START_MULTIPROXY"
    const val ACTION_STOP_MULTIPROXY = "com.tailscale.ipn.STOP_MULTIPROXY"
    
    @Volatile private var instance: IPNService? = null

    private val _runtimeMode = MutableStateFlow(VpnRuntimeMode.STOPPED)
    val runtimeMode: StateFlow<VpnRuntimeMode> = _runtimeMode.asStateFlow()

    private fun publishRuntimeMode(mode: VpnRuntimeMode) {
      _runtimeMode.value = mode
    }

    fun onUnderlyingDnsChanged(dns: String) {
        instance?.app?.multiProxySession?.onUnderlyingDnsChanged(dns)
    }

    // True when persisted intent (survives process death, unlike the
    // in-memory runtimeMode StateFlow above, which resets to STOPPED on
    // every fresh process) says Multi-Tailnet mode should be running. Lets
    // the UI tell "the user stopped this" apart from "this was running and
    // got killed - Android's own service-restart will bring it back, but on
    // a repeat crash-loop that restart is throttled and can take a while" -
    // see validation_and_gaps.md #76. Both states currently render as a bare
    // "VPN is stopped" with no way to tell them apart.
    fun persistedWantsMultiProxy(context: android.content.Context): Boolean {
      val prefs = context.getSharedPreferences("vpn_mode", android.content.Context.MODE_PRIVATE)
      return prefs.getBoolean("wantRunning", false) &&
          prefs.getString("selectedMode", "STANDARD") == "MULTIPROXY"
    }
  }

  override fun id(): String {
    return randomID
  }

  override fun updateVpnStatus(status: Boolean) {
    app.getAppScopedViewModel().setVpnActive(status)
  }

  override fun onCreate() {
    super.onCreate()
    app = App.get()
    instance = this
    
  }

  private fun setActiveMode(mode: VpnRuntimeMode) {
    activeMode = mode
    publishRuntimeMode(mode)
  }

  private suspend fun transitionTo(targetMode: VpnRuntimeMode) {
      transitionMutex.withLock {
          if (activeMode == targetMode) return
          
          TSLog.d(TAG, "Transitioning from $activeMode to $targetMode")
          
          // Teardown current mode
          if (activeMode == VpnRuntimeMode.MULTIPROXY) {
              if (!stopMultiProxyVPNLocked() && targetMode == VpnRuntimeMode.STANDARD) {
                  TSLog.e(TAG, "Refusing to start STANDARD after MULTIPROXY state restore failed")
                  setActiveMode(VpnRuntimeMode.STOPPED)
                  return@withLock
              }
          } else if (activeMode == VpnRuntimeMode.STANDARD) {
              app.setWantRunning(false)
              Libtailscale.serviceDisconnect(this) // blocking teardown
          }
          
          setActiveMode(VpnRuntimeMode.STOPPED)
          
          if (targetMode == VpnRuntimeMode.MULTIPROXY) {
              val success = startMultiProxyVPNLocked()
              if (success) {
                  setActiveMode(VpnRuntimeMode.MULTIPROXY)
              } else {
                  TSLog.e(TAG, "Failed to start MULTIPROXY")
                  stopMultiProxyVPNLocked()
              }
          } else if (targetMode == VpnRuntimeMode.STANDARD) {
              app.setWantRunning(true)
              val success = Libtailscale.requestVPN(this@IPNService)
              if (success) {
                  setActiveMode(VpnRuntimeMode.STANDARD)
              } else {
                  TSLog.e(TAG, "Failed to start STANDARD VPN")
                  setActiveMode(VpnRuntimeMode.STOPPED)
                  app.setWantRunning(false)
              }
          }
      }
  }

  private suspend fun startMultiProxyVPNLocked(): Boolean {
      val session = app.multiProxySession
      
      val token = "MULTIPROXY-${id()}"
      if (!Libtailscale.acquireMultiProxyNetworkHooks(token, this@IPNService, app)) {
          TSLog.e(TAG, "Failed to acquire Android network hooks for MULTIPROXY")
          return false
      }
      
      for (profile in session.profileRepository.getProfilesImmediate()) {
          val sourceProfileId = profile.sourceProfileId ?: continue
          if (!profile.enabled) continue
          try {
              Libtailscale.prepareRegularProfileForMultiProxy(app.filesDir.absolutePath, app, sourceProfileId, profile.id)
              session.profileRepository.updateProfile(profile.copy(owner = UpstreamOwner.MULTIPROXY))
          } catch (e: Exception) {
              TSLog.e(TAG, "Failed to prepare regular profile " + sourceProfileId + " for MULTIPROXY: " + e.message)
              Libtailscale.releaseMultiProxyNetworkHooks(token)
              return false
          }
      }

      if (session.engine == null) {
          val dataDir = app.filesDir.absolutePath
          session.engine = Libtailscale.newMultiProxyEngineForApp(dataDir, app, object : libtailscale.MultiProxyCallback {
            override fun onPeerDiscovered(hostname: String?, syntheticIPv4: String?, syntheticIPv6: String?, tailnetID: String?) {
                TSLog.d(TAG, "MultiProxy peer: $hostname -> $syntheticIPv6 (Tailnet: $tailnetID)")
            }
            override fun onTailnetStateChange(tailnetID: String?, state: String?) {
                TSLog.d(TAG, "MultiProxy tailnet $tailnetID state: $state")
            }
            override fun onAddressCrossover(ip: String?, candidateTailnetIDsCSV: String?, chosenTailnetID: String?) {
                MultiProxySessionCoordinator.recordAddressCrossover(
                    ip ?: return,
                    candidateTailnetIDsCSV ?: "",
                    chosenTailnetID ?: "",
                )
            }
            override fun onUpstreamHealthChanged(upstreamID: String?, ready: Boolean, reason: String?) {
                MultiProxySessionCoordinator.recordUpstreamHealthChange(
                    upstreamID ?: return,
                    ready,
                    reason ?: "",
                )
            }
          })
      }
      
      val success = rebuildMultiProxyTunLocked(session)
      if (!success) {
          return false
      }
      
      // Fills the race window documented in validation_and_gaps.md #78: right
      // after a process restart, the network callback registered in
      // App.onCreate may not have delivered its first update yet, which
      // would otherwise make the fallback below apply an empty DNS value.
      NetworkChangeCallback.snapshotIfEmpty(
          app.getSystemService(android.content.Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager)

      NetworkChangeCallback.currentUnderlyingDnsServer()?.let { session.onUnderlyingDnsChanged(it) }
        ?: session.applyUpstreamDNS()

      session.reconstructEngine(this@IPNService.scope)
      return true
  }

  private suspend fun stopMultiProxyVPNLocked(): Boolean {
      val session = app.multiProxySession
      var restoredAllProfiles = true
      
      val runtimeStates = MultiProxySessionCoordinator.runtimeStates.value
      session.engine?.stopVPN()
      session.engine?.close()
      session.engine = null

      for (profile in session.profileRepository.getProfilesImmediate()) {
          val sourceProfileId = profile.sourceProfileId ?: continue
          if (profile.owner != UpstreamOwner.MULTIPROXY) continue
          if (runtimeStates[profile.id] != "RUNNING") {
              TSLog.w(TAG, "Leaving regular profile " + sourceProfileId + " untouched; multiproxy upstream never authenticated")
              session.profileRepository.updateProfile(profile.copy(owner = UpstreamOwner.IDLE))
              continue
          }
          try {
              Libtailscale.restoreRegularProfileFromMultiProxy(app.filesDir.absolutePath, app, sourceProfileId, profile.id)
              session.profileRepository.updateProfile(profile.copy(owner = UpstreamOwner.IDLE))
          } catch (e: Exception) {
              restoredAllProfiles = false
              TSLog.e(TAG, "Failed to restore MULTIPROXY profile " + sourceProfileId + ": " + e.message)
          }
      }
      
      session.activePfd?.close()
      session.activePfd = null
      session.activeFd = -1
      
      Libtailscale.releaseMultiProxyNetworkHooks("MULTIPROXY-${id()}")
      return restoredAllProfiles
  }
  
  private fun rebuildMultiProxyTunLocked(session: MultiProxySession): Boolean {
      val engine = session.engine ?: return false
      
      val b = Builder()
        .setConfigureIntent(configIntent())
        .allowFamily(OsConstants.AF_INET)
        .allowFamily(OsConstants.AF_INET6)

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        b.setMetered(false)
      }
      b.setUnderlyingNetworks(null)

      val mdmAllowed = MDMSettings.includedPackages.flow.value.value?.split(",")?.map { it.trim() } ?: emptyList()
      val mdmDisallowed = MDMSettings.excludedPackages.flow.value.value?.split(",")?.map { it.trim() } ?: emptyList()

      var packagesList: List<String>
      var allowPackages: Boolean
      if (mdmAllowed.isNotEmpty()) {
        packagesList = mdmAllowed
        allowPackages = true
      } else if (mdmDisallowed.isNotEmpty()) {
        packagesList = mdmDisallowed
        allowPackages = false
      } else {
        packagesList = UninitializedApp.get().selectedPackageNames()
        allowPackages = UninitializedApp.get().allowSelectedPackages()
      }

      if (allowPackages) {
        for (packageName in packagesList) { allowApp(b, packageName) }
      } else {
        packagesList += UninitializedApp.get().builtInDisallowedPackageNames
        for (packageName in packagesList) { disallowApp(b, packageName) }
      }

      val ifaceAddr = Libtailscale.multiProxySyntheticInterfaceAddress()
      val dnsAddr = Libtailscale.multiProxySyntheticDNSAddress()
      val prefixString = Libtailscale.multiProxySyntheticIPv6Prefix()
      val prefixParts = prefixString.split("/")
      val routeAddr = prefixParts[0]
      val routeLen = prefixParts[1].toInt()

      b.addAddress(ifaceAddr, 120)
      b.addRoute(routeAddr, routeLen)
      b.addDnsServer(dnsAddr)

      // Synthetic IPv4, alongside the v6 above. Apps that can only speak v4 -
      // or that just ask for an A record and stop - would otherwise see the
      // tailnet as unreachable even though the peer resolves fine over v6.
      // The v4 resolver is listed second so v6-capable clients keep using the
      // v6 one and behavior there is unchanged.
      val ifaceAddrV4 = Libtailscale.multiProxySyntheticIPv4InterfaceAddress()
      val dnsAddrV4 = Libtailscale.multiProxySyntheticIPv4DNSAddress()
      val prefixV4Parts = Libtailscale.multiProxySyntheticIPv4Prefix().split("/")
      b.addAddress(ifaceAddrV4, 32)
      b.addRoute(prefixV4Parts[0], prefixV4Parts[1].toInt())
      b.addDnsServer(dnsAddrV4)

      // Real Tailscale space (CGNAT 100.64.0.0/10 and the Tailscale ULA
      // range), on top of the two synthetic prefixes above. Not everything
      // that talks to a peer goes through our synthetic DNS first: SIP and
      // TURN/STUN put literal peer addresses in their payloads, so the app
      // dials a real Tailscale IP it was handed rather than a name we could
      // have answered with a synthetic address. Without these routes that
      // traffic leaves over the underlying network and nothing answers.
      //
      // The engine already knows how to route these (realIPIndex), including
      // the case where two connected tailnets both hold the same address -
      // it picks deterministically and reports the conflict. What was missing
      // was purely that the OS never handed us the packets in the first place.
      for (realPrefix in listOf(
          Libtailscale.multiProxyRealTailscaleIPv4Prefix(),
          Libtailscale.multiProxyRealTailscaleIPv6Prefix(),
      )) {
          val parts = realPrefix.split("/")
          try {
              b.addRoute(parts[0], parts[1].toInt())
          } catch (e: Exception) {
              // A rejected route must not take the whole session down: the
              // synthetic prefixes above are what the common path depends on,
              // and they're already installed by this point.
              TSLog.e(TAG, "MultiProxy: could not add real Tailscale route $realPrefix: $e")
          }
      }

      // Broad capture: hand the engine ordinary internet and LAN traffic too,
      // not just the synthetic and real-Tailscale ranges above. Off by
      // default - enabling Multi-Tailnet must never, by itself, change what
      // an existing user's other apps can reach - so this only takes effect
      // once the user opts in via RoutingSettings.broadCaptureEnabled.
      // Installed alongside the narrower routes above rather than replacing
      // them: Android's VPN routing already prefers the most specific match,
      // so this only changes behaviour for traffic none of them covered.
      //
      // UpstreamPolicyApplier defaults unbound apps to the direct upstream
      // when this is on and no explicit default route is set, so turning
      // this on alone does not change behaviour for an app the user has not
      // routed anywhere - it only makes doing so possible.
      if (session.routingSettings.broadCaptureEnabled) {
          b.addRoute("0.0.0.0", 0)
          b.addRoute("::", 0)
      }

      b.setMtu(1280)

      engine.stopVPN()
      
      session.activePfd?.close()
      session.activePfd = null
      session.activeFd = -1
      
      val pfd = b.establish()
      if (pfd != null) {
          session.activePfd = pfd
          session.activeFd = pfd.detachFd()
          
          try {
              // Install per-flow app attribution before the datapath can carry a flow.
              // getConnectionOwnerUid only answers for the app holding the VPN, which is
              // us from establish() onwards, so this is the earliest correct point.
              engine.setUIDResolver(AppUidResolver(this))
              engine.startVPN(session.activeFd, 1280)
              // After startVPN, so that a registered upstream is never dialable
              // before the datapath it belongs to exists. Failures inside are
              // logged and skipped rather than taking the session down: a
              // misconfigured upstream should cost its own traffic, not the VPN.
              session.upstreamPolicyApplier.apply(engine)
              return true
          } catch (e: Exception) {
              TSLog.e(TAG, "MultiProxy StartVPN failed: $e")
              session.activePfd?.close()
              session.activePfd = null
              session.activeFd = -1
              return false
          }
      } else {
          TSLog.e(TAG, "Builder.establish() returned null")
          return false
      }
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
      val prefs = app.getSharedPreferences("vpn_mode", android.content.Context.MODE_PRIVATE)
      val selectedMode = prefs.getString("selectedMode", "STANDARD") ?: "STANDARD"

      when (intent?.action) {
        ACTION_STOP_VPN, ACTION_STOP_MULTIPROXY -> {
          prefs.edit().putBoolean("wantRunning", false).apply()
          scope.launch {
              transitionTo(VpnRuntimeMode.STOPPED)
              close()
          }
          return START_NOT_STICKY
        }
        ACTION_RESTART_VPN -> {
          scope.launch {
              transitionMutex.withLock {
                  val currentMode = activeMode
                  setActiveMode(VpnRuntimeMode.STOPPED)
                  if (currentMode == VpnRuntimeMode.MULTIPROXY) {
                      stopMultiProxyVPNLocked()
                      val s = startMultiProxyVPNLocked()
                      if (s) setActiveMode(VpnRuntimeMode.MULTIPROXY)
                  } else if (currentMode == VpnRuntimeMode.STANDARD) {
                      app.setWantRunning(false)
                      Libtailscale.serviceDisconnect(this@IPNService)
                      app.setWantRunning(true)
                      val success = Libtailscale.requestVPN(this@IPNService)
                      if (success) {
                          setActiveMode(VpnRuntimeMode.STANDARD)
                      } else {
                          setActiveMode(VpnRuntimeMode.STOPPED)
                          app.setWantRunning(false)
                      }
                  }
              }
          }
          return START_NOT_STICKY
        }
        ACTION_START_FOREGROUND_ONLY -> {
          showForegroundNotification()
          return START_NOT_STICKY
        }
        ACTION_START_VPN -> {
          prefs.edit().putString("selectedMode", "STANDARD").putBoolean("wantRunning", true).apply()
          showForegroundNotification()
          scope.launch {
              transitionTo(VpnRuntimeMode.STANDARD)
          }
          return START_STICKY
        }
        ACTION_START_MULTIPROXY -> {
          prefs.edit().putString("selectedMode", "MULTIPROXY").putBoolean("wantRunning", true).apply()
          showForegroundNotification()
          scope.launch {
              transitionTo(VpnRuntimeMode.MULTIPROXY)
          }
          return START_STICKY
        }
        "android.net.VpnService", null -> {
          val wantRunning = prefs.getBoolean("wantRunning", false)
          if (!wantRunning) {
              return START_NOT_STICKY
          }
          if (selectedMode == "MULTIPROXY") {
              showForegroundNotification()
              scope.launch { transitionTo(VpnRuntimeMode.MULTIPROXY) }
          } else {
              scope.launch {
                val hideDisconnectAction = MDMSettings.forceEnabled.flow.first()
                val exitNodeName = UninitializedApp.getExitNodeName(Notifier.prefs.value, Notifier.netmap.value)
                app.notifyStatus(true, hideDisconnectAction.value, exitNodeName)
                transitionTo(VpnRuntimeMode.STANDARD)
              }
          }
          return START_STICKY
        }
        else -> {
          val wantRunning = prefs.getBoolean("wantRunning", false)
          if (!wantRunning) {
              return START_NOT_STICKY
          }
          if (selectedMode == "MULTIPROXY") {
              showForegroundNotification()
              scope.launch { transitionTo(VpnRuntimeMode.MULTIPROXY) }
              return START_STICKY
          } else {
              if (UninitializedApp.get().isAbleToStartVPN()) {
                showForegroundNotification()
                scope.launch { transitionTo(VpnRuntimeMode.STANDARD) }
                return START_STICKY
              } else {
                return START_NOT_STICKY
              }
          }
        }
      }
  }

  override fun close() {
    if (closed) return
    closed = true
    
    scope.launch {
        transitionTo(VpnRuntimeMode.STOPPED)
        disconnectVPN()
    }
  }

  override fun disconnectVPN() {
    stopSelf()
  }

  override fun onDestroy() {
    close()
    updateVpnStatus(false)
    publishRuntimeMode(VpnRuntimeMode.STOPPED)
    if (instance == this) {
        instance = null
    }
    super.onDestroy()
  }

  override fun onRevoke() {
    val prefs = app.getSharedPreferences("vpn_mode", android.content.Context.MODE_PRIVATE)
    prefs.edit().putBoolean("wantRunning", false).apply()
    setVpnPrepared(false)
    
    scope.launch {
        transitionTo(VpnRuntimeMode.STOPPED)
        close()
        updateVpnStatus(false)
    }
    super.onRevoke()
  }

  private fun setVpnPrepared(isPrepared: Boolean) {
    app.getAppScopedViewModel().setVpnPrepared(isPrepared)
  }

  private fun showForegroundNotification(
      hideDisconnectAction: Boolean,
      exitNodeName: String? = null
  ) {
    try {
      startForeground(
          UninitializedApp.STATUS_NOTIFICATION_ID,
          UninitializedApp.get().buildStatusNotification(true, hideDisconnectAction, exitNodeName))
    } catch (e: Exception) {
      TSLog.e(TAG, "Failed to start foreground service: $e")
    }
  }

  private fun showForegroundNotification() {
    val hideDisconnectAction = MDMSettings.forceEnabled.flow.value.value
    val exitNodeName = UninitializedApp.getExitNodeName(Notifier.prefs.value, Notifier.netmap.value)
    showForegroundNotification(hideDisconnectAction, exitNodeName)
  }

  private fun configIntent(): PendingIntent {
    return PendingIntent.getActivity(
        this,
        0,
        Intent(this, MainActivity::class.java),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
  }

  private fun allowApp(b: Builder, name: String) {
    try {
      b.addAllowedApplication(name)
    } catch (e: PackageManager.NameNotFoundException) {
      TSLog.e(TAG, "Failed to add allowed application: $e")
    }
  }

  private fun disallowApp(b: Builder, name: String) {
    try {
      b.addDisallowedApplication(name)
    } catch (e: PackageManager.NameNotFoundException) {
      TSLog.e(TAG, "Failed to add disallowed application: $e")
    }
  }

  override fun newBuilder(): VPNServiceBuilder {
    val b: Builder =
        Builder()
            .setConfigureIntent(configIntent())
            .allowFamily(OsConstants.AF_INET)
            .allowFamily(OsConstants.AF_INET6)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
      b.setMetered(false)
    }
    b.setUnderlyingNetworks(null)

    val mdmAllowed =
        MDMSettings.includedPackages.flow.value.value?.split(",")?.map { it.trim() } ?: emptyList()
    val mdmDisallowed =
        MDMSettings.excludedPackages.flow.value.value?.split(",")?.map { it.trim() } ?: emptyList()

    var packagesList: List<String>
    var allowPackages: Boolean
    if (mdmAllowed.isNotEmpty()) {
      packagesList = mdmAllowed
      allowPackages = true
    } else if (mdmDisallowed.isNotEmpty()) {
      packagesList = mdmDisallowed
      allowPackages = false
    } else {
      packagesList = UninitializedApp.get().selectedPackageNames()
      allowPackages = UninitializedApp.get().allowSelectedPackages()
    }

    if (allowPackages) {
      for (packageName in packagesList) { allowApp(b, packageName) }
    } else {
      packagesList += UninitializedApp.get().builtInDisallowedPackageNames
      for (packageName in packagesList) { disallowApp(b, packageName) }
    }

    return VPNServiceBuilder(b)
  }
}
