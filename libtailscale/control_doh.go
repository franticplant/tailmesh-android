// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"log"
	"net/url"
	"strings"
	"sync/atomic"

	"tailscale.com/net/dns"
	"tailscale.com/net/dns/publicdns"
	"tailscale.com/net/dns/resolver"
	"tailscale.com/types/dnstype"
)

const (
	publicDoHURLPrefKey                   = "publicDoHURL"
	publicDoHOverrideExitNodePrefKey      = "publicDoHOverrideExitNode"
	publicDoHRouteThroughTailscalePrefKey = "publicDoHRouteThroughTailscale"
	publicDoHFailClosedResolverURL        = "https://invalid.invalid/dns-query"
	debugHTTPProxyLoggingPrefKey          = "debugHTTPProxyLogging"
	debugDNSConfigLoggingPrefKey          = "debugDNSConfigLogging"
	debugDNSQueryLoggingPrefKey           = "debugDNSQueryLogging"
)

var androidDNSBackend atomic.Pointer[backend]
var androidDNSConfigLogging atomic.Bool
var androidDNSQueryLogging atomic.Bool

func setAndroidDNSBackend(b *backend) {
	androidDNSBackend.Store(b)
	applyAndroidDNSRouteSetting()
}

func installAndroidPublicDoH(appCtx AppContext) {
	loadAndroidDNSLoggingSettings(appCtx)
	resolver.AndroidDNSConfigLogEnabled = func() bool {
		return androidDNSConfigLogging.Load()
	}
	resolver.AndroidDNSQueryLogEnabled = func() bool {
		return androidDNSQueryLogging.Load()
	}
	dns.HookModifyConfig.Add(func(cfg *dns.Config) {
		applyAndroidPublicDoHConfig(appCtx, cfg)
	})
	dnsConfigLogf("public DoH: installed Android DNS config hook")
}

func loadAndroidDNSLoggingSettings(appCtx AppContext) {
	androidDNSConfigLogging.Store(decryptBoolPref(appCtx, debugDNSConfigLoggingPrefKey, false))
	androidDNSQueryLogging.Store(decryptBoolPref(appCtx, debugDNSQueryLoggingPrefKey, false))
}

func applyAndroidDNSSettings() {
	applyAndroidDNSRouteSetting()
	b := androidDNSBackend.Load()
	if b == nil || b.sys == nil {
		dnsConfigLogf("public DoH: backend unavailable; changed DNS usage will apply on next backend start")
		return
	}
	m, ok := b.sys.DNSManager.GetOK()
	if !ok {
		dnsConfigLogf("public DoH: DNS manager unavailable; falling back to network-change reconfigure")
		OnDNSConfigChanged("")
		return
	}
	if err := m.RecompileDNSConfig(); err != nil {
		if err == dns.ErrNoDNSConfig {
			dnsConfigLogf("public DoH: no DNS config to recompile yet; falling back to network-change reconfigure")
			OnDNSConfigChanged("")
			return
		}
		dnsConfigLogf("public DoH: failed to recompile changed DNS usage: %v", err)
		return
	}
	if b.vpn == nil {
		dnsConfigLogf("public DoH: VPN facade unavailable after DNS recompile")
		return
	}
	if err := b.vpn.ReconfigureVPN(); err != nil {
		dnsConfigLogf("public DoH: failed to reconfigure VPN after DNS usage change: %v", err)
		return
	}
	dnsConfigLogf("public DoH: reapplied changed DNS usage")
}

func applyAndroidDNSRouteSetting() {
	b := androidDNSBackend.Load()
	if b == nil || b.sys == nil {
		return
	}
	resolverURL, _, valid, err := androidPublicDoHURL(b.appCtx)
	if err != nil {
		dnsConfigLogf("public DoH: failed to read resolver URL for route setting: %v", err)
		return
	}
	routeThroughTailscale := valid && resolverURL != "" &&
		decryptBoolPref(b.appCtx, publicDoHRouteThroughTailscalePrefKey, false)
	b.sys.ControlKnobs().UserDialUseRoutes.Store(routeThroughTailscale)
	dnsConfigLogf("public DoH: route-aware DNS dialing set to %v selectedResolver=%q validResolver=%v", routeThroughTailscale, resolverURL, valid)
}

func applyAndroidPublicDoHConfig(appCtx AppContext, cfg *dns.Config) {
	if cfg == nil {
		return
	}
	resolverURL, configured, valid, err := androidPublicDoHURL(appCtx)
	if err != nil {
		dnsConfigLogf("public DoH: failed to read resolver URL: %v", err)
		return
	}
	if !configured {
		dnsConfigLogf("public DoH: no selected resolver; keeping tailnet/default DNS usage")
		return
	}
	if !valid {
		cfg.DefaultResolvers = []*dnstype.Resolver{{Addr: publicDoHFailClosedResolverURL}}
		dnsConfigLogf("public DoH: refusing unsupported selected resolver URL %q; DNS will fail closed", resolverURL)
		return
	}
	overrideExitNode := decryptBoolPref(appCtx, publicDoHOverrideExitNodePrefKey, true)
	if !overrideExitNode && defaultResolversUseExitNodeProxy(cfg.DefaultResolvers) {
		dnsConfigLogf("public DoH: preserving exit-node DNS proxy selectedResolver=%q overrideExitNode=false", resolverURL)
		return
	}
	cfg.DefaultResolvers = []*dnstype.Resolver{{Addr: resolverURL}}
	dnsConfigLogf("public DoH: changed DNS usage to selected resolver %q overrideExitNode=%v", resolverURL, overrideExitNode)
}

func androidPublicDoHURL(appCtx AppContext) (resolverURL string, configured bool, valid bool, err error) {
	resolverURL, err = appCtx.DecryptFromPref(publicDoHURLPrefKey)
	if err != nil {
		return "", false, false, err
	}
	resolverURL = strings.TrimSpace(resolverURL)
	if resolverURL == "" {
		return "", false, false, nil
	}
	if !validKnownPublicDoH(resolverURL) {
		return resolverURL, true, false, nil
	}
	return resolverURL, true, true, nil
}

func validKnownPublicDoH(resolverURL string) bool {
	u, err := url.Parse(resolverURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return false
	}
	return len(publicdns.DoHIPsOfBase(resolverURL)) > 0
}

func defaultResolversUseExitNodeProxy(resolvers []*dnstype.Resolver) bool {
	for _, r := range resolvers {
		if r == nil {
			continue
		}
		if strings.HasPrefix(r.Addr, "http://") {
			return true
		}
	}
	return false
}

func decryptBoolPref(appCtx AppContext, key string, def bool) bool {
	value, err := appCtx.DecryptFromPref(key)
	if err != nil {
		dnsConfigLogf("public DoH: failed to read %s: %v", key, err)
		return def
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return def
	}
	if value == "true" {
		return true
	}
	if value == "false" {
		return false
	}
	dnsConfigLogf("public DoH: ignoring invalid boolean %s=%q", key, value)
	return def
}

func dnsConfigLogf(format string, args ...any) {
	if !androidDNSConfigLogging.Load() {
		return
	}
	log.Printf("ANDROID_DNS_USAGE "+format, args...)
}
