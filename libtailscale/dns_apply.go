// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

// ApplyDNSSettings asks the backend to recompile DNS using the current
// Android-side DNS settings.
func ApplyDNSSettings() {
	applyAndroidNetworkDebugLoggingSettings()
	applyAndroidDNSSettings()
}

// ApplyNetworkDebugLoggingSettings reloads Android-side network debug logging
// switches without requiring a process restart.
func ApplyNetworkDebugLoggingSettings() {
	applyAndroidNetworkDebugLoggingSettings()
}

func applyAndroidNetworkDebugLoggingSettings() {
	android.mu.Lock()
	appCtx := android.appCtx
	android.mu.Unlock()
	if appCtx == nil {
		return
	}
	loadAndroidHTTPProxyLoggingSetting(appCtx)
	loadAndroidDNSLoggingSettings(appCtx)
	dnsConfigLogf("public DoH: reloaded Android network debug logging settings dnsConfig=%v dnsQuery=%v", androidDNSConfigLogging.Load(), androidDNSQueryLogging.Load())
	httpProxyLogf("control proxy: reloaded Android network debug logging settings httpProxy=%v", androidHTTPProxyLogging.Load())
}
