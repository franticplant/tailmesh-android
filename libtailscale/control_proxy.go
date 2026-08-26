// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"log"
	"net/url"
	"strings"
	"sync/atomic"

	"tailscale.com/net/tshttpproxy"
)

const controlProxyURLPrefKey = "controlProxyURL"

var androidHTTPProxyLogging atomic.Bool

func installAndroidControlProxy(appCtx AppContext) {
	loadAndroidHTTPProxyLoggingSetting(appCtx)
	httpProxyLogf("control proxy: installing Android httpproxy resolver")
	if err := tshttpproxy.SetProxyFunc(func(reqURL *url.URL) (*url.URL, error) {
		proxyURL, err := appCtx.DecryptFromPref(controlProxyURLPrefKey)
		if err != nil {
			httpProxyLogf("control proxy: failed to read httpproxy setting: %v", err)
			return nil, nil
		}
		proxyURL = strings.TrimSpace(proxyURL)
		if proxyURL == "" {
			httpProxyLogf("control proxy: httpproxy disabled for %q", reqURL.Redacted())
			return nil, nil
		}

		u, err := url.Parse(proxyURL)
		if err != nil || u.Host == "" {
			httpProxyLogf("control proxy: ignoring invalid httpproxy URL %q: %v", proxyURL, err)
			return nil, nil
		}
		switch u.Scheme {
		case "http", "https":
			httpProxyLogf("control proxy: using httpproxy %q for %q", u.Redacted(), reqURL.Redacted())
			return u, nil
		default:
			httpProxyLogf("control proxy: ignoring unsupported httpproxy URL scheme %q", u.Scheme)
			return nil, nil
		}
	}); err != nil {
		httpProxyLogf("control proxy: failed to install httpproxy resolver: %v", err)
		return
	}
	httpProxyLogf("control proxy: installed Android httpproxy resolver")
}

func loadAndroidHTTPProxyLoggingSetting(appCtx AppContext) {
	androidHTTPProxyLogging.Store(decryptBoolPref(appCtx, debugHTTPProxyLoggingPrefKey, false))
}

func httpProxyLogf(format string, args ...any) {
	if !androidHTTPProxyLogging.Load() {
		return
	}
	log.Printf("ANDROID_HTTPPROXY "+format, args...)
}
