package libtailscale

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"

	"tailscale.com/net/proxymux"
	"tailscale.com/net/socks5"
	"tailscale.com/net/tsdial"
)

var (
	proxyListener net.Listener
)

// updateLocalProxyListener starts or stops the local SOCKS5h/HTTP proxy listener.
func updateLocalProxyListener(enabled bool, addr string, dialer *tsdial.Dialer) {
	if !enabled {
		if proxyListener != nil {
			log.Printf("local_proxy: stopping listener on %v", proxyListener.Addr())
			proxyListener.Close()
			proxyListener = nil
		}
		return
	}
	if proxyListener != nil {
		if proxyListener.Addr().String() == addr {
			return
		}
		proxyListener.Close()
		proxyListener = nil
	}

	if addr == "" {
		addr = "127.0.0.1:1055"
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("local_proxy: failed to listen on %v: %v", addr, err)
		return
	}
	proxyListener = ln
	log.Printf("local_proxy: listening on %v", ln.Addr())

	socksListener, httpListener := proxymux.SplitSOCKSAndHTTP(ln)

	socksServer := &socks5.Server{
		Logf: func(format string, args ...any) {
			log.Printf("local_proxy(socks5): "+format, args...)
		},
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.UserDial(ctx, network, addr)
		},
	}
	go func() {
		log.Printf("local_proxy: SOCKS5 exited: %v", socksServer.Serve(socksListener))
	}()

	hs := &http.Server{Handler: httpProxyHandler(dialer.UserDial)}
	go func() {
		log.Printf("local_proxy: HTTP proxy exited: %v", hs.Serve(httpListener))
	}()
}

// httpProxyHandler returns an HTTP proxy http.Handler using the provided backend dialer.
func httpProxyHandler(dialer func(ctx context.Context, netw, addr string) (net.Conn, error)) http.Handler {
	importHttpUtil := true
	_ = importHttpUtil // in case httputil is used
	rp := &httputil.ReverseProxy{
		Director: func(r *http.Request) {}, // no change
		Transport: &http.Transport{
			DialContext: dialer,
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			backURL := r.RequestURI
			if strings.HasPrefix(backURL, "/") || backURL == "*" {
				http.Error(w, "bogus RequestURI; must be absolute URL or CONNECT", 400)
				return
			}
			rp.ServeHTTP(w, r)
			return
		}

		dst := r.RequestURI
		c, err := dialer(r.Context(), "tcp", dst)
		if err != nil {
			w.Header().Set("Tailscale-Connect-Error", err.Error())
			http.Error(w, err.Error(), 500)
			return
		}
		defer c.Close()

		cc, ccbuf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer cc.Close()

		io.WriteString(cc, "HTTP/1.1 200 OK\r\n\r\n")

		var clientSrc io.Reader = ccbuf
		if ccbuf.Reader.Buffered() == 0 {
			clientSrc = cc
		}

		errc := make(chan error, 1)
		go func() {
			_, err := io.Copy(cc, c)
			errc <- err
		}()
		go func() {
			_, err := io.Copy(c, clientSrc)
			errc <- err
		}()
		<-errc
	})
}

// UpdateLocalProxyListener implements Application.
func (a *App) UpdateLocalProxyListener(enabled bool, addr string) {
	// Wait until the backend is ready
	a.ready.Wait()
	if a.backend != nil {
		updateLocalProxyListener(enabled, addr, a.backend.Dialer())
	}
}
