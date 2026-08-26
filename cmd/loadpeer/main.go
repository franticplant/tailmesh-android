// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Command loadpeer is a tsnet-based test peer for the multiproxy dataplane.
// It joins a tailnet as a real node and exposes a TCP throughput/echo
// endpoint and a UDP echo endpoint, so multiproxy's behavior under real
// TCP/UDP load can be exercised from an Android client without depending on
// any other machine being available or configured with specific tools.
//
// Usage:
//
//	go run ./cmd/loadpeer -authkeyfile /path/to/key.txt -hostname loadpeer -statedir /path/to/state
//
// The auth key is read from a file, never taken as a command-line argument
// or environment variable, so it doesn't end up in shell history or process
// listings. Delete the key file once the node has come up and persisted its
// state; it isn't needed again unless the state directory is also wiped.
//
// TCP protocol (port 7000): the first line sent by the client selects a
// mode:
//
//	SOURCE <n>\n   - server writes n bytes (default 64MiB) as fast as
//	                 possible, then closes. For measuring download
//	                 throughput.
//	SINK\n         - server reads until EOF, then replies with
//	                 "OK <bytes> <millis>\n". For measuring upload
//	                 throughput.
//	ECHO\n         - server echoes every subsequent byte back until the
//	                 client closes. For round-trip/latency checks under a
//	                 held-open TCP connection.
//
// UDP protocol (port 7001): every datagram received is echoed back
// unmodified, for latency/jitter/loss checks.
//
// HTTP (port 7080 by default): a small self-contained web UI at "/" for
// running the same kind of download/upload/latency tests from an ordinary
// browser instead of a raw TCP client - useful for testing interactively
// from a phone, since HTTP is still just TCP and exercises the same
// multiproxy dataplane path as the raw protocol above. See serveHTTP.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"tailscale.com/tsnet"
)

var (
	authkeyFile = flag.String("authkeyfile", "", "path to file containing the tailscale auth key")
	hostname    = flag.String("hostname", "loadpeer", "tailnet hostname for this node")
	stateDir    = flag.String("statedir", "", "tsnet state directory")
	native      = flag.Bool("native", false, "bind directly to the host's own network instead of joining the tailnet as a separate tsnet node; use this on a machine that already runs tailscaled natively")
	httpPort    = flag.Int("httpport", 7080, "port for the web UI (0 disables it)")
)

const maxDownloadBytes = 1 << 30 // 1GiB cap on a single /download request

var (
	tcpConnsActive int64
	tcpBytesTotal  int64
	udpPktsTotal   int64
	udpBytesTotal  int64
)

func main() {
	flag.Parse()

	if *native {
		runNative()
		return
	}

	if *authkeyFile == "" || *stateDir == "" {
		log.Fatal("-authkeyfile and -statedir are required (unless -native)")
	}
	keyBytes, err := os.ReadFile(*authkeyFile)
	if err != nil {
		log.Fatalf("reading authkey file: %v", err)
	}
	authkey := strings.TrimSpace(string(keyBytes))

	srv := &tsnet.Server{
		Dir:      *stateDir,
		Hostname: *hostname,
		AuthKey:  authkey,
		Logf:     func(string, ...any) {},
	}
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	status, err := srv.Up(ctx)
	if err != nil {
		log.Fatalf("tsnet.Up: %v", err)
	}
	log.Printf("loadpeer %q up, Tailscale IPs: %v (http UI port: %d)", *hostname, status.TailscaleIPs, *httpPort)

	tcpLn, err := srv.Listen("tcp", ":7000")
	if err != nil {
		log.Fatalf("Listen tcp: %v", err)
	}
	go serveTCP(tcpLn)

	// tsnet's ListenPacket requires an explicit local IP, unlike Listen,
	// which accepts a bare ":port".
	ip4, _ := srv.TailscaleIPs()
	udpConn, err := srv.ListenPacket("udp", fmt.Sprintf("%s:7001", ip4))
	if err != nil {
		log.Fatalf("ListenPacket udp: %v", err)
	}
	go serveUDP(udpConn)

	if *httpPort != 0 {
		httpLn, err := srv.Listen("tcp", fmt.Sprintf(":%d", *httpPort))
		if err != nil {
			log.Fatalf("Listen http: %v", err)
		}
		go serveHTTP(httpLn)
	}

	go statsLoop()

	select {}
}

// runNative binds directly to the host's own network stack instead of
// joining the tailnet as a second tsnet node. Use this on a machine that
// already runs tailscaled natively (e.g. a real Linux box, not the Android
// emulator's virtualized network) - it reaches the machine's existing
// Tailscale identity and NAT-traversal behavior instead of a synthetic
// tsnet node's, which matters when what's being tested is whether a
// specific network path can hold a direct (non-DERP) connection.
func runNative() {
	tcpLn, err := net.Listen("tcp", ":7000")
	if err != nil {
		log.Fatalf("Listen tcp: %v", err)
	}
	go serveTCP(tcpLn)

	udpConn, err := net.ListenPacket("udp", ":7001")
	if err != nil {
		log.Fatalf("ListenPacket udp: %v", err)
	}
	go serveUDP(udpConn)

	if *httpPort != 0 {
		httpLn, err := net.Listen("tcp", fmt.Sprintf(":%d", *httpPort))
		if err != nil {
			log.Fatalf("Listen http: %v", err)
		}
		go serveHTTP(httpLn)
		log.Printf("loadpeer (native) listening on :7000 (tcp), :7001 (udp), :%d (http)", *httpPort)
	} else {
		log.Printf("loadpeer (native) listening on :7000 (tcp) and :7001 (udp)")
	}
	go statsLoop()

	select {}
}

func statsLoop() {
	for range time.Tick(5 * time.Second) {
		log.Printf("stats: tcp_active=%d tcp_bytes_total=%d udp_pkts_total=%d udp_bytes_total=%d",
			atomic.LoadInt64(&tcpConnsActive), atomic.LoadInt64(&tcpBytesTotal),
			atomic.LoadInt64(&udpPktsTotal), atomic.LoadInt64(&udpBytesTotal))
	}
}

func serveTCP(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("tcp accept: %v", err)
			return
		}
		go handleTCPConn(conn)
	}
}

func handleTCPConn(conn net.Conn) {
	atomic.AddInt64(&tcpConnsActive, 1)
	defer atomic.AddInt64(&tcpConnsActive, -1)
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return
	}
	conn.SetReadDeadline(time.Time{})

	fields := strings.Fields(line)
	if len(fields) == 0 {
		return
	}

	switch strings.ToUpper(fields[0]) {
	case "SOURCE":
		n := int64(64 * 1024 * 1024)
		if len(fields) > 1 {
			if v, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				n = v
			}
		}
		buf := make([]byte, 32*1024)
		for i := range buf {
			buf[i] = byte(i)
		}
		var sent int64
		for sent < n {
			chunk := buf
			if remain := n - sent; remain < int64(len(chunk)) {
				chunk = chunk[:remain]
			}
			w, err := conn.Write(chunk)
			sent += int64(w)
			atomic.AddInt64(&tcpBytesTotal, int64(w))
			if err != nil {
				return
			}
		}
	case "SINK":
		buf := make([]byte, 32*1024)
		start := time.Now()
		var total int64
		for {
			conn.SetReadDeadline(time.Now().Add(15 * time.Second))
			n, err := conn.Read(buf)
			total += int64(n)
			atomic.AddInt64(&tcpBytesTotal, int64(n))
			if err != nil {
				break
			}
		}
		elapsed := time.Since(start)
		fmt.Fprintf(conn, "OK %d %d\n", total, elapsed.Milliseconds())
	case "ECHO":
		io.Copy(conn, r)
	default:
		return
	}
}

func serveUDP(pc net.PacketConn) {
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			log.Printf("udp read: %v", err)
			return
		}
		atomic.AddInt64(&udpPktsTotal, 1)
		atomic.AddInt64(&udpBytesTotal, int64(n))
		pc.WriteTo(buf[:n], addr)
	}
}

// serveHTTP runs the web UI: a single page at "/" that drives download,
// upload, and latency tests via fetch()/XHR against the handlers below.
// Every request here is ordinary HTTP over TCP, so it exercises exactly
// the same multiproxy dataplane path as the raw protocol above - this
// exists purely to make that path drivable from a browser instead of
// requiring a shell with nc.
func serveHTTP(ln net.Listener) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/download", handleDownload)
	mux.HandleFunc("/upload", handleUpload)
	mux.HandleFunc("/ping", handlePing)
	mux.HandleFunc("/stats", handleStats)
	log.Printf("http: web UI exited: %v", http.Serve(ln, mux))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, indexHTML)
}

// handleDownload streams n bytes (query param "bytes", default 8MiB,
// capped at maxDownloadBytes) as fast as possible - the HTTP equivalent of
// the raw SOURCE command, drivable by a browser's fetch() with a
// ReadableStream reader to track live throughput.
func handleDownload(w http.ResponseWriter, r *http.Request) {
	n := int64(8 * 1024 * 1024)
	if v := r.URL.Query().Get("bytes"); v != "" {
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed > 0 {
			n = parsed
		}
	}
	if n > maxDownloadBytes {
		n = maxDownloadBytes
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
	w.Header().Set("Cache-Control", "no-store")
	buf := make([]byte, 32*1024)
	for i := range buf {
		buf[i] = byte(i)
	}
	var sent int64
	for sent < n {
		chunk := buf
		if remain := n - sent; remain < int64(len(chunk)) {
			chunk = chunk[:remain]
		}
		nw, err := w.Write(chunk)
		sent += int64(nw)
		atomic.AddInt64(&tcpBytesTotal, int64(nw))
		if err != nil {
			return
		}
	}
}

// handleUpload reads the request body to completion, timing it - the HTTP
// equivalent of the raw SINK command, drivable by a browser's
// XMLHttpRequest with upload.onprogress for live throughput.
func handleUpload(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	n, err := io.Copy(io.Discard, r.Body)
	atomic.AddInt64(&tcpBytesTotal, n)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	elapsed := time.Since(start)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"bytes":%d,"millis":%d}`, n, elapsed.Milliseconds())
}

// handlePing returns immediately with a tiny fixed body, for round-trip
// latency measurement from repeated timed fetch() calls.
func handlePing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")
	io.WriteString(w, "pong")
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"tcp_active":%d,"tcp_bytes_total":%d,"udp_pkts_total":%d,"udp_bytes_total":%d}`,
		atomic.LoadInt64(&tcpConnsActive), atomic.LoadInt64(&tcpBytesTotal),
		atomic.LoadInt64(&udpPktsTotal), atomic.LoadInt64(&udpBytesTotal))
}

const indexHTML = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>loadpeer</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 640px; margin: 2rem auto; padding: 0 1rem; }
  h1 { font-size: 1.3rem; }
  section { border: 1px solid #ccc; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
  button { font-size: 1rem; padding: 0.5rem 1rem; cursor: pointer; }
  input { font-size: 1rem; width: 8rem; }
  .result { font-family: ui-monospace, monospace; white-space: pre-wrap; margin-top: 0.5rem; }
  label { display: block; margin-bottom: 0.3rem; }
</style>
</head>
<body>
<h1>loadpeer</h1>
<p>Drives the same download/upload/latency tests as the raw TCP protocol, over plain HTTP.</p>

<section>
  <label>Download test - size (bytes): <input id="dlBytes" value="8000000"></label>
  <button onclick="runDownload()">Run download test</button>
  <div class="result" id="dlResult"></div>
</section>

<section>
  <label>Upload test - size (bytes): <input id="ulBytes" value="8000000"></label>
  <button onclick="runUpload()">Run upload test</button>
  <div class="result" id="ulResult"></div>
</section>

<section>
  <label>Latency test - count: <input id="pingCount" value="20"></label>
  <button onclick="runPing()">Run latency test</button>
  <div class="result" id="pingResult"></div>
</section>

<section>
  <button onclick="refreshStats()">Refresh server stats</button>
  <div class="result" id="statsResult"></div>
</section>

<script>
function fmtRate(bytes, ms) {
  if (ms <= 0) return "n/a";
  const kbps = (bytes / 1024) / (ms / 1000);
  return kbps.toFixed(1) + " KB/s";
}

async function runDownload() {
  const bytes = parseInt(document.getElementById('dlBytes').value, 10) || 8000000;
  const out = document.getElementById('dlResult');
  out.textContent = 'running...';
  const start = performance.now();
  try {
    const resp = await fetch('/download?bytes=' + bytes, {cache: 'no-store'});
    const reader = resp.body.getReader();
    let received = 0;
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      received += value.length;
      const elapsed = performance.now() - start;
      out.textContent = received + ' / ' + bytes + ' bytes, ' + fmtRate(received, elapsed);
    }
    const elapsed = performance.now() - start;
    out.textContent = 'done: ' + received + ' bytes in ' + elapsed.toFixed(0) + 'ms = ' + fmtRate(received, elapsed);
  } catch (e) {
    out.textContent = 'error: ' + e;
  }
}

function runUpload() {
  const bytes = parseInt(document.getElementById('ulBytes').value, 10) || 8000000;
  const out = document.getElementById('ulResult');
  out.textContent = 'preparing payload...';
  const payload = new Uint8Array(bytes);
  const xhr = new XMLHttpRequest();
  const start = performance.now();
  xhr.open('POST', '/upload');
  xhr.upload.onprogress = (e) => {
    const elapsed = performance.now() - start;
    out.textContent = e.loaded + ' / ' + bytes + ' bytes, ' + fmtRate(e.loaded, elapsed);
  };
  xhr.onload = () => {
    const elapsed = performance.now() - start;
    out.textContent = 'done: ' + xhr.responseText + ' (wall clock ' + elapsed.toFixed(0) + 'ms = ' + fmtRate(bytes, elapsed) + ')';
  };
  xhr.onerror = () => { out.textContent = 'error'; };
  out.textContent = 'uploading...';
  xhr.send(payload);
}

async function runPing() {
  const count = parseInt(document.getElementById('pingCount').value, 10) || 20;
  const out = document.getElementById('pingResult');
  const times = [];
  for (let i = 0; i < count; i++) {
    const start = performance.now();
    await fetch('/ping', {cache: 'no-store'});
    times.push(performance.now() - start);
    out.textContent = 'ping ' + (i + 1) + '/' + count + '...';
  }
  const min = Math.min(...times), max = Math.max(...times);
  const avg = times.reduce((a, b) => a + b, 0) / times.length;
  out.textContent = 'min ' + min.toFixed(1) + 'ms / avg ' + avg.toFixed(1) + 'ms / max ' + max.toFixed(1) + 'ms over ' + count + ' pings';
}

async function refreshStats() {
  const out = document.getElementById('statsResult');
  try {
    const resp = await fetch('/stats', {cache: 'no-store'});
    out.textContent = JSON.stringify(await resp.json(), null, 2);
  } catch (e) {
    out.textContent = 'error: ' + e;
  }
}
</script>
</body>
</html>
`
