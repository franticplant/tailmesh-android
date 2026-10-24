// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Command tailmesh-ctl drives a phone's Tailmesh remote-control endpoint
// (Settings -> Remote control & debugging) from another machine.
//
//	tailmesh-ctl -addr 10.146.109.63:7373 login            # approve on the phone
//	tailmesh-ctl login -password                           # or sign in with the password
//	tailmesh-ctl status
//	tailmesh-ctl methods
//	tailmesh-ctl call upstreams.list
//	tailmesh-ctl call apps.bind packageName=org.mozilla.firefox upstreamId=upstream-...
//	tailmesh-ctl call capture.start mode=all
//	tailmesh-ctl call capture.stop
//	tailmesh-ctl pull /data/user/0/.../captures/capture-....pcapng
//	tailmesh-ctl logs -f -grep flow-
//	tailmesh-ctl profile -seconds 20 -o cpu.pprof
//	tailmesh-ctl update tailmesh-v0.4.1-arm64-v8a.apk         # needs "Allow remote updates" on
//	tailmesh-ctl shell exec 'ls files'                       # needs "Allow remote shell" on
//
// The session token is cached per address in the user config directory, so
// later commands need no flags beyond -addr. Set TAILMESH_ADDR to skip -addr.
// See docs/features/04-remote-control.md for the API itself.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var (
	addr   = flag.String("addr", envOr("TAILMESH_ADDR", "127.0.0.1:7373"), "phone's remote-control address")
	client = &http.Client{Timeout: 0}
)

func main() {
	flag.Usage = usage
	flag.Parse()
	if flag.NArg() == 0 {
		usage()
		os.Exit(2)
	}
	cmd, args := flag.Arg(0), flag.Args()[1:]
	var err error
	switch cmd {
	case "login":
		err = login(args)
	case "logout":
		err = logout()
	case "status":
		err = getJSON("/v1/status")
	case "methods":
		err = methods()
	case "call":
		err = call(args)
	case "logs":
		err = logs(args)
	case "access-log":
		err = getJSON("/v1/access-log?n=200")
	case "pull":
		err = pull(args)
	case "profile":
		err = profile(args)
	case "update":
		err = update(args)
	case "shell":
		err = shell(args)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "tailmesh-ctl:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: tailmesh-ctl [-addr host:port] <command> [args]

commands:
  login [-password] [-client name]   get a session (approve on the phone, or password)
  logout                             end this session
  status                             session and server status
  methods                            list every callable method
  call <method> [k=v ...|'{json}']   call a method; v may be JSON (true, 3, ["a"])
  logs [-f] [-grep s] [-since n|10m|15:04] [-level l] [-component c] [-v] [-clear]
                                     app and engine logs
  access-log                         recent entries of the phone's access log
  pull <device path> [-o file]       download a capture or export
  profile [-seconds n] [-kind k] -o  Go pprof profile (profile, heap, goroutine, ...)
  update <apk>                       install a newer build signed with the same key
  shell [open|exec 'cmd'|end|log]    development builds: run commands, approved on the phone;
                                     with no arguments, one command per line
`)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func base() string { return "http://" + *addr }

// ---------------------------------------------------------------------------
// token cache
// ---------------------------------------------------------------------------

func tokenPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "tailmesh", "ctl-tokens", strings.NewReplacer(":", "_", "/", "_").Replace(*addr))
}

func token() (string, error) {
	b, err := os.ReadFile(tokenPath())
	if err != nil {
		return "", fmt.Errorf("not logged in to %s; run: tailmesh-ctl -addr %s login", *addr, *addr)
	}
	return strings.TrimSpace(string(b)), nil
}

func saveToken(tok string) error {
	p := tokenPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(tok+"\n"), 0o600)
}

// ---------------------------------------------------------------------------
// commands
// ---------------------------------------------------------------------------

func login(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	usePassword := fs.Bool("password", false, "sign in with the password (TAILMESH_PASSWORD or prompt)")
	name := fs.String("client", hostname(), "name shown on the phone")
	fs.Parse(args)

	if *usePassword {
		pw := os.Getenv("TAILMESH_PASSWORD")
		if pw == "" {
			fmt.Fprint(os.Stderr, "Password: ")
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			pw = strings.TrimRight(line, "\r\n")
		}
		var out struct {
			Token   string `json:"token"`
			Control bool   `json:"control"`
			Error   string `json:"error"`
		}
		if err := post("/v1/auth/login", "", map[string]string{"client": *name, "password": pw}, &out); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "logged in (%s)\n", scopeWord(out.Control))
		return saveToken(out.Token)
	}

	var req struct {
		RequestID string `json:"requestId"`
		Code      string `json:"code"`
	}
	if err := post("/v1/auth/request", "", map[string]string{"client": *name}, &req); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Approve \"%s\" on the phone. It should show the code %s\n", *name, req.Code)
	for {
		resp, err := client.Get(base() + "/v1/auth/request/" + req.RequestID)
		if err != nil {
			return err
		}
		var out struct {
			Status  string `json:"status"`
			Token   string `json:"token"`
			Control bool   `json:"control"`
			Error   string `json:"error"`
		}
		err = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if err != nil {
			return err
		}
		switch out.Status {
		case "pending":
			continue
		case "approved":
			fmt.Fprintf(os.Stderr, "approved (%s)\n", scopeWord(out.Control))
			return saveToken(out.Token)
		case "":
			return errors.New(out.Error)
		default:
			return fmt.Errorf("request %s", out.Status)
		}
	}
}

func scopeWord(control bool) string {
	if control {
		return "control"
	}
	return "read-only"
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "tailmesh-ctl"
	}
	return h
}

func logout() error {
	tok, err := token()
	if err != nil {
		return err
	}
	_ = post("/v1/auth/logout", tok, nil, nil)
	return os.Remove(tokenPath())
}

func methods() error {
	tok, err := token()
	if err != nil {
		return err
	}
	var ms []struct {
		Name        string            `json:"name"`
		Mutating    bool              `json:"mutating"`
		Description string            `json:"description"`
		Params      map[string]string `json:"params"`
	}
	if err := get("/v1/methods", tok, &ms); err != nil {
		return err
	}
	for _, m := range ms {
		mark := "read "
		if m.Mutating {
			mark = "write"
		}
		fmt.Printf("%s  %-32s %s\n", mark, m.Name, m.Description)
		for k, v := range m.Params {
			fmt.Printf("       %-30s %s\n", "  "+k, v)
		}
	}
	return nil
}

// call parses "k=v" pairs into a JSON object; each v is used as JSON when it
// parses as JSON (true, 3, ["a","b"], {"x":1}) and as a string otherwise. A
// single argument that is itself a JSON object is sent as-is.
func call(args []string) error {
	if len(args) == 0 {
		return errors.New("call needs a method name; see: tailmesh-ctl methods")
	}
	tok, err := token()
	if err != nil {
		return err
	}
	method, rest := args[0], args[1:]
	body := map[string]any{}
	if len(rest) == 1 && strings.HasPrefix(strings.TrimSpace(rest[0]), "{") {
		if err := json.Unmarshal([]byte(rest[0]), &body); err != nil {
			return fmt.Errorf("arguments: %w", err)
		}
	} else {
		for _, kv := range rest {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				return fmt.Errorf("argument %q is not key=value", kv)
			}
			if v == "@-" {
				b, err := io.ReadAll(os.Stdin)
				if err != nil {
					return err
				}
				v = string(b)
			} else if strings.HasPrefix(v, "@") {
				b, err := os.ReadFile(v[1:])
				if err != nil {
					return err
				}
				v = string(b)
			}
			var parsed any
			if json.Unmarshal([]byte(v), &parsed) == nil {
				body[k] = parsed
			} else {
				body[k] = v
			}
		}
	}
	return callMethod(tok, method, body)
}

func callMethod(tok, method string, body map[string]any) error {
	var out json.RawMessage
	if err := post("/v1/call/"+url.PathEscape(method), tok, body, &out); err != nil {
		return err
	}
	return printJSON(out)
}

func logs(args []string) error {
	fs := flag.NewFlagSet("logs", flag.ExitOnError)
	follow := fs.Bool("f", false, "follow")
	grep := fs.String("grep", "", "only lines containing this")
	since := fs.String("since", "", "only lines after this sequence number, in the last duration (10m), or from a time (15:04, 15:04:05 today, or RFC 3339)")
	level := fs.String("level", "", "error, warn, info, debug or verbose: this level and more severe (Go lines: error if they mention an error or failure)")
	component := fs.String("component", "", "comma-separated components (prefix): an app log tag, or flow, wireguard, magicsock, control, ...")
	verbose := fs.Bool("v", false, "show each line's level and component")
	clear := fs.Bool("clear", false, "empty the phone's log buffer (needs control) and exit")
	fs.Parse(args)
	tok, err := token()
	if err != nil {
		return err
	}
	if *clear {
		return callMethod(tok, "logs.clear", map[string]any{})
	}
	q := url.Values{}
	if *since != "" {
		s, err := sinceParam(*since, time.Now())
		if err != nil {
			return err
		}
		q.Set("since", s)
	}
	if *grep != "" {
		q.Set("grep", *grep)
	}
	if *level != "" {
		q.Set("level", *level)
	}
	if *component != "" {
		q.Set("component", *component)
	}
	if *follow {
		q.Set("follow", "1")
	}
	resp, err := do("GET", "/v1/logs?"+q.Encode(), tok, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var l struct {
			Time      time.Time `json:"time"`
			Source    string    `json:"source"`
			Text      string    `json:"text"`
			Level     string    `json:"level"`
			Component string    `json:"component"`
		}
		if json.Unmarshal(sc.Bytes(), &l) != nil {
			continue
		}
		if *verbose {
			fmt.Printf("%s %-6s %s %-18s %s\n", l.Time.Local().Format("15:04:05.000"), l.Source, l.Level, l.Component, l.Text)
		} else {
			fmt.Printf("%s %-6s %s\n", l.Time.Format("15:04:05.000"), l.Source, l.Text)
		}
	}
	return sc.Err()
}

// sinceParam turns -since into the server's since: a sequence number or
// duration as given, a clock time today (local) as RFC 3339.
func sinceParam(s string, now time.Time) (string, error) {
	if _, err := strconv.ParseUint(s, 10, 64); err == nil {
		return s, nil
	}
	if _, err := time.ParseDuration(s); err == nil {
		return s, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC().Format(time.RFC3339), nil
	}
	for _, layout := range []string{"15:04:05", "15:04"} {
		if t, err := time.ParseInLocation(layout, s, now.Location()); err == nil {
			y, m, d := now.Date()
			t = time.Date(y, m, d, t.Hour(), t.Minute(), t.Second(), 0, now.Location())
			return t.UTC().Format(time.RFC3339), nil
		}
	}
	return "", fmt.Errorf("-since %q: want a sequence number, a duration (10m), a time (15:04) or RFC 3339", s)
}

func pull(args []string) error {
	fs := flag.NewFlagSet("pull", flag.ExitOnError)
	out := fs.String("o", "", "output file (default: the file's own name)")
	if len(args) == 0 {
		return errors.New("pull needs a device path, e.g. from: tailmesh-ctl call capture.list")
	}
	path := args[0]
	fs.Parse(args[1:])
	if *out == "" {
		*out = filepath.Base(path)
	}
	tok, err := token()
	if err != nil {
		return err
	}
	return download("/v1/files?path="+url.QueryEscape(path), tok, *out)
}

func profile(args []string) error {
	fs := flag.NewFlagSet("profile", flag.ExitOnError)
	kind := fs.String("kind", "profile", "profile (CPU), heap, goroutine, allocs, block, mutex, trace")
	secs := fs.Int("seconds", 20, "duration for profile and trace")
	out := fs.String("o", "", "output file")
	fs.Parse(args)
	if *out == "" {
		*out = *kind + ".pprof"
	}
	tok, err := token()
	if err != nil {
		return err
	}
	path := "/debug/pprof/" + *kind
	if *kind == "profile" || *kind == "trace" {
		path += "?seconds=" + strconv.Itoa(*secs)
	} else if *kind == "goroutine" {
		path += "?debug=2"
	}
	if err := download(path, tok, *out); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s; inspect with: go tool pprof %s\n", *out, *out)
	return nil
}

// update uploads an APK for the app to install over itself. The phone checks
// it (same package, same signing key, not older) before installing; once the
// install starts the app restarts, so the connection drops shortly after.
func update(args []string) error {
	if len(args) != 1 {
		return errors.New("update needs an APK path")
	}
	f, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer f.Close()
	tok, err := token()
	if err != nil {
		return err
	}
	resp, err := doBody("POST", "/v1/app/update", tok, f, "application/vnd.android.package-archive")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return printJSON(b)
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

func do(method, path, tok string, body any) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	return doBody(method, path, tok, rd, "application/json")
}

func doBody(method, path, tok string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := http.NewRequest(method, base()+path, body)
	if err != nil {
		return nil, err
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		var e struct {
			Error string `json:"error"`
		}
		b, _ := io.ReadAll(resp.Body)
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			return nil, fmt.Errorf("%s (HTTP %d)", e.Error, resp.StatusCode)
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return resp, nil
}

func get(path, tok string, out any) error {
	resp, err := do("GET", path, tok, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

func getJSON(path string) error {
	tok, err := token()
	if err != nil {
		return err
	}
	var out json.RawMessage
	if err := get(path, tok, &out); err != nil {
		return err
	}
	return printJSON(out)
}

// post sends body and decodes the response into out. For /v1/call the
// envelope {"ok":true,"result":...} is unwrapped to the result.
func post(path, tok string, body, out any) error {
	resp, err := do("POST", path, tok, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		return nil
	}
	if strings.HasPrefix(path, "/v1/call/") {
		var env struct {
			Result json.RawMessage `json:"result"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
			return err
		}
		*(out.(*json.RawMessage)) = env.Result
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func download(path, tok, out string) error {
	resp, err := do("GET", path, tok, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		fmt.Fprintf(os.Stderr, "%s: %d bytes\n", out, n)
	}
	return err
}

func printJSON(raw json.RawMessage) error {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		os.Stdout.Write(raw)
		fmt.Println()
		return nil
	}
	buf.WriteByte('\n')
	_, err := buf.WriteTo(os.Stdout)
	return err
}
