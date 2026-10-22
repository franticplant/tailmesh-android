// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// shell drives the remote shell of a development build:
//
// By default the phone approves every command, showing it, and exec waits
// for that; a phone set to approve a whole shell instead needs "shell open"
// first:
//
//	tailmesh-ctl shell open [-minutes 15]     ask; approve on the phone
//	tailmesh-ctl shell exec 'ls -la' [-timeout 60] [-stdin file]
//	tailmesh-ctl shell                        one command per line until EOF
//	tailmesh-ctl shell end
//	tailmesh-ctl shell log
//
// Every command is still one request, run with sh -c and logged on the phone
// before it starts; the interactive form just sends each line in turn, so
// there is no state (cd, variables) between lines.
func shell(args []string) error {
	tok, err := token()
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return shellRepl(tok)
	}
	switch args[0] {
	case "open":
		fs := flag.NewFlagSet("shell open", flag.ExitOnError)
		minutes := fs.Int("minutes", 15, "how long the shell stays open (the phone caps it)")
		fs.Parse(args[1:])
		return shellOpen(tok, *minutes)
	case "exec":
		fs := flag.NewFlagSet("shell exec", flag.ExitOnError)
		timeout := fs.Int("timeout", 60, "seconds before the command is killed (max 600)")
		stdinPath := fs.String("stdin", "", "file to send as the command's stdin ('-' for this stdin)")
		fs.Parse(args[1:])
		if fs.NArg() == 0 {
			return errors.New("usage: tailmesh-ctl shell exec [-timeout s] [-stdin file] 'command'")
		}
		var stdin string
		if *stdinPath != "" {
			var b []byte
			if *stdinPath == "-" {
				b, err = io.ReadAll(os.Stdin)
			} else {
				b, err = os.ReadFile(*stdinPath)
			}
			if err != nil {
				return err
			}
			stdin = string(b)
		}
		code, err := shellExec(tok, strings.Join(fs.Args(), " "), *timeout, stdin)
		if err != nil {
			return err
		}
		if code != 0 {
			os.Exit(min(max(code, 1), 255))
		}
		return nil
	case "end":
		return post("/v1/shell/end", tok, struct{}{}, nil)
	case "log":
		return getJSON("/v1/shell/log?n=200")
	default:
		return errors.New("usage: tailmesh-ctl shell [open [-minutes n] | exec 'cmd' | end | log]")
	}
}

func shellOpen(tok string, minutes int) error {
	var req struct {
		ID      string `json:"id"`
		Code    string `json:"code"`
		Minutes int    `json:"minutes"`
	}
	if err := post("/v1/shell/request", tok, map[string]int{"minutes": minutes}, &req); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Allow the shell on the phone (unlocked). It should show the code %s\n", req.Code)
	for {
		var out struct {
			Status string    `json:"status"`
			Until  time.Time `json:"until"`
		}
		if err := get("/v1/shell/request/"+req.ID, tok, &out); err != nil {
			return err
		}
		switch out.Status {
		case "pending":
			continue
		case "approved":
			fmt.Fprintf(os.Stderr, "shell open until %s\n", out.Until.Local().Format("15:04"))
			return nil
		default:
			return fmt.Errorf("shell request %s", out.Status)
		}
	}
}

func shellExec(tok, cmd string, timeout int, stdin string) (int, error) {
	var out struct {
		Seq             int64  `json:"seq"`
		Exit            int    `json:"exit"`
		DurationMs      int64  `json:"durationMs"`
		Stdout          string `json:"stdout"`
		Stderr          string `json:"stderr"`
		StdoutTruncated bool   `json:"stdoutTruncated"`
		StderrTruncated bool   `json:"stderrTruncated"`
		Note            string `json:"note"`
	}
	fmt.Fprintln(os.Stderr, "[waiting for the phone if it approves each command]")
	body := map[string]any{"cmd": cmd, "timeoutSeconds": timeout}
	if stdin != "" {
		body["stdin"] = stdin
	}
	if err := post("/v1/shell/exec", tok, body, &out); err != nil {
		return -1, err
	}
	os.Stdout.WriteString(out.Stdout)
	os.Stderr.WriteString(out.Stderr)
	if out.StdoutTruncated || out.StderrTruncated {
		fmt.Fprintln(os.Stderr, "[output truncated at 1 MiB]")
	}
	if out.Note != "" {
		fmt.Fprintln(os.Stderr, "["+out.Note+"]")
	}
	return out.Exit, nil
}

func shellRepl(tok string) error {
	var st struct {
		ShellAvailable   bool            `json:"shellAvailable"`
		ShellApproveEach bool            `json:"shellApproveEach"`
		ShellUntil       json.RawMessage `json:"shellUntil"`
	}
	if err := get("/v1/status", tok, &st); err != nil {
		return err
	}
	if !st.ShellAvailable {
		return errors.New("this phone offers no shell (development builds, with \"Allow remote shell\" on)")
	}
	if st.ShellApproveEach {
		fmt.Fprintln(os.Stderr, "each command waits for Run on the phone")
	} else if string(st.ShellUntil) == "null" || len(st.ShellUntil) == 0 {
		if err := shellOpen(tok, 15); err != nil {
			return err
		}
	}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 64<<10), 64<<10)
	for {
		fmt.Fprint(os.Stderr, "tailmesh$ ")
		if !in.Scan() {
			fmt.Fprintln(os.Stderr)
			return in.Err()
		}
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		if line == "exit" {
			if st.ShellApproveEach {
				return nil
			}
			return post("/v1/shell/end", tok, struct{}{}, nil)
		}
		code, err := shellExec(tok, line, 60, "")
		if err != nil {
			fmt.Fprintln(os.Stderr, "tailmesh-ctl:", err)
			continue
		}
		if code != 0 {
			fmt.Fprintf(os.Stderr, "[exit %d]\n", code)
		}
	}
}
