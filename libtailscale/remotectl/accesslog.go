// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package remotectl

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// accessLog is the append-only record of every remote access, one JSON object
// per line. When the file passes accessLogMaxSize it is rotated to a single
// ".1" generation, so the log is bounded at roughly twice that size while
// always keeping the most recent history.
//
// Nothing the HTTP API can reach writes to it except through append, and
// nothing reachable removes or truncates it; the app's own UI is the only
// thing that may clear it (ClearAccessLog).
type accessLog struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

func openAccessLog(path string) (*accessLog, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("remotectl: access log dir: %w", err)
	}
	a := &accessLog{path: path}
	if err := a.openLocked(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *accessLog) openLocked() error {
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("remotectl: open access log: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("remotectl: stat access log: %w", err)
	}
	a.f, a.size = f, st.Size()
	return nil
}

func (a *accessLog) append(e AccessEntry) {
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return
	}
	if a.size+int64(len(b)) > accessLogMaxSize {
		a.f.Close()
		if err := os.Rename(a.path, a.path+".1"); err != nil {
			log.Printf("remotectl: rotating access log: %v", err)
		}
		if err := a.openLocked(); err != nil {
			log.Printf("remotectl: %v", err)
			a.f = nil
			return
		}
	}
	n, err := a.f.Write(b)
	a.size += int64(n)
	if err != nil {
		log.Printf("remotectl: writing access log: %v", err)
	}
}

func (a *accessLog) close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f != nil {
		a.f.Close()
		a.f = nil
	}
}

// tail returns up to n most recent entries, oldest first.
func (a *accessLog) tail(n int) []AccessEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return readAccessTail(a.path, n)
}

// ReadAccessLog returns up to n most recent entries of the access log at path,
// oldest first. Works whether or not a server is running.
func ReadAccessLog(path string, n int) []AccessEntry {
	return readAccessTail(path, n)
}

// ClearAccessLog deletes the access log at path, including its rotated
// generation. Only the app calls this, in response to the user.
func ClearAccessLog(path string) error {
	for _, p := range []string{path, path + ".1"} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func readAccessTail(path string, n int) []AccessEntry {
	var out []AccessEntry
	for _, p := range []string{path + ".1", path} {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			var e AccessEntry
			if json.Unmarshal(sc.Bytes(), &e) == nil {
				out = append(out, e)
			}
		}
		f.Close()
	}
	if len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}
