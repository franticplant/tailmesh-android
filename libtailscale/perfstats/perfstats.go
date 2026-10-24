// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package perfstats measures what the app itself costs: process and
// per-thread CPU time, memory, the Go runtime, and how often each periodic
// job ran. It is cheap enough to leave on: a periodic job pays one atomic add
// per run (Counter.Inc), and everything else is read only when someone asks
// (Snapshot), from /proc and runtime/metrics.
package perfstats

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// clkTck is USER_HZ, 100 on Android and essentially every Linux kernel.
const clkTck = 100.0

var (
	mu       sync.Mutex
	counters = map[string]*Counter{}
	// started is when this package was initialised: the Go side of the
	// process, which the app loads at start.
	started = time.Now()
)

// Counter counts runs of one periodic job.
type Counter struct {
	name string
	n    atomic.Uint64
}

// Inc records one run.
func (c *Counter) Inc() { c.n.Add(1) }

// NewCounter returns the counter for name, creating it on first use. Call it
// once (at package init or when the job starts), not per run.
func NewCounter(name string) *Counter {
	mu.Lock()
	defer mu.Unlock()
	if c, ok := counters[name]; ok {
		return c
	}
	c := &Counter{name: name}
	counters[name] = c
	return c
}

// Counts returns every counter's value by name.
func Counts() map[string]uint64 {
	mu.Lock()
	defer mu.Unlock()
	m := make(map[string]uint64, len(counters))
	for name, c := range counters {
		m[name] = c.n.Load()
	}
	return m
}

// Thread is one thread's CPU time and context switches.
type Thread struct {
	TID  int     `json:"tid"`
	Name string  `json:"name"`
	CPU  float64 `json:"cpuSeconds"`
	// Voluntary context switches: the thread slept (waited for a timer,
	// a socket, a lock) and was woken. The closest thing to "wakeups" an
	// app can read about itself.
	Voluntary   uint64 `json:"voluntarySwitches"`
	Involuntary uint64 `json:"involuntarySwitches"`
}

// ThreadGroup sums threads that share a name.
type ThreadGroup struct {
	Name      string  `json:"name"`
	Threads   int     `json:"threads"`
	CPU       float64 `json:"cpuSeconds"`
	Voluntary uint64  `json:"voluntarySwitches"`
}

// Stats is a snapshot of the process's cost.
type Stats struct {
	At               time.Time `json:"at"`
	ProcessUptimeSec float64   `json:"processUptimeSeconds"`
	GoUptimeSec      float64   `json:"goUptimeSeconds"`
	UserCPU          float64   `json:"userCpuSeconds"`
	SysCPU           float64   `json:"sysCpuSeconds"`
	CPU              float64   `json:"cpuSeconds"`
	// CPUPerHour is CPU seconds per hour of process uptime, on average.
	CPUPerHour  float64 `json:"cpuSecondsPerHour"`
	Threads     int     `json:"threads"`
	Voluntary   uint64  `json:"voluntarySwitches"`
	Involuntary uint64  `json:"involuntarySwitches"`
	RSSBytes    uint64  `json:"rssBytes"`
	// TopThreads are the threads with the most CPU time; ByName groups
	// all threads by name (Go's threads share the name of the thread that
	// created them, so "Go" is not one group).
	TopThreads []Thread          `json:"topThreads"`
	ByName     []ThreadGroup     `json:"threadsByName"`
	Go         map[string]uint64 `json:"go"`
	Jobs       map[string]uint64 `json:"jobs"`
}

// goMetrics are the runtime/metrics read into Stats.Go, by short name.
var goMetrics = map[string]string{
	"heapLiveBytes":   "/gc/heap/live:bytes",
	"heapGoalBytes":   "/gc/heap/goal:bytes",
	"heapAllocsBytes": "/gc/heap/allocs:bytes",
	"heapObjects":     "/gc/heap/objects:objects",
	"totalMemBytes":   "/memory/classes/total:bytes",
	"gcCycles":        "/gc/cycles/total:gc-cycles",
	"goroutines":      "/sched/goroutines:goroutines",
	"gomaxprocs":      "/sched/gomaxprocs:threads",
	"cgoCalls":        "/cgo/go-to-c-calls:calls",
}

// Snapshot reads the process's current cost. top limits TopThreads.
func Snapshot(top int) Stats {
	now := time.Now()
	s := Stats{
		At:          now,
		GoUptimeSec: now.Sub(started).Seconds(),
		Go:          map[string]uint64{},
		Jobs:        Counts(),
	}
	if st, err := os.ReadFile("/proc/self/stat"); err == nil {
		if f := statFields(st); len(f) > 19 {
			s.UserCPU = ticks(f[11])
			s.SysCPU = ticks(f[12])
			s.CPU = s.UserCPU + s.SysCPU
			if up := systemUptime(); up > 0 {
				s.ProcessUptimeSec = up - ticks(f[19])
			}
		}
	}
	if s.ProcessUptimeSec > 0 {
		s.CPUPerHour = s.CPU / s.ProcessUptimeSec * 3600
	}
	if st, err := os.ReadFile("/proc/self/status"); err == nil {
		if kb, ok := statusValue(st, "VmRSS:"); ok {
			s.RSSBytes = kb * 1024
		}
	}

	threads := readThreads()
	s.Threads = len(threads)
	groups := map[string]*ThreadGroup{}
	for _, t := range threads {
		s.Voluntary += t.Voluntary
		s.Involuntary += t.Involuntary
		g := groups[t.Name]
		if g == nil {
			g = &ThreadGroup{Name: t.Name}
			groups[t.Name] = g
		}
		g.Threads++
		g.CPU += t.CPU
		g.Voluntary += t.Voluntary
	}
	sort.Slice(threads, func(i, j int) bool { return threads[i].CPU > threads[j].CPU })
	if top > 0 && len(threads) > top {
		threads = threads[:top]
	}
	s.TopThreads = threads
	for _, g := range groups {
		s.ByName = append(s.ByName, *g)
	}
	sort.Slice(s.ByName, func(i, j int) bool { return s.ByName[i].CPU > s.ByName[j].CPU })

	samples := make([]metrics.Sample, 0, len(goMetrics))
	names := make([]string, 0, len(goMetrics))
	for short, name := range goMetrics {
		samples = append(samples, metrics.Sample{Name: name})
		names = append(names, short)
	}
	metrics.Read(samples)
	for i, smp := range samples {
		if smp.Value.Kind() == metrics.KindUint64 {
			s.Go[names[i]] = smp.Value.Uint64()
		}
	}
	s.Go["numCPU"] = uint64(runtime.NumCPU())
	return s
}

// readThreads lists the process's threads from /proc/self/task.
func readThreads() []Thread {
	dirs, _ := filepath.Glob("/proc/self/task/*")
	out := make([]Thread, 0, len(dirs))
	for _, d := range dirs {
		tid, err := strconv.Atoi(filepath.Base(d))
		if err != nil {
			continue
		}
		st, err := os.ReadFile(d + "/stat")
		if err != nil {
			continue
		}
		t := Thread{TID: tid, Name: commOf(st)}
		if f := statFields(st); len(f) > 12 {
			t.CPU = ticks(f[11]) + ticks(f[12])
		}
		if status, err := os.ReadFile(d + "/status"); err == nil {
			t.Voluntary, _ = statusValue(status, "voluntary_ctxt_switches:")
			t.Involuntary, _ = statusValue(status, "nonvoluntary_ctxt_switches:")
		}
		out = append(out, t)
	}
	return out
}

// statFields splits a /proc stat line after the parenthesised comm, which
// may itself contain spaces: index 0 is field 3 (state).
func statFields(st []byte) []string {
	i := bytes.LastIndexByte(st, ')')
	if i < 0 || i+2 >= len(st) {
		return nil
	}
	return strings.Fields(string(st[i+2:]))
}

func commOf(st []byte) string {
	i := bytes.IndexByte(st, '(')
	j := bytes.LastIndexByte(st, ')')
	if i < 0 || j <= i {
		return ""
	}
	return string(st[i+1 : j])
}

func ticks(s string) float64 {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return float64(n) / clkTck
}

// statusValue returns the number after key in a /proc status file.
func statusValue(status []byte, key string) (uint64, bool) {
	// Keys start a line; "voluntary_ctxt_switches:" is also inside
	// "nonvoluntary_ctxt_switches:".
	i := bytes.Index(status, []byte("\n"+key))
	if i < 0 {
		return 0, false
	}
	rest := status[i+1+len(key):]
	if nl := bytes.IndexByte(rest, '\n'); nl >= 0 {
		rest = rest[:nl]
	}
	f := strings.Fields(string(rest))
	if len(f) == 0 {
		return 0, false
	}
	n, err := strconv.ParseUint(f[0], 10, 64)
	return n, err == nil
}

// systemUptime is the time since boot, the clock /proc/self/stat's start
// time counts on. The app sandbox can't read /proc/uptime, so it comes from
// CLOCK_BOOTTIME.
func systemUptime() float64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0
	}
	return float64(ts.Sec) + float64(ts.Nsec)/1e9
}
