// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * How often each periodic job on the Kotlin side ran, for remote control's perf.stats (the Go
 * side's are in libtailscale/perfstats). One map lookup and an atomic add per run; the jobs it
 * counts run at most once a second.
 */
object PerfCounters {
  private val counts = ConcurrentHashMap<String, AtomicLong>()

  fun inc(name: String) {
    counts.getOrPut(name) { AtomicLong() }.incrementAndGet()
  }

  fun snapshot(): Map<String, Long> = counts.mapValues { it.value.get() }.toSortedMap()
}
