// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SpeedMeterTest {
  @Test
  fun compactFitsTheIcon() {
    val cases =
        mapOf(
            0L to "0",
            -5L to "0",
            1L to "1B",
            999L to "999B",
            1_000L to "1K",
            1_234L to "1.2K",
            9_949L to "9.9K",
            12_345L to "12K",
            850_000L to "850K",
            999_499L to "999K",
            999_500L to "1M",
            1_240_000L to "1.2M",
            1_250_000L to "1.3M",
            12_000_000L to "12M",
            999_000_000L to "999M",
            1_500_000_000L to "1.5G",
        )
    for ((input, want) in cases) assertEquals("compact($input)", want, SpeedMeter.compact(input))
    for (n in generateSequence(1L) { it * 3 }.takeWhile { it < 100_000_000_000L }) {
      assertTrue("compact($n) too wide", SpeedMeter.compact(n).length <= 4)
    }
  }

  @Test
  fun readable() {
    assertEquals("0 B/s", SpeedMeter.readable(0))
    assertEquals("1.2 KB/s", SpeedMeter.readable(1_234))
    assertEquals("12.5 MB/s", SpeedMeter.readable(12_500_000))
  }

  /** Counters that advance in batches: 0, then two seconds' worth at once. */
  @Test
  fun windowSmoothsBatchedCounters() {
    val w = SpeedMeter.RateWindow(3_000)
    var rx = 0L
    var t = 0L
    val shown = mutableListOf<Long>()
    // 100 KB/s of real traffic, but the counter only moves every other second.
    for (i in 0..12) {
      if (i % 2 == 0) rx += 200_000
      w.add(t, rx, 0)?.let { shown += it.first }
      t += 1_000
    }
    // Once the window has filled, no reading is 0 or anywhere near double.
    shown.drop(3).forEach { assertTrue("rate $it", it in 60_000..140_000) }
  }

  @Test
  fun windowDropsToZeroWhenTrafficStops() {
    val w = SpeedMeter.RateWindow(3_000)
    var rx = 0L
    var t = 0L
    repeat(5) {
      rx += 100_000
      w.add(t, rx, 0)
      t += 1_000
    }
    var last: Long = -1
    repeat(4) {
      last = w.add(t, rx, 0)!!.first
      t += 1_000
    }
    assertEquals(0L, last)
  }

  @Test
  fun windowResetAndCounterDrop() {
    val w = SpeedMeter.RateWindow(3_000)
    assertEquals(null, w.add(0, 1_000_000, 0))
    assertEquals(1_000L to 0L, w.add(1_000, 1_001_000, 0))
    // After the screen was off: no average over the gap.
    w.reset()
    assertEquals(null, w.add(600_000, 9_000_000, 0))
    assertEquals(2_000L to 0L, w.add(601_000, 9_002_000, 0))
    // An interface went away and the sum fell: start again rather than show a negative rate.
    assertEquals(null, w.add(602_000, 5_000, 0))
    assertEquals(1_000L to 0L, w.add(603_000, 6_000, 0))
  }
}
