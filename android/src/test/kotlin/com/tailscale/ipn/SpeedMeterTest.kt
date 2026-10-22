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
}
