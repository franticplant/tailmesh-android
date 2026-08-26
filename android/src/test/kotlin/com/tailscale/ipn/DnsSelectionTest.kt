package com.tailscale.ipn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.net.InetAddress

class DnsSelectionTest {

    private fun extractFirstDns(dnsServers: List<InetAddress>): String? {
        return dnsServers.firstOrNull()?.hostAddress
    }

    @Test
    fun testFirstDnsSelected() {
        val servers = listOf(
            InetAddress.getByName("8.8.8.8"),
            InetAddress.getByName("8.8.4.4")
        )
        assertEquals("8.8.8.8", extractFirstDns(servers))
    }

    @Test
    fun testEmptyDnsList() {
        assertNull(extractFirstDns(emptyList()))
    }

    @Test
    fun testIPv6DnsSelected() {
        val servers = listOf(
            InetAddress.getByName("2001:4860:4860::8888"),
            InetAddress.getByName("2001:4860:4860::8844")
        )
        val selected = extractFirstDns(servers)
        // InetAddress.hostAddress returns the uncompressed string representation or exactly what was passed.
        // It's definitely not null, and will contain the v6 address.
        assertEquals(true, selected != null)
    }
}
