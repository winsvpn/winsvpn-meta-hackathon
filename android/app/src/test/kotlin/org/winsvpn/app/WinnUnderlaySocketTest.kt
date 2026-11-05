package org.winsvpn.app

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class WinnUnderlaySocketTest {
    @Test
    fun connectedSocketKeepsItsPortAcrossRequestReplyExchanges() {
        val loopback = InetAddress.getByName("127.0.0.1")
        DatagramSocket(0, loopback).use { gateway ->
            DatagramSocket(0, loopback).use { client ->
                gateway.soTimeout = 2_000
                client.soTimeout = 2_000
                val port = client.localPort
                WinnAndroidEngineHost.connectUnderlaySocket(
                    client, "127.0.0.1:${gateway.localPort}",
                )
                assertTrue(client.isConnected)
                repeat(5) { attempt ->
                    val payload = byteArrayOf(0x57, attempt.toByte())
                    client.send(DatagramPacket(payload, payload.size))
                    val request = DatagramPacket(ByteArray(64), 64)
                    gateway.receive(request)
                    assertEquals(port, request.port)
                    gateway.send(DatagramPacket(
                        request.data, request.length, request.socketAddress,
                    ))
                    val response = DatagramPacket(ByteArray(64), 64)
                    client.receive(response)
                    assertEquals(gateway.localPort, response.port)
                    assertArrayEquals(payload, response.data.copyOf(response.length))
                    assertEquals(port, client.localPort)
                }
            }
        }
    }

    @Test
    fun rejectsAHostnameBeforeConnecting() {
        DatagramSocket().use { socket ->
            try {
                WinnAndroidEngineHost.connectUnderlaySocket(socket, "example.invalid:9111")
                fail("hostname endpoint was accepted")
            } catch (_: IllegalArgumentException) {
                assertFalse(socket.isConnected)
            }
        }
    }
}
