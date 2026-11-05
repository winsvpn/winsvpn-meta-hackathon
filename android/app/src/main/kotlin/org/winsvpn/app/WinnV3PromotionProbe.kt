package org.winsvpn.app

/**
 * The self-starting promotion probe, Android edition of the host probe that
 * landed for Windows and Linux in `winn3_supervisor.cpp SendInnerPromotionProbe`.
 *
 * ## Why the probe exists at all
 *
 * The promotion gate is `gate == carrying AND rx_packets > 0`, computed beside
 * the engine's own counters, and `rx_packets` only advances once an inner
 * packet arrives FROM the gateway and is validated and delivered. Against a
 * reactive gateway (one that forwards but never initiates) nothing sends the
 * first inner packet pre-promotion: application traffic waits for native
 * start, the engine emits no inner probe, and a quiet host produces none
 * either — so the gate starves while a healthy session carries, and the
 * promotion window times out. That exact starvation was measured against the
 * GCP fleet gateway on 2026-08-22: gate carrying within 700 ms, then 30 s of
 * `rx_packets=0` and a refusal.
 *
 * This is the host's own first inner packet: ONE ICMP echo, sourced from the
 * session's inner assignment and addressed to the inner next hop. That pairing
 * is what keeps the /32 containment intact: the bootstrap posture routes
 * exactly ONE address, the inner next hop's /32, so the echo can only enter
 * the tunnel and can never escape onto the physical default route — and the
 * inner side of a FORWARD gateway answers IPv4 addressed to its own
 * assignment, which is the inner next hop, so the reflected echo satisfies
 * `rx_packets > 0` without widening anything.
 *
 * ## The Android injection path
 *
 * Apps cannot open raw ICMP sockets on Android, so this host cannot send the
 * echo the way the Windows host does (IcmpSendEcho2 through a route the
 * bootstrap posture pinned to the relay adapter). The platform's own
 * tunnel-protected path is [WinnV3AndroidIpPacketSeam.injectOutgoingPacket]:
 * the crafted packet joins the outbound queue exactly where a kernel-read tun
 * packet sits, the bridge pumps it to the engine as an ordinary `OP_INBOUND`,
 * and the engine's inner-IP validator sees a packet sourced from the session's
 * own assignment addressed to the inner next hop — which it accepts, the same
 * as any legitimate application packet. The reply comes back through the real
 * chain: gateway -> engine validator -> tun device write, which is the
 * delivery `rx_packets` counts.
 *
 * ## Bounds and authority
 *
 * The CALLER bounds the probe (attempt cap + interval) and treats it as
 * advisory: [WinnV3StagedStart] fires it at most
 * [WinnV3PromotionProbe.MAX_PROBE_ATTEMPTS] times across the promotion window,
 * and promotion still decides exclusively from the engine's own proof. The
 * window still fails closed when nothing comes back.
 */
internal object WinnV3PromotionProbe {

    /** 20-byte IPv4 header + 8-byte ICMP echo header + 8-byte payload. */
    const val PACKET_BYTES = 36

    const val MAX_PROBE_ATTEMPTS = 4

    /** 2.5-3 s between attempts, matching the Windows host's 3 s spacing. */
    const val PROBE_INTERVAL_MS = 3000L

    /**
     * Builds ONE minimal ICMP echo request: IPv4, TTL 64, protocol ICMP,
     * sourced from [innerV4] and addressed to [routerV4]. Both checksums are
     * computed and correct, because the gateway VM's kernel is the echo
     * responder and it drops a bad-checksum packet instead of answering it.
     *
     * Both addresses must be IPv4 literals. Parsing is [WinnV3Resolvers.ipv4Value],
     * the strict hand-rolled dotted-quad parser, and never `InetAddress.getByName`,
     * which would perform a NAME LOOKUP for anything that is not a literal,
     * inside the one code path whose whole subject is not leaking lookups.
     * Returns null when either address is not a literal, which the caller logs
     * and treats as an unsent probe.
     */
    fun buildEchoRequest(innerV4: String, routerV4: String, sequence: Int): ByteArray? {
        val src = parseV4(innerV4) ?: return null
        val dst = parseV4(routerV4) ?: return null
        val packet = ByteArray(PACKET_BYTES)
        packet[0] = 0x45 // version 4, IHL 5 (no options)
        packet[2] = ((PACKET_BYTES shr 8) and 0xff).toByte()
        packet[3] = (PACKET_BYTES and 0xff).toByte()
        packet[8] = 64 // TTL
        packet[9] = 1 // ICMP
        src.copyInto(packet, 12)
        dst.copyInto(packet, 16)
        writeIpHeaderChecksum(packet)
        packet[20] = 8 // ICMP echo request
        packet[21] = 0
        packet[24] = 0x57 // identifier
        packet[25] = 0x33
        packet[26] = ((sequence shr 8) and 0xff).toByte()
        packet[27] = (sequence and 0xff).toByte()
        "W3PROBE\u0000".toByteArray(Charsets.US_ASCII).copyInto(packet, 28)
        writeIcmpChecksum(packet, ICMP_OFFSET, PACKET_BYTES)
        return packet
    }

    /**
     * Sends one probe through [seam], or reports why it could not.
     *
     * [attempt] is 1-based and travels in the ICMP sequence field, so a
     * capture on either side of the gateway can tell the attempts apart.
     * Returns true only when the packet was handed to the seam.
     */
    fun send(
        seam: WinnV3AndroidIpPacketSeam?,
        innerAddress: String,
        innerNextHop: String,
        attempt: Int,
        onNote: (String) -> Unit,
    ): Boolean {
        if (seam == null) {
            onNote("no tun seam exists to send the promotion probe through")
            return false
        }
        val packet = buildEchoRequest(innerAddress, innerNextHop, attempt)
        if (packet == null) {
            onNote(
                "the promotion probe's inner assignment or next hop " +
                    "('$innerAddress' -> '$innerNextHop') is not an IPv4 literal"
            )
            return false
        }
        return seam.injectOutgoingPacket(packet, packet.size)
    }

    private const val ICMP_OFFSET = 20

    /**
     * The one strict literal parser in this path, shared rather than
     * re-implemented: [WinnV3Resolvers.ipv4Value] accepts exactly a dotted
     * quad and nothing else, so a hostname-shaped value is refused here
     * instead of being resolved.
     */
    private fun parseV4(text: String): ByteArray? {
        val value = WinnV3Resolvers.ipv4Value(text) ?: return null
        return byteArrayOf(
            ((value shr 24) and 0xff).toByte(),
            ((value shr 16) and 0xff).toByte(),
            ((value shr 8) and 0xff).toByte(),
            (value and 0xff).toByte(),
        )
    }

    /**
     * The 16-bit one's complement of the one's complement sum, the checksum
     * IPv4 and ICMP share (winn3/tun/ip.go checksum). Applied over a region
     * that already carries its checksum the result is 0, which is how the
     * unit tests verify each synthesized packet.
     */
    internal fun onesComplementSum(bytes: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        var n = length
        while (n > 1) {
            sum += (((bytes[i].toInt() and 0xff) shl 8) or (bytes[i + 1].toInt() and 0xff)).toLong()
            i += 2
            n -= 2
        }
        if (n == 1) sum += ((bytes[i].toInt() and 0xff) shl 8).toLong()
        while (sum shr 16 != 0L) {
            sum = (sum and 0xffff) + (sum shr 16)
        }
        return sum.toInt()
    }

    private fun writeIpHeaderChecksum(packet: ByteArray) {
        packet[10] = 0
        packet[11] = 0
        val checksum = onesComplementSum(packet, 0, 20).inv() and 0xffff
        packet[10] = ((checksum shr 8) and 0xff).toByte()
        packet[11] = (checksum and 0xff).toByte()
    }

    private fun writeIcmpChecksum(packet: ByteArray, offset: Int, end: Int) {
        packet[offset + 2] = 0
        packet[offset + 3] = 0
        val checksum = onesComplementSum(packet, offset, end - offset).inv() and 0xffff
        packet[offset + 2] = ((checksum shr 8) and 0xff).toByte()
        packet[offset + 3] = (checksum and 0xff).toByte()
    }
}
