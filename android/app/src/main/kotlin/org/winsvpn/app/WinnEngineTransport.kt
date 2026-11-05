package org.winsvpn.app

import java.io.Closeable
import java.io.FileDescriptor
import java.io.IOException

/**
 * The duplex channel between this host process and the Winn Protocol engine
 * subprocess, plus the things the host must own on Android.
 *
 * These are interfaces, not concrete classes, so [WinnTunnelBridge] can be
 * driven both by an in-JVM double and by the real `winn-datapath` binary. Note
 * that a double alone proved insufficient: both lanes were green against their
 * own doubles while being mutually unusable. See WinnEngineInteropTest, which
 * drives the real binary with this framing.
 */
internal interface WinnEngineTransport : Closeable {
    /** Writes one frame. Implementations must be safe to call from many threads. */
    fun writeFrame(opcode: Int, payload: ByteArray)

    /**
     * Hands the protected UDP descriptor to the engine, BEFORE any frame.
     *
     * ORDERING IS THE CONTRACT, and it is not negotiable from this side.
     * `cmd/winn-datapath` run with `-receive-fd` calls `recvmsg` with a
     * ONE-BYTE data buffer before it serves a single frame, then hands the
     * stream to the frame reader. So the host must send exactly one byte with
     * the descriptor attached as SCM_RIGHTS ancillary data, and nothing else in
     * that `sendmsg`.
     *
     * Fusing the descriptor onto the Create frame -- which is what this host
     * did before the WNN3 convergence -- does not work: the engine's one-byte
     * `recvmsg` would take the first byte of the magic and leave the remaining
     * 15 header bytes queued, so the frame reader would start mid-header, see a
     * bad magic, and tear the channel down. A stream socket does not discard
     * the remainder, so the failure is a desync rather than a clean rejection.
     *
     * A control message cannot be sent on its own, which is why there is a byte
     * at all. Its value is not read by the engine; the engine only requires
     * that at least one byte arrived with the ancillary data.
     */
    fun sendDescriptor(fd: FileDescriptor)

    /** Sends UDP first and an optional protected TCP descriptor in one message. */
    fun sendDescriptors(fds: Array<FileDescriptor>) {
        if (fds.size != 1) throw IOException("this transport cannot send a protected TCP descriptor")
        sendDescriptor(fds[0])
    }

    /** Sends a protected UDP descriptor and a TCP request channel before Create. */
    fun sendDescriptorChannel(udp: FileDescriptor, channel: FileDescriptor) {
        throw IOException("this transport cannot send a protected TCP request channel")
    }

    /** Reads one frame, or null on a clean end of stream. */
    fun readFrame(): WinnFrame?

    /** 0 means block forever. */
    fun setReadTimeoutMs(timeoutMs: Int)
}

/**
 * The outer UDP socket, opened by the host and already excluded from the
 * tunnel's routing before this object exists.
 *
 * WHY THE HOST OWNS IT (WINN_PROTOCOL_PLATFORM_PLAN.md section 2, "The UDP
 * socket rule"):
 *
 *  - `VpnService.protect()` marks the kernel socket, not the descriptor
 *    number: netd sets the bypass-VPN `SO_MARK` on the `struct sock`. Route
 *    lookups for that socket then skip the VPN routing rules and leave over
 *    the physical underlay.
 *  - `dup()` and SCM_RIGHTS both produce a new descriptor onto the *same*
 *    open file description and the same `struct sock`, so the mark travels
 *    with the descriptor into the subprocess. That is what makes the handoff
 *    sound, and it has been verified on a real device: the received descriptor
 *    reported the same socket inode, the same bound port, and a readable
 *    `SO_MARK`, while a socket the child opened for itself could not reach the
 *    network at all.
 *  - A socket the engine opened for itself carries no mark. Its datagrams to
 *    the server would match the tunnel routes this service just installed, be
 *    written back into our own tun, be handed to the engine as inbound
 *    traffic, be encapsulated again, and re-emitted -- forever, with nothing
 *    ever leaving the device. That is the dead loop the plan warns about, and
 *    it is why the engine's configuration carries `allow_own_socket:false`.
 *  - AmneziaWG gets away with the reverse order (`GoBackend.awgTurnOn` opens
 *    the sockets, Kotlin protects them afterwards via `awgGetSocketV4/V6`)
 *    only because it runs in *this* process. A subprocess cannot be protected
 *    after the fact, so the order has to be inverted: open, protect, hand over.
 *
 * OWNERSHIP AFTER HANDOFF. The engine adopts the descriptor with
 * `net.FilePacketConn` and closes the original once it holds its own duplicate.
 * The host must therefore not treat its own close as optional cleanup: it is
 * closing its end of a shared open file description, which is safe, but the
 * engine's `Close` is what releases the socket.
 */
internal interface WinnUnderlaySocket : Closeable {
    val descriptor: FileDescriptor

    /**
     * True only when `VpnService.protect()` returned true *before* this object
     * was handed out. [WinnTunnelBridge] refuses to start the engine when this
     * is false, rather than shipping a socket that would loop.
     */
    val protectedBeforeHandoff: Boolean

    val localPort: Int
}

/**
 * The source and sink of the bytes that cross `Inbound` and `Outbound`.
 *
 * THIS IS THE PAYLOAD-SEMANTICS BOUNDARY, and it is the one thing a host can
 * get wrong in a way that puts cleartext on the network.
 *
 * The engine operates in one of two distinct modes:
 *
 * 1. Legacy Wrapper Mode (default when spawned without -winn3):
 *    The engine carries AmneziaWG outer datagrams: exactly the bytes the
 *    host's own AWG engine would otherwise have sent to, and received from, the
 *    gateway's UDP endpoint. It does NOT carry raw IP packets off the tun device.
 *    The distinction is structural: the legacy wrapper contains no internal
 *    wire protocol implementation, so a raw tun packet handed to it would be
 *    forwarded unencrypted. The legacy wrapper refuses payload "ip-packet" at
 *    create time (ErrPayloadUnimplemented) so misconfigured hosts fail safely.
 *
 * 2. Standalone Winn Protocol v3 Mode (spawned with -winn3):
 *    The engine implements full post-quantum authenticated tunnel cryptography
 *    natively (ML-KEM-768, X25519, ChaCha20-Poly1305, Blake3 demuxPRF). In this
 *    mode, the engine carries raw inner IP packets ("ip-packet") directly off
 *    the tun device (or tun-fd on Linux/Android) and encrypts them into Winn v3
 *    wire frames.
 *
 * WHAT ANDROID SUPPLIES. For legacy wrapper mode, an implementation of this
 * interface sits below the AmneziaWG engine and above the network:
 *
 *     apps -> tun -> [AmneziaWG engine] -> outer datagrams -> THIS SEAM
 *                                                              -> Winn engine
 *                                                              -> gateway
 *
 * For standalone v3 mode, Android VpnTunnelService supplies direct tun packets
 * ("ip-packet") to the native Winn v3 engine or hands the tun descriptor directly.
 *
 * WHY THERE WAS NO SEAM IMPLEMENTATION FOR LEGACY WRAPPER. The app's AmneziaWG
 * engine is GoBackend.awgTurnOn, which owns the tun device and opens its own
 * UDP sockets internally. Producing outer datagrams required either modifying
 * libwg-go or adding a loopback relay. Standalone v3 bypasses this restriction
 * completely by handling inner IP packets directly.
 */
internal interface WinnAwgDatagramSeam : Closeable {
    /**
     * Blocks for the next outer datagram the AWG engine wants sent to the
     * gateway, copies it into [buffer] and returns its length. Returns -1 when
     * the seam is finished.
     */
    fun readOutgoingDatagram(buffer: ByteArray): Int

    /**
     * Delivers one outer datagram received from the gateway back into the AWG
     * engine, exactly as if its own socket had received it.
     */
    fun writeIncomingDatagram(datagram: ByteArray, length: Int)

    /** [writeIncomingDatagram] for a slice. The default copies; implementations should not. */
    fun writeIncomingDatagram(datagram: ByteArray, offset: Int, length: Int) {
        if (offset == 0) {
            writeIncomingDatagram(datagram, length)
        } else {
            writeIncomingDatagram(datagram.copyOfRange(offset, offset + length), length)
        }
    }
}

/** The spawned engine subprocess and its already-accepted channel. */
internal interface WinnEngineProcess : Closeable {
    val transport: WinnEngineTransport
    fun isAlive(): Boolean
    fun describe(): String
}

/**
 * Everything [WinnTunnelBridge] needs from the Android service. Implemented
 * for real by [WinnAndroidEngineHost] and faked in unit tests.
 */
internal interface WinnProtectedStreamChannel : Closeable {
    val descriptor: FileDescriptor
}

internal interface WinnEngineHost {
    /**
     * Opens the outer UDP socket and protects it. Must not return an
     * unprotected socket -- see [WinnUnderlaySocket].
     */
    fun openProtectedUnderlaySocket(): WinnUnderlaySocket

    /** Returns an unconnected, protected TCP socket for v3 carrier fallback. */
    fun openProtectedStreamSocket(): WinnUnderlaySocket? = null

    /** Each engine request receives a newly protected, unconnected TCP socket. */
    fun openProtectedStreamChannel(): WinnProtectedStreamChannel? = null

    /**
     * Spawns the engine binary from `nativeLibraryDir` and returns once its
     * channel is connected and its peer credentials have been checked.
     */
    fun startEngineProcess(): WinnEngineProcess

    /**
     * The AmneziaWG outer-datagram seam, or null when this build has none. See
     * [WinnAwgDatagramSeam] for why null is the honest answer on Android today.
     */
    fun openAwgDatagramSeam(): WinnAwgDatagramSeam?

    fun onDebug(message: String)
    fun onWarning(message: String, error: Throwable?)
    fun onError(message: String, error: Throwable?)
}
