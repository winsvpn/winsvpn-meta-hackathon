package carrier

import (
	"fmt"
	"net"
	"runtime"
	"syscall"
)

const (
	// ROUND 41 PACING EXPERIMENT (2026-09-20): the client default returns to
	// 8 MiB. The Round 39 4 MiB probe measured the tunnel-ingest upload at
	// 403-445 Mbps; the 8 MiB build's cloudflare uploads measured 700-790.
	// With the ingest tool now the app's primary target, this run measures
	// the ingest on 8 MiB directly to settle which buffer value the carrier
	// socket should ship with.
	DefaultUDPSocketBufferBytes = 8 << 20
)

// applyUDPSocketBuffers raises SO_RCVBUF/SO_SNDBUF and reads the granted
// sizes back with getsockopt. SetReadBuffer returning nil is not evidence
// the kernel granted the request: Linux clamps to rmem_max and still
// returns 0.
//
// This is the CLIENT pattern. The gateway in cmd/winn3-gateway REFUSES a
// grant below 4 MiB, because a gateway host is supposed to have had
// rmem_max raised by the installer. A phone or a laptop cannot raise
// net.core.rmem_max without root, and refusing there would make the
// client unusable on exactly the devices this product targets. So a
// short grant is reported (via the returned sizes and setErr) and the
// socket is left open. Callers that want to log the mismatch set
// UDPConfig.SocketBufferHook.
func applyUDPSocketBuffers(conn *net.UDPConn, requested int) (gotRead, gotWrite int, setErr error) {
	if conn == nil {
		return 0, 0, wrap(ErrConfig, "UDP socket buffers: no socket")
	}
	setReadErr := conn.SetReadBuffer(requested)
	setWriteErr := conn.SetWriteBuffer(requested)
	gotRead, readErr := udpSockoptInt(conn, syscall.SO_RCVBUF)
	gotWrite, writeErr := udpSockoptInt(conn, syscall.SO_SNDBUF)
	setErr = firstErr(setReadErr, setWriteErr, readErr, writeErr)
	return gotRead, gotWrite, setErr
}

func applyConfiguredUDPSocketBuffers(cfg *UDPConfig) error {
	if cfg.buffersApplied {
		return nil
	}
	if cfg.SocketBufferBytes < 0 {
		return wrap(ErrConfig, "SocketBufferBytes is negative")
	}
	if cfg.Conn == nil {
		return wrap(ErrConfig, "UDP socket buffers: no socket")
	}
	requested := cfg.SocketBufferBytes
	if requested == 0 {
		requested = DefaultUDPSocketBufferBytes
	}
	gotRead, gotWrite, setErr := applyUDPSocketBuffers(cfg.Conn, requested)
	cfg.buffersApplied = true
	cfg.socketBufferRequested = requested
	cfg.socketBufferRead = gotRead
	cfg.socketBufferWrite = gotWrite
	if cfg.SocketBufferHook != nil {
		cfg.SocketBufferHook(requested, gotRead, gotWrite, setErr)
	}
	return nil
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// socketBufferRequestUnits converts raw getsockopt accounting into the units
// passed to setsockopt. Linux and Android report twice the accepted request.
func socketBufferRequestUnits(goos string, granted int) int {
	if goos == "linux" || goos == "android" {
		return granted / 2
	}
	return granted
}

// shortUDPSocketGrant reports a clamped grant without refusing the socket.
// Raw grants remain unchanged in SocketBuffers and diagnostic output.
func shortUDPSocketGrant(requested, gotRead, gotWrite int) bool {
	if requested <= 0 {
		return false
	}
	return socketBufferRequestUnits(runtime.GOOS, gotRead) < requested ||
		socketBufferRequestUnits(runtime.GOOS, gotWrite) < requested
}

// FormatUDPSocketBufferGrant is the text a client log should print after
// the kernel grant is read back. DialUDP/NewUDP do not log themselves —
// this package is a library — so cmd/winn-datapath (and any other client)
// should print this from SocketBufferHook.
func FormatUDPSocketBufferGrant(requested, gotRead, gotWrite int, setErr error) string {
	if setErr != nil {
		return fmt.Sprintf(
			"UDP socket buffers: Set* error: %v (requested %d, granted read=%d write=%d); continuing because a client cannot raise rmem_max",
			setErr, requested, gotRead, gotWrite)
	}
	if shortUDPSocketGrant(requested, gotRead, gotWrite) {
		return fmt.Sprintf(
			"UDP socket buffers: short grant requested %d, granted read=%d write=%d; continuing because a client cannot raise rmem_max",
			requested, gotRead, gotWrite)
	}
	return fmt.Sprintf(
		"UDP socket buffers: requested %d, granted read=%d write=%d",
		requested, gotRead, gotWrite)
}
