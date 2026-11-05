package netdial

import (
	"net"
)

const (
	// DefaultQUICSocketBufferBytes is the SO_RCVBUF/SO_SNDBUF DialQUICPath
	// asks for on the UDP socket it opens. 8 MiB matches
	// winn3/carrier.DefaultUDPSocketBufferBytes and the gateway request so
	// the MASQUE/H3 client does not sit on the kernel default.
	//
	// A short grant is not a dial failure: a phone cannot raise
	// net.core.rmem_max. SetReadBuffer returning nil is not evidence the
	// kernel granted the request — callers that need the grant read it
	// back with happyUDPSockoptInt.
	DefaultQUICSocketBufferBytes = 8 << 20
)

func listenHappyUDP(network string, local net.IP) (*net.UDPConn, error) {
	socket, err := net.ListenUDP(network, &net.UDPAddr{IP: local})
	if err != nil {
		return nil, err
	}
	raiseHappyUDPSocketBuffers(socket)
	return socket, nil
}

func raiseHappyUDPSocketBuffers(conn *net.UDPConn) {
	if conn == nil {
		return
	}
	_ = conn.SetReadBuffer(DefaultQUICSocketBufferBytes)
	_ = conn.SetWriteBuffer(DefaultQUICSocketBufferBytes)
}
