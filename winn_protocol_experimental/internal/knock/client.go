package knock

import (
	"context"
	"fmt"
	"net"
	"time"
)

// Send builds one SPA knock datagram and transmits it to addr over a fresh
// UDP socket that this function opens and closes.
//
// It does not wait for a reply, because the server side of this package
// never sends one on any path - success and failure look identical on the
// wire (see the package doc), so waiting would only teach an observer that
// this client behaves differently after a real knock than after silence.
// Callers should attempt the real connection shortly after Send returns; a
// captured, replayed copy of the same datagram will not open the port a
// second time (see Gate's replay handling), so nothing is lost by the knock
// itself being observable in flight.
//
// Send is not appropriate wherever internal/carrier's supplied-socket
// dialers are required instead of an ordinary net.Dial - notably Android,
// where an unprotected socket can loop packets back into the tunnel it is
// trying to establish (see internal/carrier/supplied_socket.go). Use
// SendVia with an already-protected socket there.
func Send(ctx context.Context, addr string, key []byte, packetSize int, opts Options) error {
	packet, err := Build(key, packetSize, time.Now(), opts)
	if err != nil {
		return err
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return fmt.Errorf("knock: dial %s: %w", addr, err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(deadline)
	}
	if _, err := conn.Write(packet); err != nil {
		return fmt.Errorf("knock: write: %w", err)
	}
	return nil
}

// SendVia writes one SPA knock datagram to addr over an already-established
// PacketConn - for example one already passed through a platform's
// protect() call, or one about to be reused for the real dial. Prefer this
// over Send whenever such a socket is available.
func SendVia(conn net.PacketConn, addr net.Addr, key []byte, packetSize int, opts Options) error {
	packet, err := Build(key, packetSize, time.Now(), opts)
	if err != nil {
		return err
	}
	if _, err := conn.WriteTo(packet, addr); err != nil {
		return fmt.Errorf("knock: write: %w", err)
	}
	return nil
}
