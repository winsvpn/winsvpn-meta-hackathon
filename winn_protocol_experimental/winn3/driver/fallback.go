package driver

import (
	"context"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
)

// MigrateSilentUDP starts a fresh TCP initiation only if UDP has produced no
// authenticated response. The dial runs beside the existing UDP handshake, so
// a responsive UDP path keeps its original connect timing.
func MigrateSilentUDP(ctx context.Context, loop *Loop,
	dial func(context.Context) (carrier.Conn, error)) {
	timer := loop.clock.NewTimer(850 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C():
	}
	if loop.Session().HasAuthenticatedReply() {
		return
	}
	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	conn, err := dial(dialCtx)
	cancel()
	if err != nil {
		return
	}
	if ctx.Err() != nil || loop.Session().HasAuthenticatedReply() {
		_ = conn.Close()
		return
	}
	old := loop.Carrier()
	if old == nil || old.Class() != carrier.ClassUDP {
		_ = conn.Close()
		return
	}
	migrated, err := loop.MigrateSilentInitiation(conn)
	if err != nil {
		_ = conn.Close()
		if migrated {
			_ = loop.Close()
		}
		return
	}
	if !migrated {
		_ = conn.Close()
		return
	}
	_ = old.Close()
}
