package driver

import (
	"context"
	"errors"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/session"
)

// Round A2 v3: a Stop that lands while Build runs wins over whatever Build
// returns, including an error. Cancellation is checked after Build on both
// paths, before terminal, fail-fast or exhaustion classification.
// TestReconnectDoesNotDriveARoundBuiltDuringAStop keeps the successful-Build
// half, including the close of a round that will not run.

func cancelledBuildResult(t *testing.T, buildErr error) (error, int, int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	builds, sleeps := 0, 0
	rc, err := NewReconnect(ReconnectConfig{
		Build: func() (Runner, error) {
			builds++
			cancel()
			return nil, buildErr
		},
		Terminal:                TerminalRoundError,
		FailBeforeEstablishment: true,
		Sleep:                   func(context.Context, time.Duration) error { sleeps++; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return rc.Run(ctx), builds, sleeps
}

// TestACancelledBuildWithARetryableErrorReturnsCancellation: with fail-fast on,
// the retryable error would otherwise be reported as never established.
func TestACancelledBuildWithARetryableErrorReturnsCancellation(t *testing.T) {
	runErr, builds, sleeps := cancelledBuildResult(t,
		errWrap(ErrSessionFailed, "%w", session.ErrCarrierExhausted))
	if !errors.Is(runErr, context.Canceled) || errors.Is(runErr, ErrReconnectNeverEstablished) {
		t.Fatalf("Run returned %v, want context.Canceled", runErr)
	}
	if builds != 1 || sleeps != 0 {
		t.Fatalf("%d builds and %d delays after a Stop during Build, want 1 and 0", builds, sleeps)
	}
}

// TestACancelledBuildWithATerminalErrorReturnsCancellation: a terminal refusal
// that arrives after the owner stopped is not the tunnel's outcome; the Stop is.
func TestACancelledBuildWithATerminalErrorReturnsCancellation(t *testing.T) {
	runErr, builds, sleeps := cancelledBuildResult(t,
		errWrap(ErrReconnectTerminal, "key file missing"))
	if !errors.Is(runErr, context.Canceled) || errors.Is(runErr, ErrReconnectTerminal) {
		t.Fatalf("Run returned %v, want context.Canceled", runErr)
	}
	if builds != 1 || sleeps != 0 {
		t.Fatalf("%d builds and %d delays after a Stop during Build, want 1 and 0", builds, sleeps)
	}
}
