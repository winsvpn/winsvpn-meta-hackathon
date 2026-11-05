package driver

import (
	"context"
	"errors"
	"testing"
	"time"
)

type failingCloseRunner struct{ err error }

func (r failingCloseRunner) Run(context.Context) error { return nil }
func (r failingCloseRunner) Close() error              { return r.err }

func TestReconnectStopsWhenRoundTeardownFails(t *testing.T) {
	closeErr := errors.New("round output pump is still active")
	builds := 0
	r, err := NewReconnect(ReconnectConfig{
		Build: func() (Runner, error) {
			builds++
			return failingCloseRunner{err: closeErr}, nil
		},
		Attempts: 2,
		Sleep:    func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Run(context.Background()); !errors.Is(err, closeErr) {
		t.Fatalf("Run returned %v, want teardown error", err)
	}
	if builds != 1 {
		t.Fatalf("built %d rounds after failed teardown, want 1", builds)
	}
}
