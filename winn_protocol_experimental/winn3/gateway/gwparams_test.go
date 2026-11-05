package gateway

import (
	"errors"
	"testing"
	"time"
)

// TestZeroValueDefaultsResolveExplicitly pins the zerodefaults contract.
//
// Config uses zero-means-default, and that idiom is only safe if the default a
// zero field lands on is the documented one — and only if the resulting table
// actually works. This test names the resolved default for every zero field,
// then proves a table built from an all-zero Config can register and route a
// live session. It is the "zero" half of the explicit-vs-zero contrast: a zero
// field is not silent emptiness, it is a specific, documented, working choice.
func TestZeroValueDefaultsResolveExplicitly(t *testing.T) {
	var c Config

	checks := []struct {
		name string
		got  int
		want int
	}{
		{"initialWindow", c.initialWindow(), DefaultInitialWindow},
		{"maxWindow", c.maxWindow(), DefaultMaxWindow},
		{"minWindow", c.minWindow(), DefaultMinWindow},
		{"maxSessions", c.maxSessions(), DefaultMaxSessions},
		{"maxPerClient", c.maxPerClient(), DefaultMaxSessionsPerClient},
		{"shards", c.shards(), DefaultShards},
	}
	for _, ch := range checks {
		if ch.got != ch.want {
			t.Errorf("zero-value default for %s is %d, want documented %d", ch.name, ch.got, ch.want)
		}
	}
	if got, want := c.tokenBudget(), DefaultMaxSessions*DefaultMaxWindow; got != want {
		t.Errorf("zero-value tokenBudget is %d, want %d (MaxSessions*MaxWindow)", got, want)
	}
	if got, want := c.idleTimeout(), DefaultIdleTimeout; got != want {
		t.Errorf("zero-value idleTimeout is %v, want %v", got, want)
	}

	// A zero-value Config must produce a table that actually serves a session,
	// not one whose limits are silently unusable.
	tbl := testTable(t, c)
	f, src := newFake(1)
	if _, err := tbl.Register(f, src, clientKey(1), fixedNow); err != nil {
		t.Fatalf("zero-value table refused a session: %v", err)
	}
	if !deliver(t, tbl, f, 0) {
		t.Fatal("zero-value table did not route a message for a registered session")
	}
}

// TestExplicitConfigHonorsEveryFieldAndBuildsAWorkingTable is the "explicit"
// half of the contrast: values a caller actually sets must be used, never
// silently replaced by a default. It then proves the explicitly-configured
// table is a working one — it registers and routes.
func TestExplicitConfigHonorsEveryFieldAndBuildsAWorkingTable(t *testing.T) {
	cfg := Config{
		InitialWindow:        24,
		MaxWindow:            96,
		MinWindow:            16,
		MaxSessions:          128,
		MaxSessionsPerClient: 4,
		TokenBudget:          24 * 128,
		Shards:               8,
		IdleTimeout:          90 * time.Second,
		Now:                  func() time.Time { return fixedNow },
	}

	tbl, err := NewTable(cfg)
	if err != nil {
		t.Fatalf("NewTable refused the explicit config: %v", err)
	}
	t.Cleanup(tbl.Close)

	honored := []struct {
		name string
		got  int
		want int
	}{
		{"initialWindow", tbl.cfg.initialWindow(), 24},
		{"maxWindow", tbl.cfg.maxWindow(), 96},
		{"minWindow", tbl.cfg.minWindow(), 16},
		{"maxSessions", tbl.cfg.maxSessions(), 128},
		{"maxPerClient", tbl.cfg.maxPerClient(), 4},
		{"shards", tbl.cfg.shards(), 8},
	}
	for _, ch := range honored {
		if ch.got != ch.want {
			t.Errorf("explicit %s is %d, want the set value %d (not the default)", ch.name, ch.got, ch.want)
		}
	}
	if got, want := tbl.cfg.tokenBudget(), 24*128; got != want {
		t.Errorf("explicit tokenBudget is %d, want the set value %d", got, want)
	}
	if got, want := tbl.cfg.idleTimeout(), 90*time.Second; got != want {
		t.Errorf("explicit idleTimeout is %v, want the set value %v", got, want)
	}

	f, src := newFake(2)
	ent, err := tbl.Register(f, src, clientKey(2), fixedNow)
	if err != nil {
		t.Fatalf("explicit table refused a session: %v", err)
	}
	if ent == nil {
		t.Fatal("Register returned a nil entry")
	}
	if !deliver(t, tbl, f, 0) {
		t.Fatal("explicit table did not route a message for a registered session")
	}
}

// TestZeroValueConfigIsStillRefusedWhenItCannotWork closes the other edge of the
// same idiom. Zero means the documented default, but a Config that is *not*
// zero yet cannot work must still be refused outright — the forgiving zero
// default must not make an impossible configuration pass.
func TestZeroValueConfigIsStillRefusedWhenItCannotWork(t *testing.T) {
	cases := []Config{
		{InitialWindow: 8, MinWindow: 16, MaxWindow: 64},
		{InitialWindow: 32, MaxWindow: 16},
		{MinWindow: 4, InitialWindow: 4, MaxWindow: 64},
		{MaxSessions: -1},
		{IdleTimeout: -time.Second},
	}
	for _, c := range cases {
		if _, err := NewTable(c); !errors.Is(err, ErrConfig) {
			t.Errorf("NewTable accepted %+v (err=%v); an impossible Config must be refused", c, err)
		}
	}
}
