package main

import (
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/spagate"
)

func TestValidateSPALimitsAcceptsDefaults(t *testing.T) {
	if err := validateSPALimits(spagate.DefaultLimits()); err != nil {
		t.Fatalf("DefaultLimits refused: %v", err)
	}
}

func TestValidateSPALimitsRejectsNonPositive(t *testing.T) {
	type spoil struct {
		name  string
		apply func(*spagate.Limits)
		want  string
	}
	cases := []spoil{
		{"rate-burst", func(l *spagate.Limits) { l.RateBurst = 0 }, "-rate-burst"},
		{"rate-burst-negative", func(l *spagate.Limits) { l.RateBurst = -1 }, "-rate-burst"},
		{"rate-per-minute", func(l *spagate.Limits) { l.RatePerMinute = 0 }, "-rate-per-minute"},
		{"rate-max-sources", func(l *spagate.Limits) { l.MaxSources = 0 }, "-rate-max-sources"},
		{"max-authorized-sources", func(l *spagate.Limits) { l.MaxAuthorized = 0 }, "-max-authorized-sources"},
		{"max-replay-nonces", func(l *spagate.Limits) { l.MaxReplayNonces = 0 }, "-max-replay-nonces"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			limits := spagate.DefaultLimits()
			c.apply(&limits)
			err := validateSPALimits(limits)
			if err == nil {
				t.Fatalf("accepted a non-positive %s", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not name %q", err, c.want)
			}
		})
	}
}
