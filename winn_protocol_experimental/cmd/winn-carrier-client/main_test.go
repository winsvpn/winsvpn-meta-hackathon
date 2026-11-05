package main

import (
	"context"
	"net"
	"testing"

	"winsvpn.local/winnprotocol/internal/carrier"
)

type inertDialer struct{}

func (inertDialer) Dial(context.Context) (net.PacketConn, error) { return nil, nil }

func TestCarrierPrioritiesPreferEveryNodeBeforeProtocolDowngrade(t *testing.T) {
	priorities, err := carrierPriorities("h3,h2")
	if err != nil {
		t.Fatal(err)
	}
	if priorities["h3"] != 0 || priorities["h2"] != 100 {
		t.Fatalf("unexpected priorities: %v", priorities)
	}
	candidates, err := orderedCandidates("h2,h3", "h3", "h2", inertDialer{}, inertDialer{})
	if err != nil {
		t.Fatal(err)
	}
	if candidates[0].Path.ID != "h3-primary" ||
		candidates[0].Path.Priority != 100 ||
		candidates[1].Path.ID != "h2-fallback" ||
		candidates[1].Path.Priority != 0 {
		t.Fatalf("unexpected candidates: %+v", candidates)
	}
}

func TestAlternateNodeParsing(t *testing.T) {
	id, h3, h2, err := parseAlternateNode(
		"node-b|https://b.example/udp/{target_host}/{target_port}/|https://b.example" + carrier.H2Path,
	)
	if err != nil {
		t.Fatal(err)
	}
	if id != "node-b" || h3 == "" || h2 == "" {
		t.Fatalf("unexpected alternate: %q %q %q", id, h3, h2)
	}
	if _, _, _, err := parseAlternateNode("primary|x|y"); err == nil {
		t.Fatal("reserved primary node ID was accepted")
	}
}
