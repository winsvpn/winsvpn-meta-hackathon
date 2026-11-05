package session

// APPLY half of silent-refusal instance #3: ShrinkToPeerPathMTU, and the
// guarded return in refusePathMTUMismatch when Config.ApplyNegotiatedPathMTU
// is set.
//
// The refusal tests in pathmtu_negotiated_test.go pin the default (flag off):
// a two-sided difference is ErrPathMTUMismatch. These tests pin the other
// branch: a safe shrink proceeds, an unsafe shrink (the brief's 1280-vs-1500
// pair, a wider peer, a dead-zone inner MTU) still refuses.

import (
	"errors"
	"strings"
	"testing"
)

func TestShrinkToPeerPathMTUTakesTheMinimumWhenInnerIPv6StillFits(t *testing.T) {
	local := 1500
	max := MaxMessageSizeForPath(local, CarrierOverheadUDPIPv6)
	if max != 1452 {
		t.Fatalf("harness: UDP/IPv6 at 1500 is %d, want 1452", max)
	}

	// 1357 is the udp-only inner-IPv6 threshold. Applying it keeps inner MTU
	// at exactly 1280, which is the last safe value.
	got, ok := ShrinkToPeerPathMTU(local, max, 1357)
	if !ok {
		t.Fatal("a shrink to 1357 was refused: that is the last safe udp-only path MTU")
	}
	want := MaxMessageSizeForPath(1357, CarrierOverheadUDPIPv6)
	if got != want {
		t.Fatalf("ShrinkToPeerPathMTU(1500, %d, 1357) = %d, want %d", max, got, want)
	}
	if InnerMTU(got) != IPv6MinimumLinkMTU {
		t.Fatalf("inner MTU after shrink is %d, want %d", InnerMTU(got), IPv6MinimumLinkMTU)
	}
}

func TestShrinkToPeerPathMTURefusesTheBriefs1280Against1500Pair(t *testing.T) {
	// The pair tools/verify_winn3_conformance.sh still names: gateway 1280,
	// client 1500, floors 1232 vs 1452. Applying the minimum would put the
	// inner MTU at 1203, below RFC 8200. Loud refusal is the minimum correct
	// response; negotiation would recreate the dead zone.
	max := MaxMessageSizeForPath(1500, CarrierOverheadUDPIPv6)
	got, ok := ShrinkToPeerPathMTU(1500, max, 1280)
	if ok {
		t.Fatalf("a shrink to 1280 was allowed (newMax %d, inner %d): that is the dead zone",
			got, InnerMTU(got))
	}
	if got != 0 {
		t.Fatalf("a refused shrink returned newMax %d, want 0", got)
	}
	if InnerMTU(1280-CarrierOverheadUDPIPv6) >= IPv6MinimumLinkMTU {
		t.Fatal("harness: 1280 UDP/IPv6 inner MTU is no longer below 1280; the pin is stale")
	}
}

func TestShrinkToPeerPathMTURefusesAWiderPeer(t *testing.T) {
	max := MaxMessageSizeForPath(1280, CarrierOverheadUDPIPv6)
	got, ok := ShrinkToPeerPathMTU(1280, max, 1500)
	if ok {
		t.Fatalf("a wider peer was treated as a shrink (newMax %d)", got)
	}
}

func TestShrinkToPeerPathMTURefusesNoClaim(t *testing.T) {
	max := MaxMessageSizeForPath(1500, CarrierOverheadUDPIPv6)
	for _, peer := range []int{0, -1} {
		if _, ok := ShrinkToPeerPathMTU(1500, max, peer); ok {
			t.Fatalf("peer %d was treated as a claim", peer)
		}
	}
}

func TestRefusePathMTUMismatchAppliesASafeShrinkWhenTheFlagIsSet(t *testing.T) {
	max := MaxMessageSizeForPath(1500, CarrierOverheadUDPIPv6)
	d := &Driver{cfg: Config{
		PathMTU:                1500,
		MaxMessageSize:         max,
		ApplyNegotiatedPathMTU: true,
	}}
	if err := d.refusePathMTUMismatch(EncodePathMTUNotice(1357)); err != nil {
		t.Fatalf("a safe shrink was refused: %v", err)
	}
	if d.cfg.PathMTU != 1357 {
		t.Fatalf("PathMTU is %d after apply, want 1357", d.cfg.PathMTU)
	}
	wantMax := MaxMessageSizeForPath(1357, CarrierOverheadUDPIPv6)
	if d.cfg.MaxMessageSize != wantMax {
		t.Fatalf("MaxMessageSize is %d after apply, want %d", d.cfg.MaxMessageSize, wantMax)
	}
	if d.pathMTUAgreed != 1357 {
		t.Fatalf("pathMTUAgreed is %d, want 1357", d.pathMTUAgreed)
	}
}

func TestRefusePathMTUMismatchStillRefusesThe1280PairWhenTheFlagIsSet(t *testing.T) {
	max := MaxMessageSizeForPath(1500, CarrierOverheadUDPIPv6)
	d := &Driver{cfg: Config{
		PathMTU:                1500,
		MaxMessageSize:         max,
		ApplyNegotiatedPathMTU: true,
	}}
	err := d.refusePathMTUMismatch(EncodePathMTUNotice(1280))
	if err == nil {
		t.Fatal("the 1280-vs-1500 pair proceeded: APPLY walked into the dead zone")
	}
	if !errors.Is(err, ErrPathMTUMismatch) {
		t.Fatalf("refusal is %v, want ErrPathMTUMismatch", err)
	}
	if d.cfg.PathMTU != 1500 || d.cfg.MaxMessageSize != max {
		t.Fatalf("a refused apply mutated the config: PathMTU=%d MaxMessageSize=%d",
			d.cfg.PathMTU, d.cfg.MaxMessageSize)
	}
	if !strings.Contains(err.Error(), "1280") || !strings.Contains(err.Error(), "1500") {
		t.Errorf("the refusal does not name both ends:\n%s", err)
	}
	if !strings.Contains(err.Error(), "dead zone") {
		t.Errorf("the 1280-vs-1500 refusal does not name the dead zone:\n%s", err)
	}
	if strings.Contains(err.Error(), "SetMTU") {
		t.Errorf("the 1280-vs-1500 refusal named SetMTU; applying would enter the dead zone:\n%s", err)
	}
}

func TestRefusePathMTUMismatchNamesTheDeadZoneEvenWithoutSetMTU(t *testing.T) {
	// APPLY off must still name the dead zone for the brief's pair. The
	// previous single-sentence refusal always said "no host re-applies",
	// which tells an operator to add SetMTU — and then APPLY walks into
	// the dead zone. The reason that stays true if the flag is flipped
	// is the one that must be printed.
	max := MaxMessageSizeForPath(1500, CarrierOverheadUDPIPv6)
	d := &Driver{cfg: Config{
		PathMTU:        1500,
		MaxMessageSize: max,
	}}
	err := d.refusePathMTUMismatch(EncodePathMTUNotice(1280))
	if err == nil {
		t.Fatal("the 1280-vs-1500 pair proceeded with APPLY off")
	}
	if !errors.Is(err, ErrPathMTUMismatch) {
		t.Fatalf("refusal is %v, want ErrPathMTUMismatch", err)
	}
	text := err.Error()
	if !strings.Contains(text, "dead zone") {
		t.Errorf("APPLY-off 1280-vs-1500 does not name the dead zone:\n%s", text)
	}
	if strings.Contains(text, "SetMTU") {
		t.Errorf("APPLY-off 1280-vs-1500 named SetMTU:\n%s", text)
	}
	if classifyPathMTUMismatch(1500, max, 1280, false) != pathMTUMismatchDeadZone {
		t.Fatalf("classify(1500, %d, 1280, false) = %d, want dead zone", max, classifyPathMTUMismatch(1500, max, 1280, false))
	}
}

func TestRefusePathMTUMismatchNamesTheMissingSetterWhenTheShrinkWouldBeSafe(t *testing.T) {
	max := MaxMessageSizeForPath(1500, CarrierOverheadUDPIPv6)
	if _, ok := ShrinkToPeerPathMTU(1500, max, 1357); !ok {
		t.Fatal("harness: 1500→1357 must be a safe shrink")
	}
	d := &Driver{cfg: Config{
		PathMTU:        1500,
		MaxMessageSize: max,
	}}
	err := d.refusePathMTUMismatch(EncodePathMTUNotice(1357))
	if err == nil {
		t.Fatal("a safe shrink proceeded with APPLY off: production hosts would black-hole")
	}
	if !errors.Is(err, ErrPathMTUMismatch) {
		t.Fatalf("refusal is %v, want ErrPathMTUMismatch", err)
	}
	text := err.Error()
	if !strings.Contains(text, "SetMTU") {
		t.Errorf("a safe shrink with APPLY off does not name SetMTU:\n%s", text)
	}
	if strings.Contains(text, "dead zone") {
		t.Errorf("a safe shrink was diagnosed as the dead zone:\n%s", text)
	}
	if !strings.Contains(text, "1357") || !strings.Contains(text, "1500") {
		t.Errorf("the refusal does not name both ends:\n%s", text)
	}
}

func TestRefusePathMTUMismatchNamesAWiderPeer(t *testing.T) {
	max := MaxMessageSizeForPath(1357, CarrierOverheadUDPIPv6)
	d := &Driver{cfg: Config{
		PathMTU:                1357,
		MaxMessageSize:         max,
		ApplyNegotiatedPathMTU: true,
	}}
	err := d.refusePathMTUMismatch(EncodePathMTUNotice(1500))
	if err == nil {
		t.Fatal("a wider peer proceeded")
	}
	text := err.Error()
	if !strings.Contains(text, "cannot shrink") {
		t.Errorf("a wider peer does not say this end cannot shrink the responder:\n%s", text)
	}
	if strings.Contains(text, "dead zone") {
		t.Errorf("a wider peer was diagnosed as the dead zone:\n%s", text)
	}
}

func TestRefusePathMTUMismatchStillRefusesAWiderPeerWhenTheFlagIsSet(t *testing.T) {
	max := MaxMessageSizeForPath(1357, CarrierOverheadUDPIPv6)
	d := &Driver{cfg: Config{
		PathMTU:                1357,
		MaxMessageSize:         max,
		ApplyNegotiatedPathMTU: true,
	}}
	err := d.refusePathMTUMismatch(EncodePathMTUNotice(1500))
	if err == nil {
		t.Fatal("a wider peer proceeded: this end cannot shrink the gateway")
	}
	if !errors.Is(err, ErrPathMTUMismatch) {
		t.Fatalf("refusal is %v, want ErrPathMTUMismatch", err)
	}
}
