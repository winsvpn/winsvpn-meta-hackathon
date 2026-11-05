package session

import (
	"errors"
	"strings"
	"testing"
)

// Plan-floor suffix of silent-refusal instance #3.
//
// PathMTU agreement is not a plan-floor agreement. The shipping pair is
// cmd/winn3-gateway default -plan udp (Floor at 1450 = 1402) against a
// udp,tcp,tls client (Floor at 1450 = 1338). EncodePathMTUNotice cannot see
// that pair. EncodePathMTUFloorNotice can.

func TestEncodePathMTUNoticeStaysSevenBytes(t *testing.T) {
	got := EncodePathMTUNotice(1450)
	if len(got) != pathMTUNoticeSize {
		t.Fatalf("EncodePathMTUNotice(1450) is %d bytes, want %d — the conform suite pins the 7-byte record",
			len(got), pathMTUNoticeSize)
	}
}

func TestEncodePathMTUFloorNoticeAppendsMaxMessageSize(t *testing.T) {
	got := EncodePathMTUFloorNotice(1450, 1338)
	if len(got) != pathMTUNoticeFloorSize {
		t.Fatalf("EncodePathMTUFloorNotice is %d bytes, want %d", len(got), pathMTUNoticeFloorSize)
	}
	path, ok := DecodePathMTUNotice(got)
	if !ok || path != 1450 {
		t.Fatalf("DecodePathMTUNotice on a floor notice = (%d, %v), want (1450, true)", path, ok)
	}
	floor, ok := DecodePathMTUFloor(got)
	if !ok || floor != 1338 {
		t.Fatalf("DecodePathMTUFloor = (%d, %v), want (1338, true)", floor, ok)
	}
}

func TestDecodePathMTUFloorIsNoClaimOnASevenByteNotice(t *testing.T) {
	seven := EncodePathMTUNotice(1450)
	if _, ok := DecodePathMTUFloor(seven); ok {
		t.Fatal("a 7-byte PathMTU-only notice was read as a floor claim; that breaks old-peer compatibility")
	}
}

func TestRefusePathMTUMismatchIgnoresPlanFloorWhenThePeerSentOnlyPathMTU(t *testing.T) {
	// Compatibility: an old gateway, or winn3/gateway.New, emits 7 bytes.
	d := &Driver{cfg: Config{PathMTU: 1450, MaxMessageSize: 1338}}
	if err := d.refusePathMTUMismatch(EncodePathMTUNotice(1450)); err != nil {
		t.Fatalf("a PathMTU-only agreeing notice was refused: %v", err)
	}
}

func TestRefusePathMTUMismatchRefusesAWiderPlanFloorAtTheSamePathMTU(t *testing.T) {
	// Shipping pair: client udp,tcp,tls floor 1338, gateway udp-only floor 1402,
	// both PathMTU 1450. Without this check the session establishes and
	// black-holes full-size packets.
	d := &Driver{cfg: Config{PathMTU: 1450, MaxMessageSize: 1338}}
	err := d.refusePathMTUMismatch(EncodePathMTUFloorNotice(1450, 1402))
	if err == nil {
		t.Fatal("a wider peer plan floor proceeded: that is the same-PathMTU black hole")
	}
	if !errors.Is(err, ErrPathMTUMismatch) {
		t.Fatalf("refusal is %v, want ErrPathMTUMismatch", err)
	}
	text := err.Error()
	if !strings.Contains(text, "1338") || !strings.Contains(text, "1402") {
		t.Errorf("the refusal does not name both floors:\n%s", text)
	}
	if !strings.Contains(text, "1450") {
		t.Errorf("the refusal does not name the shared path MTU:\n%s", text)
	}
	if !strings.Contains(text, "cannot shrink") {
		t.Errorf("a wider plan floor does not say this end cannot shrink the responder:\n%s", text)
	}
	if d.cfg.MaxMessageSize != 1338 {
		t.Fatalf("a refused floor mutated MaxMessageSize to %d", d.cfg.MaxMessageSize)
	}
}

func TestRefusePathMTUMismatchAppliesANarrowerPlanFloorWhenTheFlagIsSet(t *testing.T) {
	d := &Driver{cfg: Config{
		PathMTU:                1450,
		MaxMessageSize:         1402,
		ApplyNegotiatedPathMTU: true,
	}}
	if err := d.refusePathMTUMismatch(EncodePathMTUFloorNotice(1450, 1338)); err != nil {
		t.Fatalf("a safe floor shrink was refused: %v", err)
	}
	if d.cfg.MaxMessageSize != 1338 {
		t.Fatalf("MaxMessageSize is %d after apply, want 1338", d.cfg.MaxMessageSize)
	}
	if d.cfg.PathMTU != 1450 {
		t.Fatalf("PathMTU mutated to %d; the path MTUs already agreed", d.cfg.PathMTU)
	}
}

func TestRefusePathMTUMismatchNamesSetMTUWhenAFloorShrinkWouldBeSafe(t *testing.T) {
	d := &Driver{cfg: Config{PathMTU: 1450, MaxMessageSize: 1402}}
	err := d.refusePathMTUMismatch(EncodePathMTUFloorNotice(1450, 1338))
	if err == nil {
		t.Fatal("a safe floor shrink proceeded with APPLY off: production hosts would black-hole")
	}
	if !errors.Is(err, ErrPathMTUMismatch) {
		t.Fatalf("refusal is %v, want ErrPathMTUMismatch", err)
	}
	if !strings.Contains(err.Error(), "SetMTU") {
		t.Errorf("APPLY-off floor shrink does not name SetMTU:\n%s", err)
	}
	if d.cfg.MaxMessageSize != 1402 {
		t.Fatalf("a refused apply mutated MaxMessageSize to %d", d.cfg.MaxMessageSize)
	}
}

func TestRefusePathMTUMismatchProceedsWhenPlanFloorsAgree(t *testing.T) {
	d := &Driver{cfg: Config{PathMTU: 1450, MaxMessageSize: 1338}}
	if err := d.refusePathMTUMismatch(EncodePathMTUFloorNotice(1450, 1338)); err != nil {
		t.Fatalf("agreeing path MTU and plan floor was refused: %v", err)
	}
}

func TestClassifyPlanFloorMismatchNamesAWiderPeer(t *testing.T) {
	if got := classifyPlanFloorMismatch(1338, 1402, true); got != pathMTUMismatchWiderPeer {
		t.Fatalf("classifyPlanFloorMismatch(1338, 1402, true) = %d, want wider peer", got)
	}
}

func TestEncodePathMTUFloorNoticeDropsTheSuffixWhenMaxMessageSizeIsUnusable(t *testing.T) {
	for _, n := range []int{0, -1, 0x10000} {
		got := EncodePathMTUFloorNotice(1450, n)
		if len(got) != pathMTUNoticeSize {
			t.Errorf("EncodePathMTUFloorNotice(1450, %d) is %d bytes, want the 7-byte PathMTU record",
				n, len(got))
		}
		if _, ok := DecodePathMTUFloor(got); ok {
			t.Errorf("unusable MaxMessageSize %d was encoded as a floor claim", n)
		}
	}
}
