package core

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This file is the enforcement of the design's central claim, and it exists
// because the failure it guards against actually shipped.
//
// The measured v3 wire fingerprint from a real handset carried 0B 00 00 00 at
// offset 16 of EVERY initiation, fleet-wide — AmneziaWG's H1 header word after
// its S1 junk prefix. One grep at line rate characterised every user of the
// product. Nothing in these tests is theoretical.

// sampleCount is large enough that a 6-sigma bound on per-bit frequency has a
// false-alarm rate around 1e-9 per bit position, and small enough that the
// suite stays fast.
const sampleCount = 1200

// fleetInitiations builds independent initiations across independent
// identities, gateways and admission keys, all padded to one fixed length so
// that every offset is present in every sample.
func fleetInitiations(t *testing.T, n, padTo int) [][]byte {
	t.Helper()
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		h := newHarnessSeeded(t, fmt.Sprintf("-fleet-%d", i))
		ini := h.initiator(t)
		msg, err := ini.WriteInitiation(nil, padTo)
		if err != nil {
			t.Fatalf("sample %d: %v", i, err)
		}
		out = append(out, msg)
	}
	return out
}

// uniformityViolations reports every way a sample set fails to look uniform.
// It returns findings rather than failing, so that the detector itself can be
// tested against material that is KNOWN to be biased.
func uniformityViolations(samples [][]byte) []string {
	var found []string
	if len(samples) < 2 {
		return []string{"fewer than two samples"}
	}
	n := len(samples[0])
	for _, s := range samples {
		if len(s) != n {
			return []string{fmt.Sprintf("samples are not the same length (%d vs %d)", len(s), n)}
		}
	}

	// 1. No byte position may be constant. This is the direct analogue of the
	//    0B 00 00 00 failure.
	for off := 0; off < n; off++ {
		first := samples[0][off]
		constant := true
		for _, s := range samples[1:] {
			if s[off] != first {
				constant = false
				break
			}
		}
		if constant {
			found = append(found, fmt.Sprintf("byte offset %d is the constant 0x%02X across all %d samples", off, first, len(samples)))
		}
	}

	// 2. No four-byte window may be constant. Stated separately from (1)
	//    because it is the exact shape of the measured failure and a reader
	//    should be able to find it by name.
	for off := 0; off+4 <= n; off++ {
		first := samples[0][off : off+4]
		constant := true
		for _, s := range samples[1:] {
			if !bytes.Equal(s[off:off+4], first) {
				constant = false
				break
			}
		}
		if constant {
			found = append(found, fmt.Sprintf("the four bytes at offset %d are the constant %X across all %d samples", off, first, len(samples)))
		}
	}

	// 3. Per-bit frequency must sit inside a binomial bound. A bit that is
	//    "almost always" one value passes (1) but is just as good a selector
	//    for a censor, so a weaker test would be a false comfort. The X25519
	//    high-bit bias this catches is real: it is why whitenInPlace exists.
	total := float64(len(samples))
	bound := 6 * math.Sqrt(total*0.25)
	for off := 0; off < n; off++ {
		for bit := 0; bit < 8; bit++ {
			ones := 0
			mask := byte(1) << bit
			for _, s := range samples {
				if s[off]&mask != 0 {
					ones++
				}
			}
			if dev := math.Abs(float64(ones) - total/2); dev > bound {
				found = append(found, fmt.Sprintf("bit %d of offset %d is set %d/%d times, deviation %.1f exceeds the 6-sigma bound %.1f",
					bit, off, ones, len(samples), dev, bound))
			}
		}
	}
	return found
}

func analyseUniformity(t *testing.T, what string, samples [][]byte) {
	t.Helper()
	for _, v := range uniformityViolations(samples) {
		t.Errorf("%s: %s", what, v)
	}
}

// TestUniformityDetectorHasTeeth proves the guard above can actually fail.
//
// A passing invariant test that could never fail is worse than no test: it
// converts an unverified claim into a verified-looking one. This feeds the
// detector the RAW X25519 public keys that whitenInPlace exists to hide, and
// requires it to object — the field is 2^255-19, so the top bit of the last
// byte is always zero, which is a constant at a fixed offset.
func TestUniformityDetectorHasTeeth(t *testing.T) {
	raw := make([][]byte, 0, 400)
	for i := 0; i < 400; i++ {
		e, err := generateEphemeral(newDetReader(fmt.Sprintf("teeth-%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, e.public())
	}
	violations := uniformityViolations(raw)
	if len(violations) == 0 {
		t.Fatal("the uniformity detector found nothing wrong with raw X25519 public keys; it cannot be trusted")
	}
	// Specifically, the top bit of the last byte.
	wantOffset := fmt.Sprintf("bit 7 of offset %d", KeySize-1)
	for _, v := range violations {
		if strings.Contains(v, wantOffset) {
			return
		}
	}
	t.Fatalf("expected the detector to name %q; it reported %v", wantOffset, violations)
}

// TestNoFixedConstantsInInitiations is the regression test for the measured
// failure. It must never be deleted or weakened.
func TestNoFixedConstantsInInitiations(t *testing.T) {
	samples := fleetInitiations(t, sampleCount, 300)
	analyseUniformity(t, "initiation", samples)
}

// TestNoFixedConstantsInResponses covers the second handshake message, whose
// tag and whitening are keyed by handshake material rather than the admission
// key.
func TestNoFixedConstantsInResponses(t *testing.T) {
	samples := make([][]byte, 0, sampleCount/3)
	for i := 0; i < sampleCount/3; i++ {
		h := newHarnessSeeded(t, fmt.Sprintf("-resp-%d", i))
		ini := h.initiator(t)
		msg1, err := ini.WriteInitiation(nil, PadAuto)
		if err != nil {
			t.Fatal(err)
		}
		rh, err := h.resp.ReadInitiation(msg1)
		if err != nil {
			t.Fatal(err)
		}
		msg2, _, err := rh.WriteResponse(nil, 260)
		if err != nil {
			t.Fatal(err)
		}
		samples = append(samples, msg2)
	}
	analyseUniformity(t, "response", samples)
}

// TestTransportIsUnconditionallyUniform is the STRONGER claim, and the test is
// deliberately harsher than the one for initiations: the samples all come from
// ONE session sealing the SAME plaintext, so any structure in the format —
// a counter, a session index, a type byte, a length — would show up
// immediately. There is none, because there is none of those fields.
func TestTransportIsUnconditionallyUniform(t *testing.T) {
	h := newHarness(t)
	cli, _ := h.completeHandshake(t)

	payload := bytes.Repeat([]byte{0x00}, 64)
	samples := make([][]byte, 0, sampleCount)
	for i := 0; i < sampleCount; i++ {
		m, err := cli.Seal(payload, 0)
		if err != nil {
			t.Fatal(err)
		}
		samples = append(samples, m)
	}
	analyseUniformity(t, "transport (one session, identical plaintext)", samples)
}

// TestTransportUniformAcrossSessions covers the cross-fleet direction too.
func TestTransportUniformAcrossSessions(t *testing.T) {
	samples := make([][]byte, 0, 300)
	for i := 0; i < 300; i++ {
		h := newHarnessSeeded(t, fmt.Sprintf("-tx-%d", i))
		cli, _ := h.completeHandshake(t)
		m, err := cli.Seal(bytes.Repeat([]byte{0xEE}, 32), 0)
		if err != nil {
			t.Fatal(err)
		}
		samples = append(samples, m)
	}
	analyseUniformity(t, "transport (first packet, across sessions)", samples)
}

// TestPadAutoSpreadsLengths guards the other half of the fingerprint problem: a
// fixed LENGTH identifies a protocol as surely as a fixed byte. The measured
// failure had a 164-byte initiation and a 172-byte response, fleet-wide.
func TestPadAutoSpreadsLengths(t *testing.T) {
	lengths := map[int]int{}
	const n = 1000
	for i := 0; i < n; i++ {
		h := newHarnessSeeded(t, fmt.Sprintf("-len-%d", i))
		ini := h.initiator(t)
		msg, err := ini.WriteInitiation(nil, PadAuto)
		if err != nil {
			t.Fatal(err)
		}
		lengths[len(msg)]++
	}
	if len(lengths) < 100 {
		t.Fatalf("PadAuto produced only %d distinct lengths over %d initiations", len(lengths), n)
	}
	// No single length may dominate. With a spread of 257 values, any length
	// holding more than a tenth of the fleet means the draw is broken.
	for l, c := range lengths {
		if c > n/10 {
			t.Fatalf("length %d accounts for %d of %d initiations", l, c, n)
		}
	}
}

// TestNoAdmissionKeyMeansNoStructure states the honest scoping as a test: an
// observer WITHOUT the gateway admission key sees uniform bytes; an observer
// WITH it can identify the traffic with certainty. The second half is the
// weakness, and it is asserted here so that nobody can later claim the
// whitening is a security boundary.
func TestAdmissionKeyHolderCanIdentifyTraffic(t *testing.T) {
	h := newHarness(t)
	ini := h.initiator(t)
	msg, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	// The gateway's own admission key verifies the tag. Anyone holding it can
	// run exactly this check on every packet they see.
	if _, _, _, err := verifyAdmission(msg, h.gwCf.Gateway, h.now); err != nil {
		t.Fatalf("the key holder must be able to identify the traffic: %v", err)
	}
	// Without it, nothing.
	other := h.gwCf.Gateway
	other.AdmissionKeys = [][]byte{bytes.Repeat([]byte{0x99}, 32)}
	if _, _, _, err := verifyAdmission(msg, other, h.now); err == nil {
		t.Fatal("a non-key-holder must not be able to verify the tag")
	}
}

// TestCoreHasNoTimersOrSockets is a structural guard on the layering that makes
// the answer to a UDP block possible at all.
//
// The core must never acquire a timer or a socket. If it does, two things break
// at once: a carrier can no longer be swapped underneath it, and the timing
// policy — which must be a jittered silence timer, never a metronome — starts
// living in two places. The 25.000-second zero-jitter keepalive this protocol
// replaces was exactly a timer in the wrong layer.
func TestCoreHasNoTimersOrSockets(t *testing.T) {
	banned := []string{
		"time.Tick",
		"time.NewTicker",
		"time.NewTimer",
		"time.After",
		"time.Sleep",
		`"net"`,
		`"net/`,
		`"os"`,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range banned {
			if bytes.Contains(src, []byte(b)) {
				t.Errorf("%s references %s; the core must hold no timer and no socket", name, b)
			}
		}
	}
}
