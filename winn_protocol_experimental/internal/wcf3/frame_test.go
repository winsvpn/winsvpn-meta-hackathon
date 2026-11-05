package wcf3

import (
	"bytes"
	"math"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
)

func TestPrivacyCellRoundTripAndConnectionBinding(t *testing.T) {
	now := time.Now().UTC()
	binding := validBinding(now)
	frameContext, err := ContextFromBinding(binding, now)
	if err != nil {
		t.Fatal(err)
	}
	frame := Frame{
		Kind:          KindData,
		SessionID:     frameContext.SessionID,
		BindingID:     frameContext.BindingID,
		PSKGeneration: frameContext.PSKGeneration,
		SequenceEpoch: frameContext.SequenceEpoch,
		Sequence:      9,
		Payload:       []byte("private payload"),
	}
	encoded, err := EncodePrivacyCell(frame)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != PrivacyCellSize || encoded[5]&FlagPadded == 0 {
		t.Fatalf("privacy cell size/flags = %d/%08b", len(encoded), encoded[5])
	}
	replay, err := NewReplayWindow(frameContext, 0)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePrivacyCell(
		encoded, &frameContext, replay, DirectionIngress,
	)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Sequence != frame.Sequence ||
		!bytes.Equal(decoded.Payload, frame.Payload) {
		t.Fatalf("decoded WCF3 frame = %#v", decoded)
	}
}

func TestBindingChangesWithCandidateAttemptAndManifest(t *testing.T) {
	now := time.Now().UTC()
	first := validBinding(now)
	firstID, err := DeriveBindingID(first, now)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*connectivity.Binding)
	}{
		{"attempt", func(binding *connectivity.Binding) {
			binding.AttemptID = strings.Repeat("d", 32)
		}},
		{"candidate", func(binding *connectivity.Binding) {
			binding.CandidateID = "candidate-2"
		}},
		{"manifest", func(binding *connectivity.Binding) {
			binding.ManifestDigest = strings.Repeat("e", 64)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := first
			test.mutate(&changed)
			changedID, err := DeriveBindingID(changed, now)
			if err != nil {
				t.Fatal(err)
			}
			if changedID == firstID {
				t.Fatal("WCF3 binding ID did not change")
			}
		})
	}
}

func TestDecodeRejectsCrossCandidateAndStructuralTampering(t *testing.T) {
	now := time.Now().UTC()
	binding := validBinding(now)
	frameContext, err := ContextFromBinding(binding, now)
	if err != nil {
		t.Fatal(err)
	}
	frame := Frame{
		Kind:          KindProbe,
		SessionID:     frameContext.SessionID,
		BindingID:     frameContext.BindingID,
		PSKGeneration: frameContext.PSKGeneration,
		SequenceEpoch: frameContext.SequenceEpoch,
		Sequence:      1,
		Payload:       bytes.Repeat([]byte{0x71}, ProbePayloadSize),
	}
	encoded, err := Encode(frame, 0)
	if err != nil {
		t.Fatal(err)
	}
	other := binding
	other.CandidateID = "candidate-2"
	otherContext, err := ContextFromBinding(other, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(
		encoded, MaxPayloadSize, &otherContext,
	); err == nil || !strings.Contains(err.Error(), "binding mismatch") {
		t.Fatalf("cross-candidate decode error = %v", err)
	}
	tampered := append([]byte(nil), encoded...)
	tampered[0] ^= 0xff
	if _, err := Decode(tampered, MaxPayloadSize, nil); err == nil {
		t.Fatal("tampered WCF3 magic decoded")
	}
	tampered = append([]byte(nil), encoded...)
	tampered[6], tampered[7] = 0xff, 0xff
	if _, err := Decode(tampered, MaxPayloadSize, nil); err == nil {
		t.Fatal("oversized WCF3 payload decoded")
	}
}

func TestWCF3RejectsUndefinedFragmentFlags(t *testing.T) {
	now := time.Now().UTC()
	frameContext, err := ContextFromBinding(validBinding(now), now)
	if err != nil {
		t.Fatal(err)
	}
	invalid := Frame{
		Kind:          KindCover,
		Flags:         1 << 1,
		SessionID:     frameContext.SessionID,
		BindingID:     frameContext.BindingID,
		PSKGeneration: frameContext.PSKGeneration,
		SequenceEpoch: frameContext.SequenceEpoch,
		Sequence:      1,
	}
	if _, err := Encode(invalid, PrivacyCellSize); err == nil {
		t.Fatal("undefined fragmentation flag encoded")
	}
}

func TestPrivacyAPIRejectsVariableCellsAndOversizePayload(t *testing.T) {
	now := time.Now().UTC()
	frameContext, err := ContextFromBinding(validBinding(now), now)
	if err != nil {
		t.Fatal(err)
	}
	frame := Frame{
		Kind:          KindData,
		SessionID:     frameContext.SessionID,
		BindingID:     frameContext.BindingID,
		PSKGeneration: frameContext.PSKGeneration,
		SequenceEpoch: frameContext.SequenceEpoch,
		Sequence:      1,
		Payload:       bytes.Repeat([]byte{1}, PrivacyPayloadSize+1),
	}
	if _, err := EncodePrivacyCell(frame); err == nil {
		t.Fatal("oversize privacy payload encoded")
	}
	frame.Payload = []byte("small")
	encoded, err := Encode(frame, PrivacyCellSize-1)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := NewReplayWindow(frameContext, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePrivacyCell(
		encoded, &frameContext, replay, DirectionIngress,
	); err == nil {
		t.Fatal("variable-size privacy cell decoded")
	}
}

func TestReplayWindowSeparatesDirectionsAndRejectsReplay(t *testing.T) {
	now := time.Now().UTC()
	frameContext, err := ContextFromBinding(validBinding(now), now)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := NewReplayWindow(frameContext, MinimumReplayWindow)
	if err != nil {
		t.Fatal(err)
	}
	frame := Frame{
		Kind:          KindData,
		SessionID:     frameContext.SessionID,
		BindingID:     frameContext.BindingID,
		PSKGeneration: frameContext.PSKGeneration,
		SequenceEpoch: frameContext.SequenceEpoch,
		Sequence:      100,
		Payload:       []byte("data"),
	}
	if err := replay.Accept(DirectionIngress, frame); err != nil {
		t.Fatal(err)
	}
	if err := replay.Accept(DirectionIngress, frame); err == nil {
		t.Fatal("same-direction replay was accepted")
	}
	if err := replay.Accept(DirectionEgress, frame); err != nil {
		t.Fatalf("other direction reused sequence: %v", err)
	}
	frame.Sequence = 200
	if err := replay.Accept(DirectionIngress, frame); err != nil {
		t.Fatal(err)
	}
	frame.Sequence = 100
	if err := replay.Accept(DirectionIngress, frame); err == nil ||
		!strings.Contains(err.Error(), "outside") {
		t.Fatalf("old sequence error = %v", err)
	}
}

func TestDecodeWithReplayRejectsGenericDuplicateAndInvalidLimit(
	t *testing.T,
) {
	now := time.Now().UTC()
	frameContext, err := ContextFromBinding(validBinding(now), now)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(Frame{
		Kind:          KindData,
		SessionID:     frameContext.SessionID,
		BindingID:     frameContext.BindingID,
		PSKGeneration: frameContext.PSKGeneration,
		SequenceEpoch: frameContext.SequenceEpoch,
		Sequence:      41,
		Payload:       []byte("generic"),
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := NewReplayWindow(frameContext, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeWithReplay(
		encoded, MaxPayloadSize, &frameContext, replay, DirectionIngress,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeWithReplay(
		encoded, MaxPayloadSize, &frameContext, replay, DirectionIngress,
	); err == nil {
		t.Fatal("generic WCF3 replay was accepted")
	}
	for _, invalid := range []int{-1, 0, MaxPayloadSize + 1} {
		if _, err := Decode(encoded, invalid, &frameContext); err == nil {
			t.Fatalf("invalid maximum payload %d was accepted", invalid)
		}
	}
}

func TestSequencerFailsClosedAtExhaustion(t *testing.T) {
	sequencer, err := NewSequencer(math.MaxUint64)
	if err != nil {
		t.Fatal(err)
	}
	if value, err := sequencer.Next(); err != nil ||
		value != math.MaxUint64 {
		t.Fatalf("last sequence = %d, %v", value, err)
	}
	if value, err := sequencer.Next(); err == nil || value != 0 {
		t.Fatalf("exhausted sequence = %d, %v", value, err)
	}
}

func FuzzDecode(fuzzer *testing.F) {
	now := time.Date(2026, 7, 23, 20, 0, 0, 0, time.UTC)
	frameContext, err := ContextFromBinding(validBinding(now), now)
	if err != nil {
		fuzzer.Fatal(err)
	}
	seed, err := Encode(Frame{
		Kind:          KindData,
		SessionID:     frameContext.SessionID,
		BindingID:     frameContext.BindingID,
		PSKGeneration: frameContext.PSKGeneration,
		SequenceEpoch: frameContext.SequenceEpoch,
		Sequence:      1,
		Payload:       []byte("seed"),
	}, PrivacyCellSize)
	if err != nil {
		fuzzer.Fatal(err)
	}
	fuzzer.Add(seed, MaxPayloadSize)
	fuzzer.Fuzz(func(t *testing.T, encoded []byte, maxPayload int) {
		if maxPayload < -1<<20 || maxPayload > 1<<20 {
			return
		}
		frame, err := Decode(encoded, maxPayload, nil)
		if err == nil {
			reencoded, encodeErr := Encode(frame, len(encoded))
			if encodeErr != nil {
				t.Fatalf("decoded frame did not re-encode: %v", encodeErr)
			}
			clear(reencoded)
		}
		clear(frame.Payload)
	})
}

func validBinding(now time.Time) connectivity.Binding {
	return connectivity.Binding{
		AttemptID:      strings.Repeat("a", 32),
		Profile:        "default",
		Mode:           connectivity.ModeMaximumPrivacy,
		ManifestDigest: strings.Repeat("b", 64),
		CandidateID:    "privacy-entry-1",
		NodeID:         "entry-nyc",
		SessionID:      strings.Repeat("c", 32),
		PSKGeneration:  7,
		SequenceEpoch:  3,
		Nonce:          strings.Repeat("d", 32),
		ExpiresAt:      now.Add(time.Minute),
	}
}
