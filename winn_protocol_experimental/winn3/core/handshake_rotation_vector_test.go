package core

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"
)

// Known-answer vectors for a handshake completed under a freshly ROTATED
// admission key.
//
// These are the same style and the same principle as the baseline vectors in
// vectors_test.go — pin the WIRE and the KEY SCHEDULE, not just the round trip
// — but for the rotation path. They exercise handshake.go's rotation seam
// (SetAdmissionKeys + a two-key overlap) against a fixed, reproducible
// configuration, so a refactor that silently perturbed rotation would fail the
// moment a byte moved.
//
// The load-bearing property they pin is the one the rotation mechanism is
// DESIGNED to have but that no existing test asserts on the wire:
//
//	rotating the admission key changes the whole wire FRAME of the
//	initiation but NOTHING the peers actually negotiate.
//
// The admission key is a wire-only obfuscation secret. sealAdmission stamps a
// leading tag and then whitens the entire body with a keystream derived from
// that key, so every byte of the on-wire initiation frame is key-dependent by
// design. What must therefore hold is the inverse: once that key is removed by
// un-whitening before the chain is touched, it appears nowhere else. Every byte
// the negotiating peers actually rely on — the response, the demux key, the
// salts, the final chaining key and transcript hash, and the first transport
// message — must be byte-identical to the baseline known-answer handshake even
// though the initiator sealed its initiation under a different, freshly rotated
// key. Any code path that leaked the admission key into the chain would drive
// all of these off the pinned values at once.
//
// Honest limit, unchanged from vectors_test.go: these vectors were produced by
// THIS implementation, so they prove stability, not cross-implementation
// correctness. What they add over the baseline is a binding between "the
// rotation seam exists" and "rotation leaves the negotiated session untouched."

// vecRotInitiation is the wire vector for a full initiation produced under a
// freshly rotated admission key, with everything else held byte-identical to
// the baseline KAT (same statics, PSK, client randomness, clock, payload and
// padTo=0). It differs from vecInitiation only in the leading admission tag;
// the sealed body is unchanged.
const vecRotInitiation = "b8116865522bf5addbdabb8e2758967376948665bb09a9ac0044b1c4357ae49a" +
	"02d6e991b5e08bf5a2cc2a34fe9cd173871e530d422de75510b74497e23235516da6dd5f" +
	"2f1d500af285694a661cd036d96a1299b9f84e478de7ff6b76d6323b7e439e53cafdcb0" +
	"b52b43d958de74cc7c88d96198afd14662a16628f3066fe8a63137615197d"

// rotationVectorParties rebuilds the pinned KAT configuration but seals the
// initiation under a freshly rotated admission key, and gives the gateway a
// two-key overlap so the rotated initiation verifies. Everything else — statics,
// PSK, randomness, clock — is byte-identical to katParties, which is what lets
// the schedule equality below be asserted against the baseline vector values.
func rotationVectorParties(t *testing.T) (*Initiator, *Responder) {
	t.Helper()
	client, err := NewStaticKey(mustSeed("winn3-kat-client-static"))
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := NewStaticKey(mustSeed("winn3-kat-gateway-static"))
	if err != nil {
		t.Fatal(err)
	}
	baseAdmission := mustSeed("winn3-kat-admission")
	rotAdmission := mustSeed("winn3-kat-rotated-admission")
	clock := func() time.Time { return vecTime }
	psk := mustSeed("winn3-kat-psk")

	// The initiator holds exactly one admission key: the freshly rotated one.
	cliGp := GatewayParams{
		AdmissionKeys: [][]byte{rotAdmission},
		GatewayID:     []byte(vecGatewayIDText),
		TagSize:       DefaultTagSize,
	}
	cliCf := Config{Gateway: cliGp, PSK: psk, Rand: newDetReader("winn3-kat-client-rand"), Now: clock}

	// The gateway holds the overlap {rotated, baseline}, newest first, exactly
	// as a live rotation would.
	gwGp := GatewayParams{
		AdmissionKeys: [][]byte{rotAdmission, baseAdmission},
		GatewayID:     []byte(vecGatewayIDText),
		TagSize:       DefaultTagSize,
	}
	gwCf := Config{Gateway: gwGp, PSK: psk, Rand: newDetReader("winn3-kat-gateway-rand"), Now: clock}

	gwPub, err := NewPublicKey(gateway.Public())
	if err != nil {
		t.Fatal(err)
	}
	ini, err := NewInitiator(cliCf, client, gwPub)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := NewResponder(gwCf, gateway, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if n := resp.AdmissionKeyCount(); n != 2 {
		t.Fatalf("rotation override not applied: gateway holds %d keys", n)
	}
	return ini, resp
}

func TestKnownAnswerRotationVector(t *testing.T) {
	ini, resp := rotationVectorParties(t)

	msg1, err := ini.WriteInitiation([]byte("kat"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(msg1); got != vecRotInitiation {
		t.Fatalf("rotated initiation drifted:\n got %s\nwant %s", got, vecRotInitiation)
	}

	// NEGATIVE CONTROL: the wire frame must actually change under rotation.
	// sealAdmission whitens the whole body with a keystream derived from the
	// admission key, so a different key must produce a different on-wire frame.
	// If this were byte-identical to the baseline, the vector would not be
	// exercising the rotated key at all.
	if bytes.Equal(mustHex(t, vecRotInitiation), mustHex(t, vecInitiation)) {
		t.Fatal("the rotated initiation is byte-identical to the baseline initiation; " +
			"it is not actually sealed under the rotated key")
	}

	rh, err := resp.ReadInitiation(msg1)
	if err != nil {
		t.Fatalf("a handshake sealed under a freshly rotated admission key was refused: %v", err)
	}

	msg2, gwSess, err := rh.WriteResponse([]byte("ok"), 0)
	if err != nil {
		t.Fatal(err)
	}

	// The RESPONSE is keyed by internal handshake material, never the admission
	// key, so it must be byte-identical to the baseline response even though the
	// initiation was sealed under a different key.
	if got := hex.EncodeToString(msg2); got != vecResponse {
		t.Fatalf("rotation perturbed the response:\n got %s\nwant %s", got, vecResponse)
	}

	cliSess, payload, err := ini.ReadResponse(msg2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, []byte("ok")) {
		t.Fatalf("response payload is %q", payload)
	}

	// The KEY SCHEDULE is the load-bearing half. Rotating the admission key must
	// leave the negotiated transport keys byte-identical to the baseline KAT: the
	// admission key is a wire-only obfuscation and must never enter the chain.
	schedCases := []struct {
		name string
		got  string
		want string
	}{
		{"epoch-0 send demux", hex.EncodeToString(cliSess.sendDemux[:]), vecSendDemux},
		{"epoch-0 send salt", hex.EncodeToString(cliSess.sendSalt[:]), vecSendSalt},
		{"final chaining key", hex.EncodeToString(cliSess.ch.ck[:]), vecFinalCK},
		{"final transcript hash", hex.EncodeToString(cliSess.ch.h[:]), vecFinalH},
	}
	for _, c := range schedCases {
		if c.got != c.want {
			t.Errorf("%s drifted under rotation: got %s, want %s; a rotated admission key "+
				"must not enter the handshake key schedule", c.name, c.got, c.want)
		}
	}

	// POSITIVE CONTROL: the schedule equality means nothing unless the rotation
	// actually produced a working transport session. The first transport message
	// must be byte-identical to the baseline and must open on the gateway side.
	tx, err := cliSess.Seal([]byte("winn3 kat payload"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(tx); got != vecTransport0 {
		t.Fatalf("first transport message drifted under rotation:\n got %s\nwant %s", got, vecTransport0)
	}
	got, err := gwSess.Open(tx)
	if err != nil {
		t.Fatalf("the rotated session's transport message no longer opens: %v", err)
	}
	if string(got) != "winn3 kat payload" {
		t.Fatalf("transport payload is %q", got)
	}
}

// ---------------------------------------------------------------------------
// Fresh two-party rotation vector (added 2026-08-11, lane gen_winn3_core_hsrot)
// ---------------------------------------------------------------------------
//
// The vector above reuses the baseline "winn3-kat-*" seeds, so its whole frame
// is a function of the SAME input material the baseline KAT pins. It proves the
// rotation seam exists, but it never pins the protocol under key material that
// has not appeared in any vector before. This second vector is that FRESH one:
// every key (client static, gateway static, PSK and both admission keys) and
// every random stream is seeded from a namespace ("winn3-hsrot-fresh-*") no
// other vector uses, so nothing here can pass because it accidentally agrees
// with the baseline.
//
// It is a strict TWO-PARTY handshake: one initiator against one responder, the
// same client random stream drawn in both runs, so the ONLY thing that differs
// between the two runs is which admission key is sealed onto the initiator's
// wire. That isolates the rotation seam to its own effect:
//
//   - the initiation WIRE must change (hsFInitRot != hsFInitBase), otherwise
//     the fresh vector is not exercising a rotated key at all;
//   - the RESPONSE must be byte-identical across the two runs (hsFResp), and
//     so must the whole negotiated key schedule (demux, salt, final chaining
//     key, transcript hash) and the first transport message. The admission key
//     is a wire-only obfuscation secret; if any of it leaked into the chain,
//     every one of these pins would go red at once, under unrelated material.
//
// Honest limit, unchanged from above: these values were produced by THIS
// implementation, so they pin stability under fresh material, not
// cross-implementation correctness. They add binding between "rotation exists"
// and "rotation leaves the negotiated session untouched" under key material no
// other vector has exercised.

const (
	hsFInitBase = "f40cf724df2883669d256bf518c7b045c9aaf2f0a910e087e7a16b810ada6fe511636a21e4b48017a2204dc91c8e27ff97d95d5c865161f6e1138e57ae269491cdd222f382e41290981ec31b692ded833dd01f6d92e815a0c306338b7be8f6d52cd775c868504c4ce5a8439ea60464fcc7831f33fcdad2611a434ce78d2eff203f47904279c19ef5"
	hsFInitRot  = "bd347a95d3fa7fc112c08aaab9a6c023cf96d3188e22f225a3763236d470ae502ae12374443e777f593e68a6214c4be387ba11ce3b9a7441e3401fdf7a262e524df60f5f821579f95e3e6c7d8daa2512cab5f9a73b3433a2c6deb2bfb2f651cb920b8befb6a37bb96bdd39282cf7fcbd759aec5194bd7c49884c81f422f897ceff35c78646f51140"
	hsFResp     = "9fbc95b591edf71767fa7d1e809f28805c98982b2d9c19c9352dc2b5472a010312392c20138c222dd54fc599891a5250098b804d0f30b7a44b5efe9961575567bbf206806829a83aa8b5771c2d6d9cd78b13d509ea"
	hsFDemux    = "a0d76e24fbc9789bab3c86b680dd592bcad62f5db91dc8d694ad10b27f279cec"
	hsFSalt     = "a26222d0"
	hsFCK       = "3b3b231bc8d6706348cc035bbfda4d6753baddec56ac8096d1072287c2b2000e"
	hsFH        = "25c7de264f59513615495b2a798996f7d5997355877503448accd8fd241637eb"
	hsFT0       = "97383f7d78e731a8062264f84d019cf22c7b72797f8d1ac5d3b8a73f5ce011ee8914a19366e365d252e4267c2c"
)

// hsFRun completes a two-party handshake on the fresh namespace with the given
// initiator admission keys (the gateway holds the given overlap), drawing the
// client random stream from cliRand each time so successive runs with the same
// stream differ ONLY in the admission key sealed onto the wire.
func hsFRun(t *testing.T, cliKeys, gwKeys [][]byte, cliRand string) (initWire, respWire string, cliSess, gwSess *Session) {
	t.Helper()
	client, err := NewStaticKey(mustSeed("winn3-hsrot-fresh-client"))
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := NewStaticKey(mustSeed("winn3-hsrot-fresh-gw"))
	if err != nil {
		t.Fatal(err)
	}
	gwPub, err := NewPublicKey(gateway.Public())
	if err != nil {
		t.Fatal(err)
	}
	psk := mustSeed("winn3-hsrot-fresh-psk")
	clock := func() time.Time { return vecTime }
	gwp := func(keys [][]byte) GatewayParams {
		return GatewayParams{AdmissionKeys: keys, GatewayID: []byte("winn3-hsrot-fresh-gw-id"), TagSize: DefaultTagSize}
	}
	cliCf := Config{Gateway: gwp(cliKeys), PSK: psk, Rand: newDetReader(cliRand), Now: clock}
	gwCf := Config{Gateway: gwp(gwKeys), PSK: psk, Rand: newDetReader("winn3-hsrot-fresh-gw-rand"), Now: clock}
	ini, err := NewInitiator(cliCf, client, gwPub)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := NewResponder(gwCf, gateway, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	msg1, err := ini.WriteInitiation([]byte("fresh"), 0)
	if err != nil {
		t.Fatal(err)
	}
	rh, err := resp.ReadInitiation(msg1)
	if err != nil {
		t.Fatal(err)
	}
	msg2, gwSess, err := rh.WriteResponse([]byte("ok"), 0)
	if err != nil {
		t.Fatal(err)
	}
	cliSess, payload, err := ini.ReadResponse(msg2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, []byte("ok")) {
		t.Fatalf("response payload is %q", payload)
	}
	return hex.EncodeToString(msg1), hex.EncodeToString(msg2), cliSess, gwSess
}

func TestTwoPartyRotationFreshVector(t *testing.T) {
	// The gateway holds the overlap {rot, base}, newest first, exactly as a live
	// rotation would.
	rotHi := [][]byte{mustSeed("winn3-hsrot-fresh-adm-new"), mustSeed("winn3-hsrot-fresh-adm-old")}
	baseLo := [][]byte{mustSeed("winn3-hsrot-fresh-adm-old")}
	sameRand := "winn3-hsrot-fresh-client-rand"

	// Run 1: a client sealed under the ORIGINAL key, no rotation yet.
	initB, respB, sessB, gwB := hsFRun(t, baseLo, baseLo, sameRand)
	if initB != hsFInitBase {
		t.Fatalf("fresh base initiation drifted:\n got %s\nwant %s", initB, hsFInitBase)
	}
	if respB != hsFResp {
		t.Fatalf("fresh base response drifted:\n got %s\nwant %s", respB, hsFResp)
	}

	// Run 2: a client sealed under the freshly ROTATED key, accepted during the
	// gateway's overlap. Same random stream, so the ONLY difference from run 1
	// is the admission key on the initiator's wire.
	initR, respR, sessR, gwR := hsFRun(t, [][]byte{mustSeed("winn3-hsrot-fresh-adm-new")}, rotHi, sameRand)
	if initR != hsFInitRot {
		t.Fatalf("fresh rotation initiation drifted:\n got %s\nwant %s", initR, hsFInitRot)
	}
	if respR != hsFResp {
		t.Fatalf("fresh rotation response drifted:\n got %s\nwant %s", respR, hsFResp)
	}

	// NEGATIVE CONTROL part 1: the rotation must actually have changed the wire.
	// sealAdmission whitens the whole initiation body with a keystream derived
	// from the admission key, so a different key must produce a different frame.
	if initB == initR {
		t.Fatal("the rotated initiation is byte-identical to the base initiation; " +
			"it is not actually sealed under the rotated key")
	}

	// The response and the whole key schedule must NOT have changed: the
	// admission key is a wire-only obfuscation secret and must never enter the
	// chain. Assert the response equality directly and the schedule against the
	// pinned constants for BOTH runs, then assert the two sessions are identical
	// to one another so the pin cannot be satisfied by luck.
	for _, c := range []struct {
		name string
		got  string
		want string
	}{
		{"epoch-0 send demux", hex.EncodeToString(sessB.sendDemux[:]), hsFDemux},
		{"epoch-0 send salt", hex.EncodeToString(sessB.sendSalt[:]), hsFSalt},
		{"final chaining key", hex.EncodeToString(sessB.ch.ck[:]), hsFCK},
		{"final transcript hash", hex.EncodeToString(sessB.ch.h[:]), hsFH},
	} {
		if c.got != c.want {
			t.Errorf("base schedule %s drifted: got %s, want %s", c.name, c.got, c.want)
		}
	}
	for _, c := range []struct {
		name string
		got  string
		want string
	}{
		{"epoch-0 send demux", hex.EncodeToString(sessR.sendDemux[:]), hsFDemux},
		{"epoch-0 send salt", hex.EncodeToString(sessR.sendSalt[:]), hsFSalt},
		{"final chaining key", hex.EncodeToString(sessR.ch.ck[:]), hsFCK},
		{"final transcript hash", hex.EncodeToString(sessR.ch.h[:]), hsFH},
	} {
		if c.got != c.want {
			t.Errorf("rotated schedule %s drifted: got %s, want %s", c.name, c.got, c.want)
		}
	}
	if sessB.ch.ck != sessR.ch.ck || sessB.ch.h != sessR.ch.h ||
		sessB.sendDemux != sessR.sendDemux || sessB.sendSalt != sessR.sendSalt {
		t.Fatal("rotating the admission key perturbed the negotiated key schedule " +
			"of otherwise identical sessions")
	}

	// NEGATIVE CONTROL part 2: the schedule pins mean nothing unless the rotated
	// session actually transports. The first transport message must be
	// byte-identical to the base and must open on the gateway side.
	txB, err := sessB.Seal([]byte("winn3 fresh payload"), 0)
	if err != nil {
		t.Fatal(err)
	}
	txR, err := sessR.Seal([]byte("winn3 fresh payload"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(txR); got != hsFT0 {
		t.Fatalf("fresh rotation transport drifted:\n got %s\nwant %s", got, hsFT0)
	}
	if hex.EncodeToString(txB) != hex.EncodeToString(txR) {
		t.Fatal("the rotated session's first transport message differs from the base " +
			"session's, though the schedule is pinned identical")
	}
	if got, err := gwR.Open(txR); err != nil || string(got) != "winn3 fresh payload" {
		t.Fatalf("the rotated session's transport no longer opens on the gateway: %v", err)
	}
	if got, err := gwB.Open(txB); err != nil || string(got) != "winn3 fresh payload" {
		t.Fatalf("the base session's transport no longer opens on the gateway: %v", err)
	}
}
