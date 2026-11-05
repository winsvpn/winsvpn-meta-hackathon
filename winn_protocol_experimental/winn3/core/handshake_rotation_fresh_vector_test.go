package core

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

// Fresh-key rotation vector.
//
// handshake_rotation_vector_test.go pins a rotation KAT that reuses the same
// baseline seeds as vectors_test.go (the "winn3-kat-*" material), so its whole
// frame is a function of the SAME input material the baseline pins. It proves
// the rotation seam exists and that rotation leaves the negotiated session
// byte-identical to the baseline KAT. What it does not do is pin the protocol
// under input material that has never appeared in any vector before.
//
// This file is that second, FRESH vector: every key (client static, gateway
// static, PSK and all three admission keys) and every random stream is seeded
// from a namespace ("winn3-fresh2-*") that no other vector uses. Nothing here
// can pass because it accidentally agrees with the baseline; this is a
// byte-for-byte pin of the handshake under unrelated key material.
//
// It also exercises the FULL rotation lifecycle on ONE responder, which is the
// part of the seam that a single-shot KAT cannot reach:
//
//   - a client sealed under the ORIGINAL key A completes before any rotation;
//   - the responder is rotated IN PLACE (SetAdmissionKeys) to a {B, A} overlap
//     while it is still live -- the replay cache is carried across, never
//     rebuilt (see SetAdmissionKeys for why a rebuild is a security defect);
//   - a client freshly sealed under the NEW key B completes during the overlap,
//     and its wire frame and key schedule are pinned (vecFreshRot*);
//   - a client still on the OLD key A is accepted during the overlap -- the
//     whole point of an overlap is that retirement is not a cliff;
//   - a second rotation to {C, B} retires A, after which a client sealed under
//     A is refused (ErrUnauthenticated) while a client on B still completes.
//
// The load-bearing negative controls are the same three as the baseline KAT:
//
//   - rotation actually changed the wire (vecFreshRotInitiation !=
//     vecFreshOldInitiation), else the fresh vector would not be exercising the
//     rotated key at all;
//   - the two sessions genuinely differ (fresh-A schedule != fresh-B schedule),
//     else the two vectors would be one;
//   - the pins are positive, so a refactor that silently perturbed any of:
//     the wire, the response, the demux keys, the salts, the chain or the first
//     transport message -- under UNRELATED key material -- goes red naming the
//     exact stage.
//
// Honest limit, unchanged from vectors_test.go: these values were produced by
// THIS implementation. They pin stability under fresh material; they do not
// prove cross-implementation correctness.

const (
	// Pre-rotation: a client sealed under the original key A. Every value
	// derives from the "winn3-fresh2-*" namespace, unrelated to any vector seed.
	fvecOldInitiation = "28984d03b3949ea8d7f44adfe587cc108eea2a408919663d4bc8b1872feff8c35" +
		"7094f2879b0789cfb707aa3f0cd44baf3a55b7c3b6c10131b9df8110439104322c3" +
		"cb91de2f1d2afc3bc25431ae8f94c714d9a611032f33710dd42b51c68216c915101" +
		"d509343ed82ac821bbec952eb3b0da8d4b0ac1cdbc3ef7a18e933d5164de9dafc4" +
		"5d7d1df"
	fvecOldResponse = "10ce0d61070a50bd4625733976f80081b3e0d00e2dbb6e873dbfe3b11b5086689" +
		"0dfb6d5bc698ecee8f6c75d3fef61cfc9b5cc3d6e99d6cd02a7cf50a3a657360a1" +
		"679a764ce2bb3ffe3d2dca2df65cf4f5fca6f3e"
	fvecOldFinalCK = "2f333b0c8a9f0c1b66b3bd9c5d72711e6bcc1e85fa35be6a214130eaf521f7f5"
	fvecOldFinalH  = "ee52f67d901ef5d544a64a16f900c9cddca9774b3da720989e9093c6c9ddb219"
	fvecOldDemux   = "7e3150f28caac71b754e9a9a66a49e6654381823c1e2cb2e5a633b81b192a65e"
	fvecOldSalt    = "08c57e9b"
	fvecOldTrans0  = "6ef5525aa84f622612f73d89cf4c46d10b251a80f7f84190a1d8255d0952a1d82" +
		"0e049e7cfd8cbc16fafcc8598"

	// During the overlap, a client freshly sealed under the NEW key B.
	fvecRotInitiation = "03b6a7fe11015a4ffdaee2bbbd943586e051adf59535e7743ac7ebdd110f54095" +
		"5cf93cace31fc7543d42714755e89c5b741e5ad7801fbfa8b54693c5a75ab2f3e8" +
		"1397da5f5f19d2ca27b19011cacd62937df53b4b2fa324f655c2f77947e800b33d" +
		"486cf03e6b886a3aa0a2a29f4eac372a71c19b62c43b2d7d26b9802bd3dfa03bc1" +
		"38706020e"
	fvecRotResponse = "01fd6110aa4fe389db1ba3e03e18d126aa0946f360e96743328cec3b188a89ac5f" +
		"0e4117510e2977dac1aedc2aae436e95bf89d18affcc5f4e443c6454319d9e6bc8" +
		"72b103873e0440514ab45b06044865cff2fdd1"
	fvecRotFinalCK = "9bf8934fe4798f6b9eaa99ccccf68e4169ee36b343c6122ad52e8477b2584075"
	fvecRotFinalH  = "057f0457a26e2c43d4d11b52a714a1ee6369d1a4f8781a0b71bb8d1aecb3751d"
	fvecRotDemux   = "9f465a6d32dd3b65fdaf3bcaef29fa87ad00bc804321ec35ba783f7b1aba4834"
	fvecRotSalt    = "77346b5c"
	fvecRotTrans0  = "9659f9ba3152cf42607d183a161e6f43da217c1081166553fcb7064d955ee6921" +
		"dc33c2e0cf7fbbf06a08fa4df"
)

// freshGWP returns a gateway profile over the given admission key set, pinned to
// the same identity and tag size everywhere so the only thing that varies is the
// key rotation.
func freshGWP(keys [][]byte) GatewayParams {
	return GatewayParams{AdmissionKeys: keys, GatewayID: []byte("winn3-fresh2-gw"), TagSize: DefaultTagSize}
}

// freshVectorParties builds a one-responder rig over entirely fresh material.
// The responder starts with {keyA}. keyB rotates in during the test; keyC is the
// second-generation key that retires keyA. Every client draws from its own
// random stream so each initiation is a genuinely distinct handshake rather than
// a byte-for-byte clone that the replay cache would (correctly) refuse.
func freshVectorParties(t *testing.T) (client *StaticKey, resp *Responder, keyA, keyB, keyC, psk []byte, clock func() time.Time, gwPub *PublicKey) {
	t.Helper()
	var err error
	client, err = NewStaticKey(mustSeed("winn3-fresh2-client-static"))
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := NewStaticKey(mustSeed("winn3-fresh2-gateway-static"))
	if err != nil {
		t.Fatal(err)
	}
	keyA = mustSeed("winn3-fresh2-adm-old")
	keyB = mustSeed("winn3-fresh2-adm-new")
	keyC = mustSeed("winn3-fresh2-adm-next")
	psk = mustSeed("winn3-fresh2-psk")
	clock = func() time.Time { return vecTime }
	gwPub, err = NewPublicKey(gateway.Public())
	if err != nil {
		t.Fatal(err)
	}
	gwCf := Config{Gateway: freshGWP([][]byte{keyA}), PSK: psk, Rand: newDetReader("winn3-fresh2-gateway-rand"), Now: clock}
	resp, err = NewResponder(gwCf, gateway, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return
}

// freshInitiator returns a fresh initiator sealed under the given admission keys
// and drawing from a unique random stream, so successive initiations are
// genuinely independent.
func freshInitiator(t *testing.T, client *StaticKey, keys [][]byte, randSeed string, psk []byte, clock func() time.Time, gwPub *PublicKey) *Initiator {
	t.Helper()
	cf := Config{Gateway: freshGWP(keys), PSK: psk, Rand: newDetReader(randSeed), Now: clock}
	ini, err := NewInitiator(cf, client, gwPub)
	if err != nil {
		t.Fatal(err)
	}
	return ini
}

// runHandshake completes a full handshake and returns the client session, the
// gateway session, the initiation wire and the response wire.
func runHandshake(t *testing.T, ini *Initiator, resp *Responder) (cliSess, gwSess *Session, init, respWire []byte) {
	t.Helper()
	var err error
	init, err = ini.WriteInitiation([]byte("fresh"), 0)
	if err != nil {
		t.Fatal(err)
	}
	rh, err := resp.ReadInitiation(init)
	if err != nil {
		t.Fatalf("initiation refused: %v", err)
	}
	respWire, gwSess, err = rh.WriteResponse([]byte("ok"), 0)
	if err != nil {
		t.Fatal(err)
	}
	var payload []byte
	cliSess, payload, err = ini.ReadResponse(respWire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, []byte("ok")) {
		t.Fatalf("response payload is %q", payload)
	}
	return
}

func assertSchedule(t *testing.T, sess *Session, ck, h, demux, salt string) {
	t.Helper()
	if got := hex.EncodeToString(sess.ch.ck[:]); got != ck {
		t.Errorf("final chaining key drifted: got %s, want %s", got, ck)
	}
	if got := hex.EncodeToString(sess.ch.h[:]); got != h {
		t.Errorf("final transcript hash drifted: got %s, want %s", got, h)
	}
	if got := hex.EncodeToString(sess.sendDemux[:]); got != demux {
		t.Errorf("epoch-0 send demux key drifted: got %s, want %s", got, demux)
	}
	if got := hex.EncodeToString(sess.sendSalt[:]); got != salt {
		t.Errorf("epoch-0 send nonce salt drifted: got %s, want %s", got, salt)
	}
}

func TestFreshKeyRotationVectorLifecycle(t *testing.T) {
	client, resp, keyA, keyB, keyC, psk, clock, gwPub := freshVectorParties(t)

	// --- Generation 0: a client sealed under the ORIGINAL key A, before any
	// rotation. This pins the baseline of the fresh namespace.
	iniA := freshInitiator(t, client, [][]byte{keyA}, "winn3-fresh2-client-rand-A", psk, clock, gwPub)
	cliA, gwA, initA, respA := runHandshake(t, iniA, resp)
	if got := hex.EncodeToString(initA); got != fvecOldInitiation {
		t.Fatalf("fresh pre-rotation initiation drifted:\n got %s\nwant %s", got, fvecOldInitiation)
	}
	if got := hex.EncodeToString(respA); got != fvecOldResponse {
		t.Fatalf("fresh pre-rotation response drifted:\n got %s\nwant %s", got, fvecOldResponse)
	}
	assertSchedule(t, cliA, fvecOldFinalCK, fvecOldFinalH, fvecOldDemux, fvecOldSalt)
	if cliA.ch.ck != gwA.ch.ck || cliA.ch.h != gwA.ch.h {
		t.Fatal("the two ends derived different chain state")
	}
	txA, err := cliA.Seal([]byte("winn3 fresh payload"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(txA); got != fvecOldTrans0 {
		t.Fatalf("fresh pre-rotation transport drifted:\n got %s\nwant %s", got, fvecOldTrans0)
	}
	if _, err := gwA.Open(txA); err != nil {
		t.Fatalf("fresh pre-rotation transport no longer opens: %v", err)
	}

	// --- Rotation 1, IN PLACE: responder goes {A} -> {B, A}. The replay cache
	// and clock are carried across untouched; this is the seam the document says
	// is the only safe way to rotate (rebuilding the Responder reopens the replay
	// window and reads as a rotation clock).
	if err := resp.SetAdmissionKeys([][]byte{keyB, keyA}); err != nil {
		t.Fatal(err)
	}
	if n := resp.AdmissionKeyCount(); n != 2 {
		t.Fatalf("overlap not applied: gateway holds %d keys", n)
	}

	// --- Generation 1: a client freshly sealed under the NEW key B completes
	// during the overlap. This is the fresh rotation vector.
	iniB := freshInitiator(t, client, [][]byte{keyB}, "winn3-fresh2-client-rand-B", psk, clock, gwPub)
	cliB, gwB, initB, respB := runHandshake(t, iniB, resp)
	if got := hex.EncodeToString(initB); got != fvecRotInitiation {
		t.Fatalf("fresh rotation initiation drifted:\n got %s\nwant %s", got, fvecRotInitiation)
	}
	if got := hex.EncodeToString(respB); got != fvecRotResponse {
		t.Fatalf("fresh rotation response drifted:\n got %s\nwant %s", got, fvecRotResponse)
	}
	assertSchedule(t, cliB, fvecRotFinalCK, fvecRotFinalH, fvecRotDemux, fvecRotSalt)
	if cliB.ch.ck != gwB.ch.ck || cliB.ch.h != gwB.ch.h {
		t.Fatal("fresh rotated session: the two ends derived different chain state")
	}
	txB, err := cliB.Seal([]byte("winn3 fresh payload"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(txB); got != fvecRotTrans0 {
		t.Fatalf("fresh rotation transport drifted:\n got %s\nwant %s", got, fvecRotTrans0)
	}
	if _, err := gwB.Open(txB); err != nil {
		t.Fatalf("fresh rotation transport no longer opens on the gateway: %v", err)
	}

	// --- NEGATIVE CONTROL: the fresh rotation vector must actually differ from
	// the fresh pre-rotation vector. If sealAdmission's whitening stopped being
	// key-dependent, a rotated key would not change the frame and the above pins
	// would be trivially satisfied.
	if bytes.Equal(mustHex(t, fvecOldInitiation), mustHex(t, fvecRotInitiation)) {
		t.Fatal("the rotated initiation is byte-identical to the pre-rotation initiation; " +
			"it is not actually sealed under the rotated key")
	}

	// --- NEGATIVE CONTROL: the two completed sessions must be genuinely
	// different (different fresh ephemerals, different negotiated keys). If the
	// fresh vector converged on the pre-rotation schedule, the two vectors would
	// be one and the pin would prove nothing about rotation.
	if cliA.ch.ck == cliB.ch.ck || cliA.ch.h == cliB.ch.h {
		t.Fatal("the pre-rotation session and the rotated session derived identical chain state; " +
			"the fresh rotation vector is not an independent handshake")
	}

	// --- Overlap courtesy: a client STILL on the old key A is accepted during
	// the overlap. An overlap exists precisely so retirement is not a cliff.
	iniA2 := freshInitiator(t, client, [][]byte{keyA}, "winn3-fresh2-client-rand-A2", psk, clock, gwPub)
	runHandshake(t, iniA2, resp)

	// --- Rotation 2: {B, A} -> {C, B} retires A in place.
	if err := resp.SetAdmissionKeys([][]byte{keyC, keyB}); err != nil {
		t.Fatal(err)
	}

	// A is now retired and MUST be refused -- the negative half of the
	// previous overlap assertion.
	iniA3 := freshInitiator(t, client, [][]byte{keyA}, "winn3-fresh2-client-rand-A3", psk, clock, gwPub)
	msgA3, err := iniA3.WriteInitiation([]byte("fresh"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resp.ReadInitiation(msgA3); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("a retired key must stop being accepted, got %v", err)
	}

	// B still works after A is gone -- the surviving half of the same overlap.
	iniB2 := freshInitiator(t, client, [][]byte{keyB}, "winn3-fresh2-client-rand-B2", psk, clock, gwPub)
	runHandshake(t, iniB2, resp)
}
