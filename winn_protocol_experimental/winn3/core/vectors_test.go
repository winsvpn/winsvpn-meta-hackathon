package core

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"testing"
	"time"
)

// Known-answer vectors.
//
// These pin the WIRE and the KEY SCHEDULE, not just the round trip. A round-trip
// test passes happily when both ends drift together; these fail the moment a
// label, an ordering, a field position or a KDF input changes, which is exactly
// the class of change that silently breaks interoperability with a client
// already in a user's hands.
//
// They are reproducible because every source of randomness and the clock are
// injected (see GenerateStaticKeyFrom for why ecdh.GenerateKey could not be
// used) and because handshake padding is set to 0 here.
//
// IMPORTANT, and it is the honest limit of these vectors: they were produced by
// THIS implementation, so they prove stability, not correctness. Regenerating
// them from an independent implementation is an outstanding item in the design
// document, and until that happens these catch drift and nothing more.

const (
	vecClientStaticPub  = "d73b4f5570e4bfad37929b3e3eadd3d0ab47e1b0ebeb6bae780a60590a74604b"
	vecGatewayStaticPub = "5a083ff5cf5601844fe2064fafedf43d3ee4c587b3d5dd7a35a36983a3cfcf60"

	vecInitiation = "13133389168a3f6081c07821cf17849e21cd8d858c9486e9d0671df9ad7ddf24" +
		"385a951d767bb00c1fa86cf12acee8339020ddfe4cc7d5065d9696d93b4a0a25" +
		"d49e003db353552646295ddca3eef8b9eac2090dac7371eaa62e717c77b75fa0" +
		"48c82e74faea6c0055f66799651c4edc2b820c698763c3f848929cf7e3e3221a" +
		"9795b9b9afcf"

	vecResponse = "54ae01551b082fed9adecb1d16eb2c049aaa24279d9b6e49223f12f5c740716b" +
		"d99cfb7d398be8ff95d7e2933d0a10056135e9323b52fbd00d79b0d02949eb3d" +
		"7bd50e5187e43a5cf2ecf4d855b0c9bda0da0861be"

	vecTransport0 = "240664fd9cdda2defb167c8f979e0e9ee3506b1f3afc78a25da95f6b29c80daf" +
		"514835de440773fe394d71"

	vecSendDemux = "29cebe3829dcfc62bc8ba6f9835ac636e4e54e504f3a5ca48af2eafb2ca42ff2"
	vecSendSalt  = "9749c6b9"
	vecFinalCK   = "c27ffc068ecc773c02794a10e1633f851bfea0484d549ecdb8f1a5c90365214b"
	vecFinalH    = "0f3ddd5c321350d8bf671604a4f7e3ae5ee9eed2aa84e98fbb8be90531a8e22c"

	// Primitive-level vectors, so that a failure points at the primitive rather
	// than only at the composed message.
	vecAdmissionTag  = "308994266d3072f13ef78b5afe6292125076cd71d2647077569e6b949e23e5d2"
	vecDemuxToken42  = "8d6f49298315d163"
	vecWhitenStream  = "4667a987ffe0c3935102ac152d73910d"
	vecGatewayIDText = "winn3-kat-gw"
	vecBucket        = int64(178692480)
)

// Rotation-fresh key-derivation vectors.
//
// These pin the key-derivation primitives themselves — GenerateStaticKeyFrom
// in keys.go, generateEphemeral in keys.go, and elligator2Codec.GenerateEphemeral
// in elligator.go — under seed material that no other vector in the package uses.
//
// The baseline KAT (vecClientStaticPub etc.) and the rotation vectors in
// handshake_rotation_*.go all draw from the "winn3-kat-*" or "winn3-fresh2-*"
// and "winn3-hsrot-fresh-*" namespaces; these vectors draw from "winn3-keys-fresh-*".
// So a regression that drifted the derivation without changing the full handshake
// layout would still be caught here.
//
// Honest limit, unchanged: these values were produced by THIS implementation,
// so they prove stability, not cross-implementation correctness. They add
// pinning at the primitive level — before any transcript, any admission tag,
// any AEAD — so a fault in the codec's GenerateEphemeral rejection loop or in
// privateFrom surfaces here before it can hide in a round trip.
const (
	// Static key derivation from a fresh seed, testing the keys.go path.
	vecFreshStaticPriv = "553d90a869d386bd71d7947549fec72bf61ac0b2a7d7e108376fb648ada8ba1f"
	vecFreshStaticPub  = "fea3714621d094a472c1203f8ea86351e83b9c98c6490c829825d6f3376f765c"

	// V1 ephemeral key derivation from a fresh seed, testing the keys.go path
	// that the identity codec takes (no elligator).
	vecFreshEphPriv = "885c50fbcf0c647dea838232abbc6725177a87741415898a235b4c7c4db57fa9"
	vecFreshEphPub  = "723632689c68a40f95681dacbdc3e5a42fdcbddf93046da7e8925633964d495e"

	// Elligator2 ephemeral derivation from a fresh seed, testing the elligator.go
	// path. GenerateEphemeral returns (priv, wire); the wire is the uniform
	// representative, and DecodePublic must recover a point that DHs to the
	// same shared secret as the clean public.
	vecFreshEllPriv     = "dd6e8026f434725f829a133d45632c3257a4ba83038b86f518ec7e0a3588f95f"
	vecFreshEllCleanPub = "54031d14519a229c7345c7f2c251b23e71bff3b08f37f85bfbe8dbe28bebf241"
	vecFreshEllWire     = "71bf1de2b46bd4eda0d31012227bf875cdef352d11bc17fdd62295910ac11bde"
	vecFreshEllDecoded  = "37ddce2314ded897d6bd9a757f0dfebc8532dc264a7099e6eff96e8c7928ee59"

	// A fresh peer static key for DH verification. The elligator dirty point must
	// agree with the clean point on a DH against this peer, because the peer
	// clamps and the torsion component is annihilated.
	vecFreshPeerPriv = "88d5507cd1766b2dceaa2a720e900b8fff0f8ad927ad8e0d070daae6867a0152"
	vecFreshPeerPub  = "9102e1dc6dcaf650fb2d0665eb132c6e991f94de0bbbe1ba493d78453918b22b"
)

// vecTime is the pinned clock. It is inside the freshness window of nothing in
// particular; the bucket it produces is an authenticated input to the tag and
// is never transmitted, so pinning it pins the tag.
var vecTime = time.Unix(1786924800, 0).UTC()

func mustSeed(s string) []byte {
	b := make([]byte, KeySize)
	if _, err := newDetReader(s).Read(b); err != nil {
		panic(err)
	}
	return b
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad vector hex: %v", err)
	}
	return b
}

// katParties rebuilds the pinned configuration.
func katParties(t *testing.T) (*Initiator, *Responder) {
	t.Helper()
	client, err := NewStaticKey(mustSeed("winn3-kat-client-static"))
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := NewStaticKey(mustSeed("winn3-kat-gateway-static"))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(client.Public()); got != vecClientStaticPub {
		t.Fatalf("client static public key drifted: %s", got)
	}
	if got := hex.EncodeToString(gateway.Public()); got != vecGatewayStaticPub {
		t.Fatalf("gateway static public key drifted: %s", got)
	}

	gp := GatewayParams{
		AdmissionKeys: [][]byte{mustSeed("winn3-kat-admission")},
		GatewayID:     []byte(vecGatewayIDText),
		TagSize:       DefaultTagSize,
	}
	clock := func() time.Time { return vecTime }
	psk := mustSeed("winn3-kat-psk")

	cliCf := Config{Gateway: gp, PSK: psk, Rand: newDetReader("winn3-kat-client-rand"), Now: clock}
	gwCf := Config{Gateway: gp, PSK: psk, Rand: newDetReader("winn3-kat-gateway-rand"), Now: clock}

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
	return ini, resp
}

func TestKnownAnswerHandshake(t *testing.T) {
	ini, resp := katParties(t)

	msg1, err := ini.WriteInitiation([]byte("kat"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(msg1); got != vecInitiation {
		t.Fatalf("initiation drifted:\n got %s\nwant %s", got, vecInitiation)
	}

	rh, err := resp.ReadInitiation(msg1)
	if err != nil {
		t.Fatalf("the pinned initiation no longer verifies: %v", err)
	}
	if !bytes.Equal(rh.Payload(), []byte("kat")) {
		t.Fatalf("payload is %q", rh.Payload())
	}

	msg2, gwSess, err := rh.WriteResponse([]byte("ok"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(msg2); got != vecResponse {
		t.Fatalf("response drifted:\n got %s\nwant %s", got, vecResponse)
	}

	cliSess, payload, err := ini.ReadResponse(msg2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, []byte("ok")) {
		t.Fatalf("response payload is %q", payload)
	}

	// The key schedule, not just the wire.
	if got := hex.EncodeToString(cliSess.sendDemux[:]); got != vecSendDemux {
		t.Errorf("epoch-0 send demux key drifted: %s", got)
	}
	if got := hex.EncodeToString(cliSess.sendSalt[:]); got != vecSendSalt {
		t.Errorf("epoch-0 send nonce salt drifted: %s", got)
	}
	if got := hex.EncodeToString(cliSess.ch.ck[:]); got != vecFinalCK {
		t.Errorf("final chaining key drifted: %s", got)
	}
	if got := hex.EncodeToString(cliSess.ch.h[:]); got != vecFinalH {
		t.Errorf("final transcript hash drifted: %s", got)
	}
	// Both ends must land on the same schedule.
	if cliSess.ch.ck != gwSess.ch.ck || cliSess.ch.h != gwSess.ch.h {
		t.Fatal("the two ends derived different chain state")
	}

	tx, err := cliSess.Seal([]byte("winn3 kat payload"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(tx); got != vecTransport0 {
		t.Fatalf("first transport message drifted:\n got %s\nwant %s", got, vecTransport0)
	}
	got, err := gwSess.Open(tx)
	if err != nil {
		t.Fatalf("the pinned transport message no longer opens: %v", err)
	}
	if string(got) != "winn3 kat payload" {
		t.Fatalf("transport payload is %q", got)
	}
}

func TestKnownAnswerPrimitives(t *testing.T) {
	tag := make([]byte, DefaultTagSize)
	admissionTag(mustSeed("winn3-kat-admission"), []byte(vecGatewayIDText),
		DefaultTagSize, vecBucket, bytes.Repeat([]byte{0x5A}, 64), tag)
	if got := hex.EncodeToString(tag); got != vecAdmissionTag {
		t.Errorf("admission tag drifted:\n got %s\nwant %s", got, vecAdmissionTag)
	}

	var dk [KeySize]byte
	copy(dk[:], mustSeed("winn3-kat-demux"))
	tok := demuxToken(&dk, 42)
	if got := hex.EncodeToString(tok[:]); got != vecDemuxToken42 {
		t.Errorf("demux token drifted:\n got %s\nwant %s", got, vecDemuxToken42)
	}

	ks := expandFrom([]byte("tag"), []byte("key"), labelAdmitWhtn, 16)
	if got := hex.EncodeToString(ks); got != vecWhitenStream {
		t.Errorf("whitening keystream drifted:\n got %s\nwant %s", got, vecWhitenStream)
	}
}

// TestKnownAnswerLengths pins the geometry separately, because a length change
// is a wire break even when every byte that remains is correct.
func TestKnownAnswerLengths(t *testing.T) {
	cases := []struct {
		name string
		vec  string
		want int
	}{
		// tag 32 + ephemeral 32 + sealed static 48 + sealed payload (3 + 3 + 16)
		{"initiation", vecInitiation, 134},
		// tag 32 + ephemeral 32 + sealed payload (3 + 2 + 16)
		{"response", vecResponse, 85},
		// demux 8 + inner length 2 + payload 17 + tag 16
		{"transport", vecTransport0, 43},
	}
	for _, tc := range cases {
		if got := len(mustHex(t, tc.vec)); got != tc.want {
			t.Errorf("%s vector is %d bytes, expected %d", tc.name, got, tc.want)
		}
	}
	if got := TransportOverhead(); got != 26 {
		t.Errorf("transport overhead is %d, expected 26", got)
	}
}

// TestSuiteIdentityIsPinned: the suite string is an input to the transcript
// hash, so changing it silently changes every key in the protocol. It must move
// only with a deliberate version bump.
func TestSuiteIdentityIsPinned(t *testing.T) {
	if WireVersion != "winn/3" {
		t.Errorf("wire version is %q", WireVersion)
	}
	if Suite != "winn3-x25519-mlkem768-chacha20poly1305-sha256" {
		t.Errorf("suite is %q", Suite)
	}
	if protocolLabel != "winn/3 winn3-x25519-mlkem768-chacha20poly1305-sha256" {
		t.Errorf("protocol label is %q", protocolLabel)
	}
}

// TestKnownAnswerKeyDerivation pins the key-derivation primitives in keys.go
// and elligator.go at the POINT where the bytes are produced, before they touch
// any handshake, any transcript, any admission tag, or any AEAD.
//
// Why this exists alongside the baseline KAT and the rotation vectors:
//
//   - The baseline KAT pins a whole handshake but only one scalar per role.
//     A fault in privateFrom or in generateEphemeral that happened to produce
//     a different key on the first draw but still round-tripped would pass the
//     full-handshake test and still ship.
//   - The rotation fresh vector (handshake_rotation_fresh_vector_test.go)
//     exercises the full lifecycle but never asserts on the elligator output
//     bytes directly — it asserts on the composed initiation and response,
//     which mix the ephemeral with half a dozen other derived values.
//
// This test isolates the derivation. It runs under a deterministic reader so
// the rejection loop in GenerateEphemeral is fully reproducible, and it asserts
// BOTH directions of the elligator invariant: the dirty (torsion-laden) public
// must DH to the same shared secret as the clean public against an independent
// peer, and the two publics must NOT be byte-identical (proving the torsion
// was actually added rather than elided).
func TestKnownAnswerKeyDerivation(t *testing.T) {
	// Static key derivation: GenerateStaticKeyFrom over a fresh deterministic
	// reader must produce the pinned private scalar and public key.
	sk, err := GenerateStaticKeyFrom(newDetReader("winn3-keys-fresh-static"))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(sk.Bytes()); got != vecFreshStaticPriv {
		t.Errorf("fresh static private key drifted:\n got %s\nwant %s", got, vecFreshStaticPriv)
	}
	if got := hex.EncodeToString(sk.Public()); got != vecFreshStaticPub {
		t.Errorf("fresh static public key drifted:\n got %s\nwant %s", got, vecFreshStaticPub)
	}

	// V1 (identity codec) ephemeral derivation: generateEphemeral over a fresh
	// reader. This is the path taken when Config.Codec is nil.
	eph, err := generateEphemeral(newDetReader("winn3-keys-fresh-eph"))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(eph.priv.Bytes()); got != vecFreshEphPriv {
		t.Errorf("fresh v1 ephemeral private key drifted:\n got %s\nwant %s", got, vecFreshEphPriv)
	}
	if got := hex.EncodeToString(eph.public()); got != vecFreshEphPub {
		t.Errorf("fresh v1 ephemeral public key drifted:\n got %s\nwant %s", got, vecFreshEphPub)
	}

	// Elligator2 ephemeral derivation: GenerateEphemeral over a fresh reader.
	kg := Elligator2Codec.(EphemeralKeygen)
	priv, wire, err := kg.GenerateEphemeral(newDetReader("winn3-keys-fresh-ell"))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(priv); got != vecFreshEllPriv {
		t.Errorf("fresh elligator private scalar drifted:\n got %s\nwant %s", got, vecFreshEllPriv)
	}
	if got := hex.EncodeToString(wire); got != vecFreshEllWire {
		t.Errorf("fresh elligator representative drifted:\n got %s\nwant %s", got, vecFreshEllWire)
	}

	// The wire must round-trip back to the pinned decoded public point.
	decoded, err := Elligator2Codec.DecodePublic(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(decoded); got != vecFreshEllDecoded {
		t.Errorf("fresh elligator decoded public drifted:\n got %s\nwant %s", got, vecFreshEllDecoded)
	}

	// The private scalar must produce the pinned clean X25519 public key.
	sk1, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(sk1.PublicKey().Bytes()); got != vecFreshEllCleanPub {
		t.Errorf("fresh elligator clean public drifted:\n got %s\nwant %s", got, vecFreshEllCleanPub)
	}

	// NEGATIVE control: the clean public and the decoded public must differ.
	// If they were identical the torsion addition is being skipped and the
	// codec would be distinguishable from random bytes by a single scalar
	// mult per packet.
	if bytes.Equal(decoded, sk1.PublicKey().Bytes()) {
		t.Fatal("elligator representative decoded to the clean public; " +
			"the torsion component was not added and the codec is a no-op")
	}

	// DH agreement: the clean scalar and the dirty (decoded) point must
	// produce the same shared secret against an independent peer. This is the
	// algebraic property 8k(P+T) = 8kP that the torsion addition depends on.
	peer, err := ecdh.X25519().NewPrivateKey(mustSeed("winn3-keys-fresh-peer"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := sk1.ECDH(peer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	got, err := peer.ECDH(mustECDHPublic(t, decoded))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Fatal("the elligator dirty point and the clean point do not agree on DH; " +
			"the torsion randomisation is corrupting the shared secret")
	}

	// Pin the peer too, so the whole DH triple is reproducible.
	if got := hex.EncodeToString(peer.PublicKey().Bytes()); got != vecFreshPeerPub {
		t.Errorf("fresh peer public drifted:\n got %s\nwant %s", got, vecFreshPeerPub)
	}
	if got := hex.EncodeToString(peer.Bytes()); got != vecFreshPeerPriv {
		t.Errorf("fresh peer private drifted:\n got %s\nwant %s", got, vecFreshPeerPriv)
	}
}
