package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

// --- test scaffolding -------------------------------------------------------

// detReader is a deterministic CSPRNG-shaped stream: SHA-256 in counter mode
// over a seed. It exists so that known-answer vectors are reproducible and so
// that a failing test can be replayed exactly.
// It carries a mutex because a Responder is shared across handshakes and reads
// its configured reader from every one of them; without the lock the -race
// build reports the TEST HELPER, not the package.
type detReader struct {
	mu    sync.Mutex
	seed  string
	ctr   uint64
	block []byte
}

func newDetReader(seed string) *detReader { return &detReader{seed: seed} }

func (d *detReader) Read(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for n < len(p) {
		if len(d.block) == 0 {
			var c [8]byte
			binary.BigEndian.PutUint64(c[:], d.ctr)
			d.ctr++
			h := sha256.New()
			h.Write([]byte(d.seed))
			h.Write(c[:])
			d.block = h.Sum(nil)
		}
		k := copy(p[n:], d.block)
		d.block = d.block[k:]
		n += k
	}
	return n, nil
}

var fixedNow = time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)

type harness struct {
	client   *StaticKey
	gateway  *StaticKey
	clientCf Config
	gwCf     Config
	resp     *Responder
	now      time.Time
}

func (h *harness) clock() time.Time { return h.now }

// newHarness builds a matched client/gateway pair with deterministic
// randomness and an injected clock.
func newHarness(t *testing.T, opts ...func(*harness)) *harness {
	t.Helper()
	return newHarnessSeeded(t, "", opts...)
}

// newHarnessSeeded varies every key and every random stream by a seed. Tests
// that need a genuinely UNRELATED peer must use it: with the default seed two
// harnesses are byte-for-byte identical, including their ephemerals, so a
// "foreign" session built from newHarness is the same session and would pass a
// test it should fail.
func newHarnessSeeded(t *testing.T, seed string, opts ...func(*harness)) *harness {
	t.Helper()

	client, err := GenerateStaticKeyFrom(newDetReader("client-static" + seed))
	if err != nil {
		t.Fatalf("client static: %v", err)
	}
	gateway, err := GenerateStaticKeyFrom(newDetReader("gateway-static" + seed))
	if err != nil {
		t.Fatalf("gateway static: %v", err)
	}

	admission := bytes.Repeat([]byte{0xA7}, 32)
	if seed != "" {
		sum := sha256.Sum256([]byte("admission" + seed))
		admission = sum[:]
	}
	gwParams := GatewayParams{
		AdmissionKeys: [][]byte{admission},
		GatewayID:     []byte("gw-test-1" + seed),
		TagSize:       DefaultTagSize,
	}

	h := &harness{client: client, gateway: gateway, now: fixedNow}
	h.clientCf = Config{
		Gateway: gwParams,
		Rand:    newDetReader("client-rand" + seed),
		Now:     h.clock,
	}
	h.gwCf = Config{
		Gateway: gwParams,
		Rand:    newDetReader("gateway-rand" + seed),
		Now:     h.clock,
	}
	for _, o := range opts {
		o(h)
	}

	resp, err := NewResponder(h.gwCf, gateway, func(pub []byte) error {
		if !bytes.Equal(pub, client.Public()) {
			return errors.New("unknown client")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	h.resp = resp
	return h
}

func (h *harness) initiator(t *testing.T) *Initiator {
	t.Helper()
	gwPub, err := NewPublicKey(h.gateway.Public())
	if err != nil {
		t.Fatalf("gateway public: %v", err)
	}
	i, err := NewInitiator(h.clientCf, h.client, gwPub)
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	return i
}

// completeHandshake runs one full exchange and returns both sessions.
func (h *harness) completeHandshake(t *testing.T) (*Session, *Session) {
	t.Helper()
	ini := h.initiator(t)
	msg1, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatalf("write initiation: %v", err)
	}
	rh, err := h.resp.ReadInitiation(msg1)
	if err != nil {
		t.Fatalf("read initiation: %v", err)
	}
	msg2, gwSess, err := rh.WriteResponse(nil, PadAuto)
	if err != nil {
		t.Fatalf("write response: %v", err)
	}
	cliSess, _, err := ini.ReadResponse(msg2)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return cliSess, gwSess
}

// --- round trip -------------------------------------------------------------

func TestHandshakeRoundTrip(t *testing.T) {
	h := newHarness(t)
	ini := h.initiator(t)

	clientHint := []byte("winn3 client hint")
	msg1, err := ini.WriteInitiation(clientHint, PadAuto)
	if err != nil {
		t.Fatalf("write initiation: %v", err)
	}
	if len(msg1) > MaxHandshakeMessage {
		t.Fatalf("initiation is %d bytes, over the %d ceiling", len(msg1), MaxHandshakeMessage)
	}

	rh, err := h.resp.ReadInitiation(msg1)
	if err != nil {
		t.Fatalf("read initiation: %v", err)
	}
	if !bytes.Equal(rh.InitiatorStatic(), h.client.Public()) {
		t.Fatal("responder recovered the wrong client identity")
	}
	if !bytes.Equal(rh.Payload(), clientHint) {
		t.Fatalf("payload mismatch: %q", rh.Payload())
	}

	gwHint := []byte("winn3 gateway hint")
	msg2, gwSess, err := rh.WriteResponse(gwHint, PadAuto)
	if err != nil {
		t.Fatalf("write response: %v", err)
	}

	cliSess, gotHint, err := ini.ReadResponse(msg2)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !bytes.Equal(gotHint, gwHint) {
		t.Fatalf("response payload mismatch: %q", gotHint)
	}

	if cliSess.Role() != RoleInitiator || gwSess.Role() != RoleResponder {
		t.Fatal("roles are wrong")
	}

	// The sessions must actually agree on keys, in both directions.
	for _, dir := range []struct {
		name     string
		from, to *Session
	}{
		{"client to gateway", cliSess, gwSess},
		{"gateway to client", gwSess, cliSess},
	} {
		payload := []byte("hello " + dir.name)
		sealed, err := dir.from.Seal(payload, 0)
		if err != nil {
			t.Fatalf("%s seal: %v", dir.name, err)
		}
		got, err := dir.to.Open(sealed)
		if err != nil {
			t.Fatalf("%s open: %v", dir.name, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("%s payload mismatch", dir.name)
		}
	}
}

// TestHandshakeIsSmallerThanWireGuard is a documentation test with teeth. The
// AmneziaWG initiation this replaces is 148 bytes of body plus S1 junk; the
// point of the admission tag replacing mac1/mac2/cookie is that Winn3 gets
// authorisation for FEWER bytes, not more.
func TestHandshakeMinimumSize(t *testing.T) {
	h := newHarness(t)
	ini := h.initiator(t)
	msg, err := ini.WriteInitiation(nil, 0) // no padding, to measure the floor
	if err != nil {
		t.Fatalf("write initiation: %v", err)
	}
	// tag(32) + eph(32) + sealed static(48) + sealed payload(3+16)
	const want = 32 + 32 + 48 + 19
	if len(msg) != want {
		t.Fatalf("unpadded initiation is %d bytes, expected %d", len(msg), want)
	}
	if len(msg) >= 148 {
		t.Fatalf("initiation (%d) is not smaller than the 148-byte AWG body it replaces", len(msg))
	}
}

func TestHandshakePaddingTarget(t *testing.T) {
	h := newHarness(t)
	for _, target := range []int{200, 512, MaxHandshakeMessage} {
		ini := h.initiator(t)
		msg, err := ini.WriteInitiation(nil, target)
		if err != nil {
			t.Fatalf("target %d: %v", target, err)
		}
		if len(msg) != target {
			t.Fatalf("target %d produced %d bytes", target, len(msg))
		}
		if _, err := h.resp.ReadInitiation(msg); err != nil {
			t.Fatalf("target %d did not verify: %v", target, err)
		}
	}
}

func TestHandshakePaddingTargetTooSmall(t *testing.T) {
	h := newHarness(t)
	ini := h.initiator(t)
	if _, err := ini.WriteInitiation(nil, 8); !errors.Is(err, ErrTargetLenTooSmall) {
		t.Fatalf("expected ErrTargetLenTooSmall, got %v", err)
	}
}

func TestHandshakeOverCeiling(t *testing.T) {
	h := newHarness(t)
	ini := h.initiator(t)
	if _, err := ini.WriteInitiation(nil, MaxHandshakeMessage+1); !errors.Is(err, ErrLongMessage) {
		t.Fatalf("expected ErrLongMessage, got %v", err)
	}
}

func TestHandshakePayloadTooLarge(t *testing.T) {
	h := newHarness(t)
	ini := h.initiator(t)
	if _, err := ini.WriteInitiation(make([]byte, MaxHandshakePayload+1), 0); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("expected ErrPayloadTooLarge, got %v", err)
	}
}

// --- negative paths ---------------------------------------------------------

// TestWrongAdmissionKeyIsSilent is the probe-resistance property: a gateway
// must not react at all to traffic that does not authenticate under its own
// admission key.
func TestWrongAdmissionKeyIsSilent(t *testing.T) {
	h := newHarness(t)
	ini := h.initiator(t)
	msg, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}

	other := newHarness(t, func(hh *harness) {
		hh.gwCf.Gateway.AdmissionKeys = [][]byte{bytes.Repeat([]byte{0x5C}, 32)}
	})
	if _, err := other.resp.ReadInitiation(msg); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected ErrUnauthenticated, got %v", err)
	}
}

// TestGatewayIDBindsTheTag: two gateways mid-rotation on a shared admission key
// must not accept each other's initiations.
func TestGatewayIDBindsTheTag(t *testing.T) {
	h := newHarness(t)
	ini := h.initiator(t)
	msg, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	other := newHarness(t, func(hh *harness) {
		hh.gwCf.Gateway.GatewayID = []byte("gw-test-2")
	})
	if _, err := other.resp.ReadInitiation(msg); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected ErrUnauthenticated across gateway ids, got %v", err)
	}
}

// TestTagSizeBindsTheTag: without binding the tag length, a message sealed for
// a 32-byte-tag gateway would verify at a 16-byte-tag gateway sharing the key,
// because one tag would be a prefix of the other.
func TestTagSizeBindsTheTag(t *testing.T) {
	h := newHarness(t)
	ini := h.initiator(t)
	msg, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	other := newHarness(t, func(hh *harness) {
		hh.gwCf.Gateway.TagSize = MinTagSize
	})
	if _, err := other.resp.ReadInitiation(msg); err == nil {
		t.Fatal("a 16-byte-tag gateway accepted a 32-byte-tag initiation")
	}
}

func TestPSKMismatchFails(t *testing.T) {
	h := newHarness(t, func(hh *harness) {
		hh.clientCf.PSK = bytes.Repeat([]byte{0x11}, 32)
		hh.gwCf.PSK = bytes.Repeat([]byte{0x22}, 32)
	})
	ini := h.initiator(t)
	msg, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.resp.ReadInitiation(msg); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("expected ErrDecrypt on PSK mismatch, got %v", err)
	}
}

func TestPSKMatchSucceeds(t *testing.T) {
	psk := bytes.Repeat([]byte{0x33}, 32)
	h := newHarness(t, func(hh *harness) {
		hh.clientCf.PSK = psk
		hh.gwCf.PSK = psk
	})
	cli, gw := h.completeHandshake(t)
	sealed, err := cli.Seal([]byte("psk ok"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gw.Open(sealed); err != nil {
		t.Fatalf("psk session failed: %v", err)
	}
}

func TestUnauthorisedClientRejected(t *testing.T) {
	h := newHarness(t)
	stranger, err := GenerateStaticKeyFrom(newDetReader("stranger"))
	if err != nil {
		t.Fatal(err)
	}
	gwPub, _ := NewPublicKey(h.gateway.Public())
	ini, err := NewInitiator(h.clientCf, stranger, gwPub)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.resp.ReadInitiation(msg); !errors.Is(err, ErrPeerIdentity) {
		t.Fatalf("expected ErrPeerIdentity, got %v", err)
	}
}

// TestReplayedInitiationRejected is the property that stops a single captured
// packet becoming a permanent gateway detector.
func TestReplayedInitiationRejected(t *testing.T) {
	h := newHarness(t)
	ini := h.initiator(t)
	msg, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.resp.ReadInitiation(msg); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	if _, err := h.resp.ReadInitiation(msg); !errors.Is(err, ErrReplay) {
		t.Fatalf("expected ErrReplay on the second delivery, got %v", err)
	}
	// And a third, so that the cache is not single-shot.
	if _, err := h.resp.ReadInitiation(msg); !errors.Is(err, ErrReplay) {
		t.Fatalf("expected ErrReplay on the third delivery, got %v", err)
	}
}

// TestFailedCryptoDoesNotConsumeReplaySlot: a key holder must not be able to
// fill the replay cache with packets that never pass the crypto.
func TestFailedCryptoDoesNotConsumeReplaySlot(t *testing.T) {
	h := newHarness(t)
	ini := h.initiator(t)
	msg, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	// Reject by identity rather than by tag, so verifyAdmission passes.
	strict := newHarness(t)
	strict.resp, err = NewResponder(strict.gwCf, strict.gateway, func([]byte) error {
		return errors.New("no")
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strict.resp.ReadInitiation(msg); !errors.Is(err, ErrPeerIdentity) {
		t.Fatalf("expected ErrPeerIdentity, got %v", err)
	}
	if n := strict.resp.replay.size(); n != 0 {
		t.Fatalf("replay cache holds %d entries after a rejected handshake", n)
	}
}

func TestTamperedInitiationRejected(t *testing.T) {
	h := newHarness(t)
	ini := h.initiator(t)
	msg, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(msg); i++ {
		bad := append([]byte(nil), msg...)
		bad[i] ^= 0x01
		if _, err := h.resp.ReadInitiation(bad); err == nil {
			t.Fatalf("byte %d could be flipped without rejection", i)
		}
	}
}

func TestTruncatedAndOversizedInitiation(t *testing.T) {
	h := newHarness(t)
	ini := h.initiator(t)
	msg, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.resp.ReadInitiation(msg[:16]); !errors.Is(err, ErrShortMessage) {
		t.Fatalf("expected ErrShortMessage, got %v", err)
	}
	if _, err := h.resp.ReadInitiation(nil); !errors.Is(err, ErrShortMessage) {
		t.Fatalf("expected ErrShortMessage on nil, got %v", err)
	}
	huge := make([]byte, MaxHandshakeMessage+1)
	if _, err := h.resp.ReadInitiation(huge); !errors.Is(err, ErrLongMessage) {
		t.Fatalf("expected ErrLongMessage, got %v", err)
	}
}

func TestClockSkewInsideAndOutsideWindow(t *testing.T) {
	h := newHarness(t)
	ini := h.initiator(t)
	msg, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}

	// Inside MaxSkew (60s default): accepted.
	h.now = fixedNow.Add(45 * time.Second)
	if _, err := h.resp.ReadInitiation(msg); err != nil {
		t.Fatalf("45s of skew should verify: %v", err)
	}

	// Far outside: rejected, and indistinguishably from a wrong key.
	fresh := newHarness(t)
	fresh.now = fixedNow.Add(10 * time.Minute)
	if _, err := fresh.resp.ReadInitiation(msg); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected ErrUnauthenticated far outside skew, got %v", err)
	}
}

func TestAdmissionKeyRotation(t *testing.T) {
	oldKey := bytes.Repeat([]byte{0x01}, 32)
	newKey := bytes.Repeat([]byte{0x02}, 32)

	h := newHarness(t, func(hh *harness) {
		hh.clientCf.Gateway.AdmissionKeys = [][]byte{oldKey}
		// The gateway holds both, newest first, so a rotation completes without
		// an outage.
		hh.gwCf.Gateway.AdmissionKeys = [][]byte{newKey, oldKey}
	})
	ini := h.initiator(t)
	msg, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.resp.ReadInitiation(msg); err != nil {
		t.Fatalf("a client on the old key must still connect mid-rotation: %v", err)
	}
}

func TestTamperedResponseRejected(t *testing.T) {
	h := newHarness(t)
	ini := h.initiator(t)
	msg1, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	rh, err := h.resp.ReadInitiation(msg1)
	if err != nil {
		t.Fatal(err)
	}
	msg2, _, err := rh.WriteResponse(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(msg2); i++ {
		bad := append([]byte(nil), msg2...)
		bad[i] ^= 0x80
		fresh := h.initiator(t)
		if _, err := fresh.WriteInitiation(nil, PadAuto); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ini.ReadResponse(bad); err == nil {
			t.Fatalf("response byte %d could be flipped without rejection", i)
		}
	}
}

// TestResponseFromAnotherGatewayRejected: the response tag is keyed by
// handshake material, so a response minted by anyone else is unrecognisable.
func TestResponseFromAnotherGatewayRejected(t *testing.T) {
	h := newHarness(t)
	ini := h.initiator(t)
	msg1, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}

	// A second gateway with a different static key, same admission key.
	evilStatic, err := GenerateStaticKeyFrom(newDetReader("evil-gateway"))
	if err != nil {
		t.Fatal(err)
	}
	evil, err := NewResponder(h.gwCf, evilStatic, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	// It cannot even read the initiation: h is bound to the real gateway's
	// static key through the transcript.
	if _, err := evil.ReadInitiation(msg1); err == nil {
		t.Fatal("a different gateway static key must not decrypt the initiation")
	}
}

// --- state machine ----------------------------------------------------------

func TestInitiatorSequenceErrors(t *testing.T) {
	h := newHarness(t)
	ini := h.initiator(t)

	if _, err := ini.Retransmit(); !errors.Is(err, ErrStateSequence) {
		t.Fatalf("Retransmit before write should be a sequence error, got %v", err)
	}
	if _, _, err := ini.ReadResponse(make([]byte, 200)); !errors.Is(err, ErrStateSequence) {
		t.Fatalf("ReadResponse before write should be a sequence error, got %v", err)
	}

	msg1, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ini.WriteInitiation(nil, PadAuto); !errors.Is(err, ErrStateSequence) {
		t.Fatalf("a second WriteInitiation should be a sequence error, got %v", err)
	}
	again, err := ini.Retransmit()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, msg1) {
		t.Fatal("Retransmit must be byte-identical")
	}

	rh, err := h.resp.ReadInitiation(msg1)
	if err != nil {
		t.Fatal(err)
	}
	msg2, _, err := rh.WriteResponse(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := rh.WriteResponse(nil, PadAuto); !errors.Is(err, ErrStateSequence) {
		t.Fatalf("a second WriteResponse should be a sequence error, got %v", err)
	}
	if _, _, err := ini.ReadResponse(msg2); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ini.ReadResponse(msg2); !errors.Is(err, ErrStateSequence) {
		t.Fatalf("a second ReadResponse should be a sequence error, got %v", err)
	}
}

// --- configuration ----------------------------------------------------------

func TestConfigValidation(t *testing.T) {
	good := GatewayParams{
		AdmissionKeys: [][]byte{bytes.Repeat([]byte{1}, 32)},
		GatewayID:     []byte("g"),
	}
	client, _ := GenerateStaticKeyFrom(newDetReader("c"))
	gw, _ := GenerateStaticKeyFrom(newDetReader("g"))
	gwPub, _ := NewPublicKey(gw.Public())

	cases := []struct {
		name string
		mut  func(*Config)
	}{
		{"short admission key", func(c *Config) { c.Gateway.AdmissionKeys = [][]byte{{1, 2, 3}} }},
		{"no admission key", func(c *Config) { c.Gateway.AdmissionKeys = nil }},
		{"empty gateway id", func(c *Config) { c.Gateway.GatewayID = nil }},
		{"tag too small", func(c *Config) { c.Gateway.TagSize = 4 }},
		{"tag too large", func(c *Config) { c.Gateway.TagSize = 64 }},
		{"bad psk length", func(c *Config) { c.PSK = []byte{1, 2, 3} }},
		{"window too small", func(c *Config) { c.TokenWindow = 2 }},
		{"window too large", func(c *Config) { c.TokenWindow = MaxTokenWindow + 1 }},
		{"sub-second bucket", func(c *Config) { c.Gateway.Fresh.BucketWindow = time.Millisecond }},
		{"skew below bucket", func(c *Config) {
			c.Gateway.Fresh.BucketWindow = 30 * time.Second
			c.Gateway.Fresh.MaxSkew = time.Second
		}},
		{"two keys on an initiator", func(c *Config) {
			c.Gateway.AdmissionKeys = [][]byte{bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{Gateway: good}
			cfg.Gateway.AdmissionKeys = append([][]byte(nil), good.AdmissionKeys...)
			tc.mut(&cfg)
			if _, err := NewInitiator(cfg, client, gwPub); err == nil {
				t.Fatal("expected a configuration error")
			}
		})
	}

	t.Run("nil accept callback", func(t *testing.T) {
		if _, err := NewResponder(Config{Gateway: good}, gw, nil); !errors.Is(err, ErrConfig) {
			t.Fatalf("a nil AcceptFunc must be refused, got %v", err)
		}
	})
	t.Run("nil static", func(t *testing.T) {
		if _, err := NewInitiator(Config{Gateway: good}, nil, gwPub); !errors.Is(err, ErrConfig) {
			t.Fatalf("expected ErrConfig, got %v", err)
		}
	})
}

func TestKeyHelpers(t *testing.T) {
	if _, err := NewStaticKey([]byte{1, 2, 3}); !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ErrConfig for a short private key, got %v", err)
	}
	if _, err := NewPublicKey([]byte{1, 2, 3}); !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ErrConfig for a short public key, got %v", err)
	}
	// crypto/ecdh ACCEPTS an all-zero X25519 public key encoding and rejects it
	// at agreement time as a low-order point. That is where the check lives, so
	// that is where the test has to look; see TestLowOrderEphemeralRejected for
	// the end-to-end proof that the rejection is actually reached.
	if _, err := NewPublicKey(make([]byte, KeySize)); err != nil {
		t.Fatalf("crypto/ecdh changed behaviour on zero public keys: %v", err)
	}
	k, err := GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	same, err := NewStaticKey(k.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k.Public(), same.Public()) {
		t.Fatal("round-tripping a private key changed the public key")
	}
	a, _ := NewPublicKey(k.Public())
	b, _ := NewPublicKey(k.Public())
	if !a.Equal(b) {
		t.Fatal("equal public keys did not compare equal")
	}
	if a.Equal(nil) {
		t.Fatal("a public key must not equal nil")
	}
}

// TestLowOrderEphemeralRejected proves the degenerate-point check is live on
// the path an attacker actually controls.
//
// This matters more than it looks. An adversary holding the gateway admission
// key can mint a well-formed initiation. If the responder then agreed with a
// low-order ephemeral, the resulting shared secret would be a constant the
// attacker also knows, and the handshake would authenticate nothing. The
// rejection lives inside crypto/ecdh; this test proves we reach it rather than
// swallowing it.
func TestLowOrderEphemeralRejected(t *testing.T) {
	h := newHarness(t)

	// Build a body whose ephemeral field is the all-zero point, then seal it
	// with the gateway's own admission key so that it passes the tag check and
	// reaches the cryptography.
	body := make([]byte, KeySize+KeySize+AEADTagSize+handshakePayloadHeaderSize+AEADTagSize)
	window, _, err := h.gwCf.Gateway.Fresh.resolve()
	if err != nil {
		t.Fatal(err)
	}
	msg := sealAdmission(body,
		h.gwCf.Gateway.AdmissionKeys[0], h.gwCf.Gateway.GatewayID,
		h.gwCf.Gateway.tagSize(), bucketIndex(h.now, window))

	_, err = h.resp.ReadInitiation(msg)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("a low-order ephemeral must be refused as unauthenticated, got %v", err)
	}
}

func TestDetReaderIsDeterministic(t *testing.T) {
	a := make([]byte, 100)
	b := make([]byte, 100)
	if _, err := io.ReadFull(newDetReader("x"), a); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(newDetReader("x"), b); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("the deterministic reader is not deterministic")
	}
}

// TestAcceptRunsOnlyAfterStaticKeyPossessionIsProved pins the AcceptFunc
// contract a stateful callback relies on (the gateway's per-key session cap
// counts in it). Stage 1 is keyed by the client ephemeral and the gateway
// static alone, so anyone holding the fleet-visible admission key and the
// gateway public key can put ANY client's public key into cstat; only Stage
// 2 (cpay, keyed by the static-static DH) proves the sender holds that
// client's private key. A genuine body with cpay corrupted is exactly what
// such a forger sends: the callback must never see it (audit R1 ARGON-2).
func TestAcceptRunsOnlyAfterStaticKeyPossessionIsProved(t *testing.T) {
	h := newHarness(t)
	calls := 0
	resp, err := NewResponder(h.gwCf, h.gateway, func(pub []byte) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := h.initiator(t).WriteInitiation(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	body, _, _, err := verifyAdmission(raw, resp.gatewayParams(), h.now)
	if err != nil {
		t.Fatal(err)
	}
	forged := append([]byte(nil), body...)
	forged[len(forged)-1] ^= 0xff
	if _, err := resp.ReadInitiation(resealUnder(t, forged, h.gwCf.Gateway, h.now, 0)); err == nil {
		t.Fatal("an initiation with a corrupted Stage 2 was accepted")
	}
	if calls != 0 {
		t.Fatalf("AcceptFunc ran %d time(s) for a sender that never proved the client key", calls)
	}
	// The genuine body still authenticates and reaches the callback once.
	if _, err := resp.ReadInitiation(resealUnder(t, body, h.gwCf.Gateway, h.now, 0)); err != nil {
		t.Fatalf("genuine initiation refused: %v", err)
	}
	if calls != 1 {
		t.Fatalf("AcceptFunc ran %d time(s) for one genuine initiation, want 1", calls)
	}
}
