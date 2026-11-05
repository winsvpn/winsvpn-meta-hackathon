package core

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"
)

// failingReader hands out n bytes and then fails, so that every path which
// draws randomness can be made to fail on demand.
type failingReader struct{ remaining int }

func (f *failingReader) Read(p []byte) (int, error) {
	if f.remaining <= 0 {
		return 0, errors.New("entropy exhausted")
	}
	n := len(p)
	if n > f.remaining {
		n = f.remaining
	}
	for i := range p[:n] {
		p[i] = 0x5A
	}
	f.remaining -= n
	return n, nil
}

// TestProductionDefaults runs a full exchange with an entirely zero-valued
// Config beyond the gateway profile: crypto/rand, time.Now, the default codec
// and the default window. This is the path a shipping caller takes, and it must
// not depend on anything a test injected.
func TestProductionDefaults(t *testing.T) {
	client, err := GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	gp := GatewayParams{
		AdmissionKeys: [][]byte{bytes.Repeat([]byte{0x77}, 32)},
		GatewayID:     []byte("defaults"),
	}
	cfg := Config{Gateway: gp}

	gwPub, err := NewPublicKey(gateway.Public())
	if err != nil {
		t.Fatal(err)
	}
	ini, err := NewInitiator(cfg, client, gwPub)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := NewResponder(cfg, gateway, func(pub []byte) error {
		if !bytes.Equal(pub, client.Public()) {
			return errors.New("unknown client")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resp.Public(), gateway.Public()) {
		t.Fatal("Responder.Public did not return the gateway static key")
	}

	msg1, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	rh, err := resp.ReadInitiation(msg1)
	if err != nil {
		t.Fatal(err)
	}
	msg2, gwSess, err := rh.WriteResponse(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	cliSess, _, err := ini.ReadResponse(msg2)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := cliSess.Seal([]byte("defaults work"), 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := gwSess.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "defaults work" {
		t.Fatalf("payload is %q", got)
	}
}

// TestEntropyFailurePropagates: a failing CSPRNG must surface as an error, not
// as a handshake built from predictable bytes.
func TestEntropyFailurePropagates(t *testing.T) {
	h := newHarness(t)
	gwPub, err := NewPublicKey(h.gateway.Public())
	if err != nil {
		t.Fatal(err)
	}

	for _, budget := range []int{0, 4, 8, 20} {
		cfg := h.clientCf
		cfg.Rand = &failingReader{remaining: budget}
		ini, err := NewInitiator(cfg, h.client, gwPub)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ini.WriteInitiation(nil, PadAuto); err == nil {
			t.Fatalf("budget %d: a failing reader must not yield an initiation", budget)
		}
	}

	// And on the responder's side of the exchange.
	ini := h.initiator(t)
	msg1, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	starved := h.gwCf
	starved.Rand = &failingReader{remaining: 2}
	resp, err := NewResponder(starved, h.gateway, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	rh, err := resp.ReadInitiation(msg1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := rh.WriteResponse(nil, PadAuto); err == nil {
		t.Fatal("a failing reader must not yield a response")
	}
}

func TestHandshakePaddingArgumentChecks(t *testing.T) {
	if _, err := handshakePadding(nil, 10, -7); !errors.Is(err, ErrConfig) {
		t.Fatalf("a negative target that is not PadAuto must be refused, got %v", err)
	}
	n, err := handshakePadding(nil, 10, 0)
	if err != nil || n != 0 {
		t.Fatalf("zero means no padding: (%d, %v)", n, err)
	}
	n, err = handshakePadding(nil, 10, 25)
	if err != nil || n != 15 {
		t.Fatalf("explicit target: (%d, %v)", n, err)
	}
	if _, err := handshakePadding(&failingReader{}, 10, PadAuto); err == nil {
		t.Fatal("PadAuto with a dead reader must fail")
	}
}

// TestDecodeHandshakePayloadRejects covers the inner parser directly. These
// states are unreachable from the wire while the AEAD holds, which is exactly
// why they are worth pinning: they are the last line if it ever does not.
func TestDecodeHandshakePayloadRejects(t *testing.T) {
	cases := map[string][]byte{
		"empty":               nil,
		"header truncated":    {0x00, 0x01},
		"unknown flags set":   {0x02, 0x00, 0x00},
		"unknown flags high": {0x80, 0x00, 0x00},
		"length past the end": {0x00, 0x00, 0x10},
		"length beyond ceiling": append([]byte{0x00, 0x02, 0x00},
			make([]byte, MaxHandshakePayload+1)...),
	}
	for name, in := range cases {
		if _, _, err := decodeHandshakePayload(in); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: expected ErrDecrypt, got %v", name, err)
		}
	}

	good := append([]byte{0x00, 0x00, 0x03}, []byte("abc")...)
	good = append(good, make([]byte, 40)...) // padding
	out, _, err := decodeHandshakePayload(good)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "abc" {
		t.Fatalf("payload is %q; padding leaked", out)
	}
	dual, _, err := decodeHandshakePayload(append([]byte{0x01, 0x00, 0x03}, []byte("abc")...))
	if err != nil {
		t.Fatalf("dual-auth flag must decode: %v", err)
	}
	if string(dual) != "abc" {
		t.Fatalf("dual payload is %q; want abc", dual)
	}
}

func TestEncodeHandshakePayloadRejectsOversize(t *testing.T) {
	if _, err := encodeHandshakePayload(0, make([]byte, MaxHandshakePayload+1), 0); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("expected ErrPayloadTooLarge, got %v", err)
	}
}

func TestIdentityCodecRejectsWrongSizes(t *testing.T) {
	c := DefaultEphemeralCodec
	if c.WireSize() != KeySize {
		t.Fatalf("wire size is %d", c.WireSize())
	}
	if _, err := c.EncodePublic(make([]byte, 31)); !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ErrConfig, got %v", err)
	}
	if _, err := c.DecodePublic(make([]byte, 33)); !errors.Is(err, ErrShortMessage) {
		t.Fatalf("expected ErrShortMessage, got %v", err)
	}
	out, err := c.EncodePublic(make([]byte, KeySize))
	if err != nil || len(out) != KeySize {
		t.Fatalf("round trip: (%d, %v)", len(out), err)
	}
	back, err := c.DecodePublic(out)
	if err != nil || len(back) != KeySize {
		t.Fatalf("round trip: (%d, %v)", len(back), err)
	}
}

func TestVerifyAdmissionRejectsBadFreshness(t *testing.T) {
	g := GatewayParams{
		AdmissionKeys: [][]byte{bytes.Repeat([]byte{1}, 32)},
		GatewayID:     []byte("g"),
		Fresh:         Freshness{BucketWindow: time.Millisecond},
	}
	if _, _, _, err := verifyAdmission(make([]byte, 200), g, fixedNow); !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ErrConfig, got %v", err)
	}
}

func TestGatewayParamsValidation(t *testing.T) {
	long := GatewayParams{
		AdmissionKeys: [][]byte{bytes.Repeat([]byte{1}, 32)},
		GatewayID:     bytes.Repeat([]byte{'x'}, 256),
	}
	if err := long.validate(true); !errors.Is(err, ErrConfig) {
		t.Fatalf("an over-long gateway id must be refused, got %v", err)
	}
	inverted := GatewayParams{
		AdmissionKeys: [][]byte{bytes.Repeat([]byte{1}, 32)},
		GatewayID:     []byte("g"),
		Fresh:         Freshness{BucketWindow: time.Second, MaxSkew: 24 * time.Hour * 400},
	}
	if err := inverted.validate(true); !errors.Is(err, ErrConfig) {
		t.Fatalf("an absurd skew must exceed the candidate ceiling, got %v", err)
	}
}

func TestWhiteningIsAnInvolution(t *testing.T) {
	key := bytes.Repeat([]byte{0x3C}, 32)
	tag := bytes.Repeat([]byte{0x11}, 32)
	original := []byte("the quick brown fox jumps over the lazy dog")

	body := append([]byte(nil), original...)
	whitenInPlace(key, tag, body)
	if bytes.Equal(body, original) {
		t.Fatal("whitening did not change the body")
	}
	whitenInPlace(key, tag, body)
	if !bytes.Equal(body, original) {
		t.Fatal("whitening is not its own inverse")
	}

	// Empty input is a no-op rather than a panic.
	whitenInPlace(key, tag, nil)
	responseWhitenInPlace(key, tag, nil)

	// A different tag gives a different stream, which is what makes the
	// keystream per-packet rather than per-gateway.
	other := append([]byte(nil), original...)
	whitenInPlace(key, bytes.Repeat([]byte{0x22}, 32), other)
	whitenInPlace(key, tag, other)
	if bytes.Equal(other, original) {
		t.Fatal("the keystream does not depend on the tag")
	}
}

func TestFreshnessDefaults(t *testing.T) {
	w, spread, err := Freshness{}.resolve()
	if err != nil {
		t.Fatal(err)
	}
	if w != DefaultBucketWindow {
		t.Fatalf("default window is %s", w)
	}
	if spread != int(DefaultMaxSkew/DefaultBucketWindow) {
		t.Fatalf("default spread is %d", spread)
	}
}

var _ io.Reader = (*failingReader)(nil)
