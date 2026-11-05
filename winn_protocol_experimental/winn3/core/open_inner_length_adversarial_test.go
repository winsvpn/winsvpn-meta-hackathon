package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// sealWithClaimedInnerLength is Seal with the inner uint16 length field
// set to claimed instead of len(payload). Padding after the payload is
// still present, matching the on-wire layout. A hostile peer that has
// the session keys can emit any claimed value; Open must not over-read.
func sealWithClaimedInnerLength(s *Session, payload []byte, claimed uint16, padLen int) ([]byte, error) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.wiped || s.sendAEAD == nil {
		return nil, ErrWiped
	}
	if s.sendCounter >= RejectAfterMessages {
		return nil, ErrCounterExhausted
	}
	counter := s.sendCounter
	token := demuxToken(&s.sendDemux, counter)
	var nonce [AEADNonceSize]byte
	copy(nonce[:nonceSaltSize], s.sendSalt[:])
	binary.BigEndian.PutUint64(nonce[nonceSaltSize:], counter)

	plain := make([]byte, transportHeaderSize+len(payload)+padLen)
	binary.BigEndian.PutUint16(plain[:transportHeaderSize], claimed)
	copy(plain[transportHeaderSize:], payload)

	out := make([]byte, DemuxTokenSize, DemuxTokenSize+len(plain)+AEADTagSize)
	copy(out, token[:])
	out = s.sendAEAD.Seal(out, nonce[:], plain, token[:])
	s.sendCounter++
	s.sentBytes += uint64(len(out))
	return out, nil
}

// TestOpenInnerLengthAdversarialInputs is the transport analogue of
// TestParseFramesAdversarialInputs. After AEAD success the plaintext is
// length(2 BE) || payload || pad. A claimed length that runs past the
// plaintext is an over-read; a claimed length shorter than the body is
// padding (accepted, truncated). A panic here is a session DoS on a
// message that already authenticated.
func TestOpenInnerLengthAdversarialInputs(t *testing.T) {
	h := newHarness(t)
	cli, gw := h.completeHandshake(t)

	body := []byte("abcdefghij") // 10 bytes

	cases := []struct {
		name    string
		payload []byte
		claimed uint16
		padLen  int
		accept  bool
		want    []byte
	}{
		{"claimed equals payload, no pad", body, 10, 0, true, body},
		{"empty payload claimed 0", nil, 0, 0, true, []byte{}},
		{"claimed 0 with 8 bytes of pad (cover)", nil, 0, 8, true, []byte{}},
		{"claimed shorter than body is padding", body, 4, 0, true, body[:4]},
		{"claimed equals payload with trailing pad", body, 10, 5, true, body},
		{"claimed one past the plaintext", body, 11, 0, false, nil},
		{"claimed 0xFFFF with a 10-byte body", body, 0xFFFF, 0, false, nil},
		{"claimed 1 with empty body", nil, 1, 0, false, nil},
		{"header-only plaintext claimed 0", nil, 0, 0, true, []byte{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := sealWithClaimedInnerLength(cli, tc.payload, tc.claimed, tc.padLen)
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			got, err := gw.Open(msg)
			if tc.accept {
				if err != nil {
					t.Fatalf("accepted case returned %v", err)
				}
				if !bytes.Equal(got, tc.want) {
					t.Fatalf("opened %q, want %q", got, tc.want)
				}
				if len(got) > int(tc.claimed) {
					t.Fatalf("opened %d bytes from claimed %d (over-read)", len(got), tc.claimed)
				}
				return
			}
			if err == nil {
				t.Fatalf("oversize inner length was accepted (%d bytes)", len(got))
			}
			if !errors.Is(err, ErrDecrypt) {
				t.Fatalf("error is %v, want ErrDecrypt", err)
			}
			if got != nil {
				t.Fatalf("error path delivered %d bytes", len(got))
			}
		})
	}
}

// TestOpenInnerLengthExactFillIsAccepted pins the fencepost on
// `transportHeaderSize+n > len(plain)`. Changing that to `>=` would reject
// a well-formed message whose payload runs to the last plaintext byte.
func TestOpenInnerLengthExactFillIsAccepted(t *testing.T) {
	h := newHarness(t)
	cli, gw := h.completeHandshake(t)
	payload := []byte("xyz")
	msg, err := sealWithClaimedInnerLength(cli, payload, uint16(len(payload)), 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := gw.Open(msg)
	if err != nil {
		t.Fatalf("exact-fill inner length was rejected: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q", got)
	}
}
