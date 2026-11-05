//go:build darwin

package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/winn3/core"
)

// The config-encoding variant of the late-validation family, 2026-08-09.
//
// admissionProfile decoded admission_key and accepted ANY non-empty length.
// core's 32-byte floor is real, but it only fires at driver.NewClient — which
// in openWinn3 runs after outerSocket has already opened a connection to the
// gateway. So a client with an unusable admission key bought an observable
// connection to a censored endpoint for a session that could never be admitted.
//
// What these tests do NOT claim: they do not distinguish the two base64
// conventions. A 32-byte secret held by the gateway as ASCII hex text is 64
// admission-key bytes, and both 32 and 64 clear the floor, so a client that
// picks the wrong convention still produces a well-formed key and is still
// refused in silence. Only a two-ended comparison settles that, which is what
// winn3/conform.AdmissionRoundTrip is for.

func admissionOf(t *testing.T, key string) error {
	t.Helper()
	_, err := admissionProfile(winn3Config{GatewayID: "gw.example", AdmissionKey: key})
	return err
}

// TestAnAdmissionKeyBelowTheFloorIsRefusedBeforeAnySocketIsOpened.
func TestAnAdmissionKeyBelowTheFloorIsRefusedBeforeAnySocketIsOpened(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"one byte", []byte("k")},
		{"eight bytes", []byte("tooshort")},
		{"thirty-one bytes, one below the floor", []byte(strings.Repeat("k", 31))},
		{
			// The exact reported mistake: base64 of the DECODED 16 bytes when
			// the gateway holds their hex text. Well-formed base64, plausible
			// to author, and unusable.
			"sixteen decoded bytes where the gateway holds their hex text",
			mustHex(t, strings.Repeat("ab", 16))[:16],
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := admissionOf(t, base64.StdEncoding.EncodeToString(tc.raw))
			if err == nil {
				t.Fatal("accepted an admission key below core's floor; the socket would " +
					"have been opened before core refused it")
			}
			if !errors.Is(err, errWinn3Config) {
				t.Fatalf("refused with the wrong error kind: %v", err)
			}
			if !strings.Contains(err.Error(), "decodes to") {
				t.Fatalf("the refusal does not state the decoded length, which is the "+
					"only non-secret fact that helps: %v", err)
			}
		})
	}
}

// TestTheRefusalNamesBothEncodingConventions. The failure this closes cost a
// lane most of a session, and the thing that would have saved it is the
// sentence, not the exit code.
func TestTheRefusalNamesBothEncodingConventions(t *testing.T) {
	err := admissionOf(t, base64.StdEncoding.EncodeToString([]byte("tooshort")))
	if err == nil {
		t.Fatal("accepted a short key")
	}
	for _, want := range []string{"HEX TEXT", "base64 of raw bytes", "asymmetry"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal omits %q: %v", want, err)
		}
	}
	// It must not echo the key itself. Length is not key material; bytes are.
	if strings.Contains(err.Error(), "tooshort") ||
		strings.Contains(err.Error(), base64.StdEncoding.EncodeToString([]byte("tooshort"))) {
		t.Fatalf("the refusal echoes key material: %v", err)
	}
}

// TestBothEncodingsThatClearTheFloorAreStillAccepted is the over-fire control,
// and it is the honest statement of this gate's limit.
//
// The gateway's own file in this tree is 64 ASCII hex characters, so base64 of
// the hex TEXT (64 bytes) is the convention that actually works here. base64 of
// the 32 decoded bytes also clears the floor and is WRONG against that gateway
// — and this gate cannot and must not refuse it, because against a gateway
// provisioned the other way it is the correct one. Refusing either would break
// a deployed configuration, which is an owner decision and not this lane's.
func TestBothEncodingsThatClearTheFloorAreStillAccepted(t *testing.T) {
	secretHex := strings.Repeat("ab", 32) // 64 ASCII characters
	cases := []struct {
		name string
		raw  []byte
	}{
		{"base64 of the ASCII hex text, which is what this tree's keygen writes",
			[]byte(secretHex)},
		{"base64 of the 32 decoded bytes, the opposite convention",
			mustHex(t, secretHex)},
		{"exactly the 32-byte floor", []byte(strings.Repeat("k", 32))},
		{"a long secret", []byte(strings.Repeat("k", 128))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := admissionOf(t, base64.StdEncoding.EncodeToString(tc.raw)); err != nil {
				t.Fatalf("refused an admission key core would accept, which would break a "+
					"deployed configuration: %v", err)
			}
		})
	}
}

// TestTheAdmissionFloorHereIsStillCoresFloor.
//
// minAdmissionKeyBytes restates a constant winn3/core does not export. If core
// ever raises its floor, this file would let through a key core then refuses —
// back to a refusal after the socket is open. Asserted against core itself
// rather than against a number typed twice.
func TestTheAdmissionFloorHereIsStillCoresFloor(t *testing.T) {
	atFloor := core.GatewayParams{
		GatewayID:     []byte("gw.example"),
		AdmissionKeys: [][]byte{[]byte(strings.Repeat("k", minAdmissionKeyBytes))},
	}
	belowFloor := core.GatewayParams{
		GatewayID:     []byte("gw.example"),
		AdmissionKeys: [][]byte{[]byte(strings.Repeat("k", minAdmissionKeyBytes-1))},
	}
	if _, err := core.NewResponder(
		core.Config{Gateway: atFloor}, mustStatic(t), func([]byte) error { return nil },
	); err != nil {
		t.Fatalf("core refuses a key at this file's floor, so the floor is too low: %v", err)
	}
	if _, err := core.NewResponder(
		core.Config{Gateway: belowFloor}, mustStatic(t), func([]byte) error { return nil },
	); err == nil {
		t.Fatal("core accepts a key one byte below this file's floor, so the floor is " +
			"higher than core's and this file now over-fires")
	}
}

// TestGatewayIDIsStillTakenAsRawBytesNotBase64 pins the fix that landed earlier
// today at this boundary, because it is the one that made an Apple client
// compute a different admission tag from the same operator value and be refused
// in silence. A regression here is invisible from either end.
func TestGatewayIDIsStillTakenAsRawBytesNotBase64(t *testing.T) {
	const operatorValue = "gw.example"
	cfg, err := admissionProfile(winn3Config{
		GatewayID:    operatorValue,
		AdmissionKey: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 64))),
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(cfg.Gateway.GatewayID) != operatorValue {
		t.Fatalf("gateway_id became %q; every other host in the tree derives "+
			"[]byte(%q), and two ends that derive different bytes produce different "+
			"admission tags", cfg.Gateway.GatewayID, operatorValue)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustStatic(t *testing.T) *core.StaticKey {
	t.Helper()
	k, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}
