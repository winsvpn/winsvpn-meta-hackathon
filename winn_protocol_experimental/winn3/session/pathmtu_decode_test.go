package session

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestDecodePathMTUNoticePinsEveryNoClaimShape is the decoder half of silent-
// refusal instance #3. refusePathMTUMismatch treats ok=false as "proceed with
// this end's own number", which is the remaining fail-OPEN hatch when a peer
// made a claim this build cannot read. Every branch that returns ok=false is
// therefore a load-bearing compatibility choice, not an omission, and each
// one is named here.
func TestDecodePathMTUNoticePinsEveryNoClaimShape(t *testing.T) {
	valid := EncodePathMTUNotice(1500)
	if len(valid) != pathMTUNoticeSize {
		t.Fatalf("EncodePathMTUNotice(1500) is %d bytes, want %d", len(valid), pathMTUNoticeSize)
	}

	unknown := append([]byte(nil), valid...)
	unknown[4] = pathMTUNoticeVersion + 1

	zeroMTU := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(zeroMTU[5:7], 0)

	longer := append(append([]byte(nil), valid...), 0xAA, 0xBB)

	for _, tc := range []struct {
		name    string
		payload []byte
		wantMTU int
		wantOK  bool
	}{
		{"empty payload — pre-notice peer", nil, 0, false},
		{"too short to hold the record", valid[:pathMTUNoticeSize-1], 0, false},
		{"foreign magic", []byte("XXXX\x01\x05\xdc"), 0, false},
		{"unknown version — remaining fail-open hatch", unknown, 0, false},
		{"mtu field is zero — no claim", zeroMTU, 0, false},
		{"valid v1", valid, 1500, true},
		{"valid v1 with trailing bytes — forward compatible", longer, 1500, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := DecodePathMTUNotice(tc.payload)
			if ok != tc.wantOK || got != tc.wantMTU {
				t.Fatalf("DecodePathMTUNotice(%q) = (%d, %v), want (%d, %v)",
					tc.name, got, ok, tc.wantMTU, tc.wantOK)
			}
		})
	}
}

func TestEncodePathMTUNoticeIsNilForUnusableClaims(t *testing.T) {
	for _, n := range []int{0, -1, 0x10000} {
		if got := EncodePathMTUNotice(n); got != nil {
			t.Errorf("EncodePathMTUNotice(%d) = %x, want nil", n, got)
		}
	}
}

func TestEncodeDecodePathMTUNoticeRoundTrip(t *testing.T) {
	for _, mtu := range []int{1280, 1400, 1500, 0xFFFF} {
		enc := EncodePathMTUNotice(mtu)
		got, ok := DecodePathMTUNotice(enc)
		if !ok {
			t.Fatalf("DecodePathMTUNotice rejected a record this package just encoded for %d", mtu)
		}
		if got != mtu {
			t.Fatalf("round trip %d → %d", mtu, got)
		}
		if !bytes.Equal(enc[:4], pathMTUNoticeMagic[:]) {
			t.Fatalf("magic drifted: %x", enc[:4])
		}
		if enc[4] != pathMTUNoticeVersion {
			t.Fatalf("version is %d, want %d", enc[4], pathMTUNoticeVersion)
		}
	}
}
