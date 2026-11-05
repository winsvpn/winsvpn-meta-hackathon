package phase1anchor

import (
	"strings"
	"testing"
)

func TestSlotArtifactNamesExactSet(t *testing.T) {
	want := []string{
		"provider-config.json",
		"provider-one.receipt.json",
		"provider-one.receipt.json.sha256",
		"provider-two.receipt.json",
		"provider-two.receipt.json.sha256",
		"request.json",
		"request.json.sha256",
	}
	got := SlotArtifactNames()
	if len(got) != len(want) {
		t.Fatalf("SlotArtifactNames len=%d want %d: %q", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SlotArtifactNames[%d]=%q want %q", i, got[i], want[i])
		}
	}
	set := SlotArtifactSet()
	if len(set) != len(want) {
		t.Fatalf("SlotArtifactSet len=%d want %d", len(set), len(want))
	}
	for _, name := range want {
		if _, ok := set[name]; !ok {
			t.Fatalf("SlotArtifactSet missing %q", name)
		}
	}
}

func TestParseSidecarDigestRoundTrip(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	got, err := ParseSidecarDigest(SidecarDigestBytes(digest))
	if err != nil {
		t.Fatal(err)
	}
	if got != digest {
		t.Fatalf("ParseSidecarDigest = %q want %q", got, digest)
	}
}

func TestParseSidecarDigestRejectsTrimmedAndPadded(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	for name, data := range map[string][]byte{
		"empty":            nil,
		"digest_only":      []byte(digest),
		"leading_space":    []byte(" " + digest + "\n"),
		"trailing_blank":   []byte(digest + "\n\n"),
		"uppercase":        []byte(strings.ToUpper(digest) + "\n"),
		"writer_empty":     SidecarDigestBytes(""),
		"writer_uppercase": SidecarDigestBytes(strings.ToUpper(digest)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSidecarDigest(data); err == nil {
				t.Fatalf("accepted %q", data)
			}
		})
	}
}
