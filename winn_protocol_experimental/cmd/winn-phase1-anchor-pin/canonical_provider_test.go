// What the pin tool does with a provider that answers non-canonically.
//
// A receipt's signature and its digest are both computed over a RE-MARSHAL, so
// a provider that pads its answer with whitespace, reorders its object keys, or
// repeats one of them produces bytes that verify perfectly and digest to
// exactly the right value. The pin tool used to seal those bytes verbatim.
//
// The formal verifier then requires the sealed receipt to BE the canonical
// encoding plus one newline, so such a slot is refused at audit — after two
// external providers have signed and the chain can no longer be withdrawn. The
// pin tool is the last place the deviation is cheap to notice.
//
// Canonicalising the provider's answer instead of refusing it would be worse:
// it would seal a document no provider actually sent, and it would hide a
// misbehaving provider for as long as the deviation stayed semantically
// harmless. The deviation is the signal.
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/anchorfixture"
	"winsvpn.local/winnprotocol/internal/phase1anchor"
)

// TestPinToolRefusesNonCanonicalProviderOutput runs the real pin tool against a
// provider whose receipts are semantically identical to the canonical form and
// differ only in bytes.
func TestPinToolRefusesNonCanonicalProviderOutput(t *testing.T) {
	for _, test := range []struct {
		name   string
		mangle func([]byte) []byte
	}{
		{
			name: "trailing_blank_line",
			mangle: func(data []byte) []byte {
				return append(data, '\n')
			},
		},
		{
			name: "leading_whitespace",
			mangle: func(data []byte) []byte {
				return append([]byte("  "), data...)
			},
		},
		{
			name: "no_terminating_newline",
			mangle: func(data []byte) []byte {
				return bytes.TrimRight(data, "\n")
			},
		},
		{
			name: "reindented_json",
			mangle: func(data []byte) []byte {
				// Insert a space after every field separator. encoding/json
				// ignores it, every signature and digest is unchanged, and the
				// bytes are no longer the sealed canonical encoding.
				return append(
					bytes.ReplaceAll(
						bytes.TrimRight(data, "\n"), []byte(`","`), []byte(`", "`),
					), '\n',
				)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := anchorfixture.ProduceWith(
				t,
				anchorfixture.GenesisRequest("m1"),
				phase1anchor.ZeroDigest, phase1anchor.ZeroDigest,
				anchorfixture.Options{
					MangleProviderOutput: test.mangle,
					AllowFailure:         true,
				},
			)
			if err == nil {
				t.Fatal(
					"the pin tool sealed a non-canonical provider receipt; " +
						"the formal verifier would refuse the resulting slot " +
						"after the signatures are irreversible",
				)
			}
			if !strings.Contains(err.Error(), "canonical sealed encoding") {
				t.Fatalf("the pin tool refused for the wrong reason: %v", err)
			}
		})
	}
}

// TestPinToolAcceptsCanonicalProviderOutput is the control. Without it the test
// above could pass over a pin tool that refused every provider.
func TestPinToolAcceptsCanonicalProviderOutput(t *testing.T) {
	slot := anchorfixture.Produce(
		t, anchorfixture.GenesisRequest("m1"),
		phase1anchor.ZeroDigest, phase1anchor.ZeroDigest,
	)
	for _, name := range phase1anchor.SlotArtifactNames() {
		info, err := os.Lstat(filepath.Join(slot.Directory, name))
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("the pin tool did not write %s: %v", name, err)
		}
	}
}

// TestPinToolRefusesToCommitAnIncompleteSlot covers the writer-side exact-set
// check. The pin tool is where an incomplete slot is cheapest to notice; the
// verifier notices it only after the anchors are irreversible.
func TestPinToolRefusesToCommitAnIncompleteSlot(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), "requireExactSlotContents(pendingDirectory)") {
		t.Fatal(
			"the pin tool no longer checks its own output against the shared " +
				"anchor slot artifact set before returning success",
		)
	}
	// And the behaviour itself, over a real slot the real tool produced.
	slot := anchorfixture.Produce(
		t, anchorfixture.GenesisRequest("m1"),
		phase1anchor.ZeroDigest, phase1anchor.ZeroDigest,
	)
	if err := requireExactSlotContents(slot.Directory); err != nil {
		t.Fatalf("a real slot failed the writer's own exact-set check: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(slot.Directory, "batch-meta.env"),
		[]byte("planted=1\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := requireExactSlotContents(slot.Directory); err == nil {
		t.Fatal("an extra member was accepted into the slot")
	}
	if err := os.Remove(
		filepath.Join(slot.Directory, "batch-meta.env"),
	); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(
		filepath.Join(slot.Directory, phase1anchor.SlotRequestName),
	); err != nil {
		t.Fatal(err)
	}
	if err := requireExactSlotContents(slot.Directory); err == nil {
		t.Fatal("a slot missing its request was accepted as complete")
	}
}
