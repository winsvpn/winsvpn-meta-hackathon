package gatewaymanifest

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

// FuzzDecodeManifestV2 drives the v2 gateway manifest JSON decode and the whole
// validateV2 tree with attacker-shaped documents. The manifest is fetched from
// the network and its signature is only checked after this decode, so every
// field reachable here is unauthenticated input. validateV2 fans out into node,
// role, circuit, transport, and regional-policy validation, which is a large
// amount of nested slice and map handling to reach with one target.
func FuzzDecodeManifestV2(fuzzer *testing.F) {
	fuzzer.Add([]byte(`{}`))
	fuzzer.Add([]byte(`{"format":"` + FormatV2 + `"}`))
	fuzzer.Add([]byte(`{"format":"` + FormatV2 + `","sequence":1,"nodes":[]}`))
	fuzzer.Add([]byte(`{"format":"` + FormatV2 + `","sequence":1,"nodes":null,"circuits":null}`))
	fuzzer.Add([]byte(`[]`))
	fuzzer.Add([]byte(`null`))

	fuzzer.Fuzz(func(t *testing.T, data []byte) {
		// LoadV2 bounds the document before decoding; mirror that bound so the
		// target explores structure rather than size.
		if len(data) > MaxDocumentSize {
			return
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		var manifest ManifestV2
		if err := decoder.Decode(&manifest); err != nil {
			return
		}
		if err := requireManifestEOF(decoder); err != nil {
			return
		}

		now := time.Unix(1700000000, 0).UTC()
		if err := validateV2(manifest, now, time.Minute, manifest.AuthSignature != ""); err != nil {
			return
		}

		// A manifest that validates must re-encode and survive a round trip.
		// A validate-but-cannot-encode document would mean the two paths
		// disagree about what is well formed, which is where signature
		// canonicalisation bugs live.
		encoded, err := EncodeV2(manifest)
		if err != nil {
			t.Fatalf("validated manifest failed to encode: %v", err)
		}
		if len(encoded) > MaxDocumentSize {
			t.Fatalf("validated manifest re-encoded to %d bytes, over the document limit", len(encoded))
		}
		roundTrip := json.NewDecoder(bytes.NewReader(encoded))
		roundTrip.DisallowUnknownFields()
		var second ManifestV2
		if err := roundTrip.Decode(&second); err != nil {
			t.Fatalf("re-encoded manifest failed to decode: %v", err)
		}
		if err := validateV2(second, now, time.Minute, second.AuthSignature != ""); err != nil {
			t.Fatalf("re-encoded manifest failed to validate: %v", err)
		}
		if manifest.AuthSignature != "" {
			// Digest must be stable across the round trip, otherwise a peer
			// could present two encodings of one signed manifest.
			first, err := DigestV2(manifest)
			if err != nil {
				t.Fatalf("validated signed manifest failed to digest: %v", err)
			}
			repeat, err := DigestV2(second)
			if err != nil {
				t.Fatalf("round-tripped manifest failed to digest: %v", err)
			}
			if first != repeat {
				t.Fatalf("digest changed across a round trip: %s then %s", first, repeat)
			}
		}
	})
}
