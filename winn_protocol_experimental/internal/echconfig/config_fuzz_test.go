package echconfig

import (
	"encoding/binary"
	"testing"
)

// FuzzValidateConfigList drives the hand-rolled RFC 9849 ECHConfigList parser.
// The config list reaches this parser from bootstrap and DNS-adjacent sources,
// so every byte is attacker-controlled. The parser walks nested 16-bit
// length-prefixed vectors, which is the classic place for truncation and
// out-of-bounds slicing, so the invariants below assert both memory safety and
// forward progress.
func FuzzValidateConfigList(fuzzer *testing.F) {
	generated, _, err := Generate("example.com", 1)
	if err != nil {
		fuzzer.Fatal(err)
	}
	fuzzer.Add(generated)
	fuzzer.Add([]byte{})
	fuzzer.Add([]byte{0x00, 0x04, 0xfe, 0x0d, 0x00, 0x00})
	// A list header that claims more bytes than are present.
	fuzzer.Add([]byte{0xff, 0xff, 0xfe, 0x0d, 0x00, 0x00})
	// A zero-length inner config, the shape that could stall the walk loop.
	fuzzer.Add([]byte{0x00, 0x04, 0x00, 0x00, 0x00, 0x00})

	fuzzer.Fuzz(func(t *testing.T, data []byte) {
		err := validateConfigList(data)
		if err != nil {
			return
		}
		// An accepted list must have a self-consistent outer framing.
		if len(data) < 6 {
			t.Fatalf("accepted an ECHConfigList shorter than the minimum: %d", len(data))
		}
		if int(binary.BigEndian.Uint16(data[:2])) != len(data)-2 {
			t.Fatal("accepted an ECHConfigList whose declared length disagrees with its size")
		}
		// Acceptance must be stable: the parser has no state, so a second call
		// on identical input must reach the identical verdict.
		if second := validateConfigList(data); second != nil {
			t.Fatalf("validateConfigList is not deterministic: %v", second)
		}
		// Every accepted list must survive the base64 presentation round trip
		// that the production bootstrap path performs.
		encoded, err := PublicConfigListBase64(data)
		if err != nil {
			t.Fatalf("accepted list failed base64 presentation: %v", err)
		}
		if encoded == "" {
			t.Fatal("accepted list produced an empty presentation form")
		}
	})
}

// FuzzValidateConfig targets a single ECHConfig, which is the inner structure
// reached both from the config list walk and from the server key file loader
// via TLSKeys. Reaching it directly gives the fuzzer a far shorter path to the
// public-name and extension-vector parsing than going through the outer list.
func FuzzValidateConfig(fuzzer *testing.F) {
	generated, _, err := Generate("winsvpn.example", 7)
	if err != nil {
		fuzzer.Fatal(err)
	}
	if len(generated) > 2 {
		fuzzer.Add(generated[2:])
	}
	fuzzer.Add([]byte{0xfe, 0x0d, 0x00, 0x00})
	fuzzer.Add([]byte{0xfe, 0x0d, 0xff, 0xff})

	fuzzer.Fuzz(func(t *testing.T, data []byte) {
		if err := validateConfig(data); err != nil {
			return
		}
		// An accepted config must expose a well-formed 32-byte X25519 key.
		publicKey, err := publicKeyFromConfig(data)
		if err != nil {
			t.Fatalf("validateConfig accepted a config whose public key will not parse: %v", err)
		}
		if len(publicKey) != 32 {
			t.Fatalf("accepted config yielded a %d byte public key", len(publicKey))
		}
	})
}
