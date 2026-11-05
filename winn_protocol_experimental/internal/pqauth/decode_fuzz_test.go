package pqauth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"testing"
)

// FuzzDecodeSignature drives the base64 ML-DSA signature decoder that guards
// every signed message on the wire. It is reached before any verification, so
// a peer controls both the encoding and the declared length.
func FuzzDecodeSignature(fuzzer *testing.F) {
	fuzzer.Add("", 3309)
	fuzzer.Add("AAAA", 3)
	fuzzer.Add("====", 3309)
	fuzzer.Add("%%%%", 2420)

	fuzzer.Fuzz(func(t *testing.T, encoded string, expectedSize int) {
		if expectedSize < 0 || expectedSize > 1<<20 {
			return
		}
		signature, err := decodeSignature(encoded, expectedSize)
		if err != nil {
			return
		}
		if len(signature) != expectedSize {
			t.Fatalf("decoded a %d byte signature for an expected size of %d",
				len(signature), expectedSize)
		}
	})
}

// FuzzVerifierSetDocument drives the verifier-set JSON loader. The document is
// distributed as trust material, so a compromised or tampered distribution path
// is exactly the threat this parser must survive. It builds ML-DSA verifiers
// from attacker-chosen base64, which is where a bad length reaches the CIRCL
// key parser.
func FuzzVerifierSetDocument(fuzzer *testing.F) {
	fuzzer.Add([]byte(`{}`))
	fuzzer.Add([]byte(`{"format":"` + verifierSetFormat + `","keys":{}}`))
	fuzzer.Add([]byte(`{"format":"` + verifierSetFormat + `","keys":{"ml-dsa-65":["AAAA"]}}`))
	fuzzer.Add([]byte(`{"format":"` + verifierSetFormat + `","keys":{"ml-dsa-65":[]}}`))
	fuzzer.Add([]byte(`{"format":"x","keys":null}`))

	fuzzer.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			return
		}
		// Mirror LoadVerifierSet's decode without touching the filesystem.
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		var file VerifierSetFile
		if err := decoder.Decode(&file); err != nil {
			return
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			return
		}
		if file.Format != verifierSetFormat || len(file.Keys) == 0 {
			return
		}
		// Bound the key count so the target does not spend its budget building
		// thousands of real ML-DSA verifiers per execution.
		total := 0
		for _, keys := range file.Keys {
			total += len(keys)
		}
		if total > 8 {
			return
		}
		set, err := buildFuzzVerifierSet(file)
		if err != nil {
			return
		}
		if set == nil {
			t.Fatal("verifier set construction returned nil without an error")
		}
		for algorithm, keys := range file.Keys {
			if len(keys) == 0 {
				continue
			}
			if !set.HasAlgorithm(algorithm) {
				t.Fatalf("accepted set does not report its own algorithm %q", algorithm)
			}
		}
	})
}

func buildFuzzVerifierSet(file VerifierSetFile) (*VerifierSet, error) {
	var verifiers []*Verifier
	for algorithm, encodedKeys := range file.Keys {
		if len(encodedKeys) == 0 || len(encodedKeys) > maxRegistryKeysPerType {
			return nil, errors.New("verifier key count out of range")
		}
		for _, encoded := range encodedKeys {
			publicKey, err := base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil {
				return nil, err
			}
			verifier, err := NewVerifier(algorithm, publicKey)
			clear(publicKey)
			if err != nil {
				return nil, err
			}
			verifiers = append(verifiers, verifier)
		}
	}
	return NewVerifierSet(verifiers...)
}

// FuzzVerifyDomainMessage drives signature verification with attacker-supplied
// message and signature bytes against a real verifier. Length handling here
// runs before the constant-time verify, so a mismatch must be rejected without
// reaching the CIRCL code with a wrong-sized buffer.
func FuzzVerifyDomainMessage(fuzzer *testing.F) {
	seed, err := GenerateSeed()
	if err != nil {
		fuzzer.Skipf("cannot generate an ML-DSA seed: %v", err)
	}
	signer, err := NewSigner(MLDSA65, seed)
	if err != nil {
		fuzzer.Skipf("cannot build an ML-DSA signer: %v", err)
	}
	verifier, err := NewVerifier(MLDSA65, signer.PublicBytes())
	if err != nil {
		fuzzer.Skipf("cannot build an ML-DSA verifier: %v", err)
	}
	valid, err := SignDomainMessage(CarrierSignatureDomain, []byte("winn"), signer)
	if err != nil {
		fuzzer.Skipf("cannot sign a seed message: %v", err)
	}

	fuzzer.Add(CarrierSignatureDomain, []byte("winn"), valid)
	fuzzer.Add("", []byte{}, []byte{})
	fuzzer.Add(CarrierSignatureDomain, []byte("winn"), []byte{0x00})
	fuzzer.Add("winn-unknown-domain", []byte("winn"), valid)

	fuzzer.Fuzz(func(t *testing.T, domain string, message, signature []byte) {
		if len(message) > 64<<10 || len(signature) > 16<<10 {
			return
		}
		if err := VerifyDomainMessage(domain, message, signature, verifier); err != nil {
			return
		}
		// Anything that verifies must be a well-formed domain and a signature
		// of exactly the algorithm's size.
		if !validSignatureDomain(domain) {
			t.Fatalf("verified a message under an unrecognised domain %q", domain)
		}
		if len(message) == 0 {
			t.Fatal("verified an empty message")
		}
		if len(signature) != verifier.signatureSize {
			t.Fatalf("verified a %d byte signature against a %d byte algorithm",
				len(signature), verifier.signatureSize)
		}
	})
}
