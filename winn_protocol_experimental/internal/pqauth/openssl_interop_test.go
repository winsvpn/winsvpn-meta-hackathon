package pqauth

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

func TestOpenSSLVerifiesWinnMLDSASignatures(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("OpenSSL is unavailable")
	}
	if output, err := exec.Command(openssl, "list", "-signature-algorithms").CombinedOutput(); err != nil ||
		!bytes.Contains(output, []byte("ML-DSA-65")) {
		t.Skip("OpenSSL does not expose ML-DSA")
	}
	profiles := []struct {
		algorithm string
		oid       asn1.ObjectIdentifier
		fill      byte
	}{
		{MLDSA65, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}, 0x51},
		{MLDSA87, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}, 0x52},
	}
	for _, profile := range profiles {
		t.Run(profile.algorithm, func(t *testing.T) {
			signer := signerFor(t, profile.algorithm, profile.fill)
			message := []byte("Winn Protocol OpenSSL ML-DSA interoperability")
			signature, err := signer.sign(message)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(signature)
			publicKey := signer.PublicBytes()
			defer clear(publicKey)
			der, err := asn1.Marshal(subjectPublicKeyInfo{
				Algorithm:        pkix.AlgorithmIdentifier{Algorithm: profile.oid},
				SubjectPublicKey: asn1.BitString{Bytes: publicKey, BitLength: len(publicKey) * 8},
			})
			if err != nil {
				t.Fatal(err)
			}
			directory := t.TempDir()
			publicPath := filepath.Join(directory, "public.pem")
			messagePath := filepath.Join(directory, "message.bin")
			signaturePath := filepath.Join(directory, "signature.bin")
			if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(messagePath, message, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(signaturePath, signature, 0o600); err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command(
				openssl,
				"pkeyutl",
				"-verify",
				"-pubin",
				"-inkey", publicPath,
				"-in", messagePath,
				"-sigfile", signaturePath,
				"-pkeyopt", "context-string:Winn-Protocol-v3",
			).CombinedOutput()
			if err != nil {
				t.Fatalf("OpenSSL rejected %s signature: %v\n%s", profile.algorithm, err, output)
			}
		})
	}
}
