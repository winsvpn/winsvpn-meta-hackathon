package testvectors

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"winsvpn.local/winnprotocol/internal/protocol"
)

type vectorFile struct {
	Format  string       `json:"format"`
	Vectors []testVector `json:"vectors"`
}

type testVector struct {
	Name               string                `json:"name"`
	Request            protocol.RekeyRequest `json:"request"`
	RequestDigest      string                `json:"request_digest"`
	ResponseGeneration uint64                `json:"response_generation"`
	PresharedKey       string                `json:"preshared_key"`
	KeyID              string                `json:"key_id"`
}

func TestV2Vectors(t *testing.T) {
	data, err := os.ReadFile("v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors vectorFile
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Format != "winn-test-vectors/v2" || len(vectors.Vectors) != 3 {
		t.Fatalf("unexpected vector set: format=%s count=%d", vectors.Format, len(vectors.Vectors))
	}
	for _, vector := range vectors.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			digest, err := protocol.RequestDigest(vector.Request)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(digest[:]) != vector.RequestDigest {
				t.Fatalf("request digest = %x, want %s", digest, vector.RequestDigest)
			}
			psk, err := base64.StdEncoding.Strict().DecodeString(vector.PresharedKey)
			if err != nil {
				t.Fatal(err)
			}
			keyID := protocol.KeyID(
				vector.Request.ControllerID,
				vector.Request.Suite,
				vector.Request.DeviceID,
				vector.Request.PeerPublicKey,
				vector.ResponseGeneration,
				psk,
			)
			clear(psk)
			if keyID != vector.KeyID {
				t.Fatalf("key ID = %s, want %s", keyID, vector.KeyID)
			}
		})
	}
}
