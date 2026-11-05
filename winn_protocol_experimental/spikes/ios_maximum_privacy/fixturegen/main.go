// Command fixturegen emits one byte-for-byte deterministic WCF3 privacy cell.
// It deliberately constructs deterministic padding for cross-language testing,
// then validates the result with the authoritative Go WCF3 decoder.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"winsvpn.local/winnprotocol/internal/wcf3"
)

type fixture struct {
	Schema        string `json:"schema"`
	Protocol      string `json:"protocol"`
	Frame         string `json:"frame"`
	TotalSize     int    `json:"total_size"`
	HeaderSize    int    `json:"header_size"`
	PayloadSize   int    `json:"payload_size"`
	Kind          byte   `json:"kind"`
	Flags         byte   `json:"flags"`
	PSKGeneration uint64 `json:"psk_generation"`
	SequenceEpoch uint64 `json:"sequence_epoch"`
	Sequence      uint64 `json:"sequence"`
	SessionIDHex  string `json:"session_id_hex"`
	BindingIDHex  string `json:"binding_id_hex"`
	PayloadBase64 string `json:"payload_base64"`
	EncodedBase64 string `json:"encoded_base64"`
	SHA256        string `json:"sha256"`
}

func main() {
	encoded := make([]byte, wcf3.PrivacyCellSize)
	copy(encoded[0:4], wcf3.Magic)
	encoded[4] = wcf3.KindData
	encoded[5] = wcf3.FlagPadded

	payload := []byte("hello-winn-v3")
	// #nosec G115 -- payload is the fixed 13-byte literal above, far under
	// uint16's range.
	binary.BigEndian.PutUint16(encoded[6:8], uint16(len(payload)))
	for index := 0; index < 16; index++ {
		encoded[8+index] = byte(index + 1)
		encoded[24+index] = byte(index + 17)
	}
	const pskGeneration = uint64(7)
	const sequenceEpoch = uint64(9)
	const sequence = uint64(42)
	binary.BigEndian.PutUint64(encoded[40:48], pskGeneration)
	binary.BigEndian.PutUint64(encoded[48:56], sequenceEpoch)
	binary.BigEndian.PutUint64(encoded[56:64], sequence)
	copy(encoded[wcf3.HeaderSize:], payload)
	for index := wcf3.HeaderSize + len(payload); index < len(encoded); index++ {
		encoded[index] = byte(((index-(wcf3.HeaderSize+len(payload)))*31 + 17) & 0xff)
	}

	decoded, err := wcf3.Decode(encoded, wcf3.MaxPayloadSize, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fixture failed authoritative decode: %v\n", err)
		os.Exit(1)
	}
	sum := sha256.Sum256(encoded)
	value := fixture{
		Schema:        "winn-wcf3-fixture/1",
		Protocol:      "winn/3",
		Frame:         "WCF3",
		TotalSize:     len(encoded),
		HeaderSize:    wcf3.HeaderSize,
		PayloadSize:   len(decoded.Payload),
		Kind:          decoded.Kind,
		Flags:         decoded.Flags,
		PSKGeneration: decoded.PSKGeneration,
		SequenceEpoch: decoded.SequenceEpoch,
		Sequence:      decoded.Sequence,
		SessionIDHex:  hex.EncodeToString(decoded.SessionID[:]),
		BindingIDHex:  hex.EncodeToString(decoded.BindingID[:]),
		PayloadBase64: base64.StdEncoding.EncodeToString(decoded.Payload),
		EncodedBase64: base64.StdEncoding.EncodeToString(encoded),
		SHA256:        hex.EncodeToString(sum[:]),
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		fmt.Fprintf(os.Stderr, "encode fixture: %v\n", err)
		os.Exit(1)
	}
}
