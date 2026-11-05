// SPDX-License-Identifier: MIT
// Derived from cmd/winn-datapath for the isolated direct-host study candidate.
// See docs/evidence/stages345_astra/windows.md for the shared and candidate paths.
package hostqueue

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"winsvpn.local/winnprotocol/internal/securefile"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/dualsign"
	"winsvpn.local/winnprotocol/winn3/session"
)

const winn3KeyFileMaxBytes = 8 << 10

// ReadPrivateKeyFile uses the existing bounded custody-checked key reader.
func ReadPrivateKeyFile(path, field string) ([]byte, error) {
	raw, err := securefile.ReadPrivateLimited(path, winn3KeyFileMaxBytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	return raw, nil
}

// ApplyDualAuthPublics loads both attestation publics or refuses a partial pair.
// Both absent remains the legacy desktop policy; Open requires both paths.
func ApplyDualAuthPublics(cfg *session.Config, edPath, mlPath string) error {
	edPath = strings.TrimSpace(edPath)
	mlPath = strings.TrimSpace(mlPath)
	if (edPath == "") != (mlPath == "") {
		return fmt.Errorf(
			"dual_auth_ed25519_pub_path and dual_auth_mldsa65_pub_path must be set together")
	}
	if edPath == "" {
		return nil
	}
	edPub, err := ReadDualAuthPublic(
		edPath, dualsign.Ed25519PublicKeySize, "dual_auth_ed25519_pub_path")
	if err != nil {
		return err
	}
	mlPub, err := ReadDualAuthPublic(
		mlPath, dualsign.MLDSA65PublicKeySize, "dual_auth_mldsa65_pub_path")
	if err != nil {
		return err
	}
	cfg.DualAuth = session.DualAuthConfig{
		Expected:      true,
		Ed25519Public: edPub,
		MLDSA65Public: mlPub,
	}
	return nil
}

// ReadDualAuthPublic validates the protected file encoding and exact key size.
func ReadDualAuthPublic(path string, want int, field string) ([]byte, error) {
	raw, err := ReadPrivateKeyFile(path, field)
	if err != nil {
		return nil, err
	}
	return DecodeDualAuthPublic(raw, want, field)
}

// DecodeDualAuthPublic is ReadDualAuthPublic's decoding half, for a caller
// that read the file itself and owns (and later clears) the raw buffer. The
// result is always a fresh allocation.
func DecodeDualAuthPublic(raw []byte, want int, field string) ([]byte, error) {
	decoded, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	if len(decoded) != want {
		return nil, fmt.Errorf("%s: got %d bytes, want %d", field, len(decoded), want)
	}
	return decoded, nil
}

// ReadKeyFile accepts the existing raw or hex X25519 file encodings.
func ReadKeyFile(path, field string) ([]byte, error) {
	raw, err := ReadPrivateKeyFile(path, field)
	if err != nil {
		return nil, err
	}
	key, err := DecodeKeyBytes(raw, field)
	if err != nil {
		clear(raw)
		return nil, err
	}
	// This function owns raw (see DecodeKeyBytes): return a copy and clear
	// both, so the hex encoding of the key does not outlive the read.
	out := bytes.Clone(key)
	clear(key)
	clear(raw)
	return out, nil
}

// DecodeKeyBytes is ReadKeyFile's decoding half, for a caller that read the
// file itself and owns (and later clears) the raw buffer. The result is a fresh
// allocation for the hex encoding and a subslice of raw for the raw one.
func DecodeKeyBytes(raw []byte, field string) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == hex.EncodedLen(core.KeySize) {
		// hex.Decode rather than DecodeString: a string conversion would leave
		// an immutable copy of the secret that no caller can clear.
		decoded := make([]byte, core.KeySize)
		if _, decodeErr := hex.Decode(decoded, trimmed); decodeErr == nil {
			return decoded, nil
		}
		clear(decoded)
	}
	if len(raw) == core.KeySize {
		return raw, nil
	}
	if len(trimmed) == core.KeySize {
		return trimmed, nil
	}
	return nil, fmt.Errorf(
		"%s: %d bytes; expected %d raw bytes or %d hex characters",
		field, len(raw), core.KeySize, hex.EncodedLen(core.KeySize))
}
