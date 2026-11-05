package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/securefile"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/dualsign"
)

// derivedPublicFiles are the public halves keygen writes beside its secrets,
// in the order -mode derive-public writes them.
var derivedPublicFiles = []string{"static.pub", "auth_ed25519.pub", "auth_mldsa65.pub"}

// runDerivePublic re-derives the three public halves of a gateway identity from
// its secrets: static.pub from the X25519 static key, auth_ed25519.pub and
// auth_mldsa65.pub from the dual-auth seeds.
//
// Adopting a node built by the standalone installer needs them (ONETOUCH
// design v17, 2.6), and its public halves may survive only off the node.
// Ubuntu 24.04's OpenSSL 3.0 derives X25519 and Ed25519 but not ML-DSA-65, so
// this is the one on-node source for that half.
//
// The inputs are the -static, -dual-auth-ed-key and -dual-auth-ml-seed paths
// -mode serve reads, under the same rules, so it can be pointed at exactly the
// files a live unit loads. The outputs are keygen's: the same names, lowercase
// hex with no newline, 0600, and O_EXCL so nothing existing is overwritten.
func runDerivePublic(staticPath, edKeyPath, mlSeedPath, dir string, out io.Writer) error {
	if strings.TrimSpace(dir) == "" {
		return errors.New("derive-public needs -out")
	}
	if staticPath == "" || edKeyPath == "" || mlSeedPath == "" {
		return errors.New("derive-public needs -static, -dual-auth-ed-key and -dual-auth-ml-seed")
	}
	staticBytes, err := readKeyFile(staticPath)
	if err != nil {
		return fmt.Errorf("-static: %w", err)
	}
	staticKey, err := core.NewStaticKey(staticBytes)
	if err != nil {
		return fmt.Errorf("-static: %w", err)
	}
	edRaw, err := securefile.ReadPrivateLimited(edKeyPath, 4096)
	if err != nil {
		return fmt.Errorf("-dual-auth-ed-key: %w", err)
	}
	edPriv, err := hex.DecodeString(strings.TrimSpace(string(bytes.TrimRight(edRaw, "\r\n"))))
	if err != nil || len(edPriv) != dualsign.Ed25519PrivateKeySize {
		return errors.New("-dual-auth-ed-key must hold 64 bytes hex (seed||public)")
	}
	edPub := ed25519.NewKeyFromSeed(edPriv[:ed25519.SeedSize]).Public().(ed25519.PublicKey)
	// ed25519.Sign hashes the public half stored after the seed. If that copy
	// is not the seed's own, the key's signatures verify under neither, so no
	// half derived from it may be published.
	if !bytes.Equal(edPub, edPriv[ed25519.SeedSize:]) {
		return errors.New("-dual-auth-ed-key: the public half stored after the seed is not derived from the seed")
	}
	mlRaw, err := securefile.ReadPrivateLimited(mlSeedPath, 4096)
	if err != nil {
		return fmt.Errorf("-dual-auth-ml-seed: %w", err)
	}
	mlSeed, err := hex.DecodeString(strings.TrimSpace(string(bytes.TrimRight(mlRaw, "\r\n"))))
	if err != nil || len(mlSeed) != dualsign.MLDSA65SeedSize {
		return fmt.Errorf("-dual-auth-ml-seed must hold %d bytes hex", dualsign.MLDSA65SeedSize)
	}
	mlSigner, err := pqauth.NewSigner(pqauth.MLDSA65, mlSeed)
	if err != nil {
		return fmt.Errorf("-dual-auth-ml-seed: %w", err)
	}
	mlPub := append([]byte(nil), mlSigner.PublicBytes()...)
	mlSigner.Destroy()

	bodies := map[string][]byte{
		"static.pub":       []byte(hex.EncodeToString(staticKey.Public())),
		"auth_ed25519.pub": []byte(hex.EncodeToString(edPub)),
		"auth_mldsa65.pub": []byte(hex.EncodeToString(mlPub)),
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// All three names must be free before the first write, so a refusal never
	// leaves a partial set behind; O_EXCL below still closes the race.
	for _, name := range derivedPublicFiles {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			return fmt.Errorf("refusing to overwrite existing key file %s", name)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for _, name := range derivedPublicFiles {
		// O_EXCL, as keygen: an existing file is never truncated or replaced.
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("refusing to overwrite existing key file %s: %w", name, err)
		}
		if _, err := f.Write(bodies[name]); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "{\"event\":\"derive-public\",\"dir\":%q,\"gateway_public\":%q}\n",
		dir, hex.EncodeToString(staticKey.Public()))
	return nil
}
