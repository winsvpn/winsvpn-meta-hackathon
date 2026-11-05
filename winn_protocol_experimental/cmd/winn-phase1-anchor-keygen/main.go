package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	privatePath := flag.String(
		"private-key", "", "new raw Ed25519 private key path",
	)
	publicPath := flag.String(
		"public-key", "", "new base64 Ed25519 public key path",
	)
	flag.Parse()
	if flag.NArg() != 0 || *privatePath == "" || *publicPath == "" ||
		*privatePath == *publicPath {
		fatal(errors.New(
			"distinct private-key and public-key paths are required",
		))
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal(err)
	}
	if err := createExclusive(*privatePath, private, 0o600); err != nil {
		fatal(err)
	}
	publicText := []byte(base64.StdEncoding.EncodeToString(public) + "\n")
	if err := createExclusive(*publicPath, publicText, 0o600); err != nil {
		_ = os.Remove(*privatePath)
		fatal(err)
	}
	fmt.Printf("PUBLIC_KEY=%s\n", *publicPath)
}

func createExclusive(path string, content []byte, mode os.FileMode) error {
	// #nosec G304 -- both destinations are explicit administrator paths and
	// O_EXCL prevents replacement of any existing key material.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	cleanup := func(closeErr error) error {
		removeErr := os.Remove(path)
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return errors.Join(closeErr, removeErr)
		}
		return closeErr
	}
	wrote, err := file.Write(content)
	if err != nil {
		return cleanup(errors.Join(err, file.Close()))
	}
	if wrote != len(content) {
		return cleanup(errors.Join(
			fmt.Errorf("short write %d of %d", wrote, len(content)),
			file.Close(),
		))
	}
	if err := file.Sync(); err != nil {
		return cleanup(errors.Join(err, file.Close()))
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	directoryPath := filepath.Dir(path)
	if directoryPath != "." && directoryPath != "" {
		// #nosec G304 -- directoryPath is the validated parent of an explicit administrator path.
		if directory, err := os.Open(directoryPath); err == nil {
			_ = errors.Join(directory.Sync(), directory.Close())
		}
	}
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ANCHOR_KEYGEN_FAIL:", err)
	os.Exit(1)
}
