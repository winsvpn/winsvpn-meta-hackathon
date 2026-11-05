// The anchor provider server. POSIX only: it is a thin front end over
// phase1anchor.Ledger, whose flock(2) and O_NOFOLLOW guarantees exist only on
// a POSIX host and are deliberately not emulated elsewhere.

//go:build unix

package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"winsvpn.local/winnprotocol/internal/phase1anchor"
	"winsvpn.local/winnprotocol/internal/securefile"
)

func main() {
	providerID := flag.String(
		"provider-id", "", "frozen independent provider identity",
	)
	ledgerDirectory := flag.String(
		"ledger-directory", "", "private append-only ledger directory",
	)
	privateKeyPath := flag.String(
		"private-key", "", "raw Ed25519 private key path",
	)
	outputPath := flag.String(
		"output", "", "optional exclusive receipt output path",
	)
	flag.Parse()
	if flag.NArg() != 0 {
		fatal(errors.New("positional arguments are forbidden"))
	}
	if *providerID == "" {
		fatal(errors.New("provider-id is required"))
	}
	if *ledgerDirectory == "" {
		fatal(errors.New("ledger-directory is required"))
	}
	private, err := readPrivateKey(*privateKeyPath)
	if err != nil {
		fatal(err)
	}
	request, err := phase1anchor.DecodeRequest(os.Stdin)
	if err != nil {
		reject(err)
	}
	receipt, err := (phase1anchor.Ledger{
		Directory:  *ledgerDirectory,
		ProviderID: *providerID,
		PrivateKey: private,
	}).Append(request)
	if err != nil {
		if phase1anchor.IsRejection(err) {
			reject(err)
		}
		fatal(err)
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		fatal(err)
	}
	encoded = append(encoded, '\n')
	if *outputPath != "" {
		if err := createExclusive(*outputPath, encoded); err != nil {
			fatal(err)
		}
		return
	}
	if _, err := os.Stdout.Write(encoded); err != nil {
		fatal(err)
	}
}

func createExclusive(path string, content []byte) error {
	// #nosec G304 -- this optional output is an explicit administrator path;
	// O_EXCL prevents replacement.
	file, err := os.OpenFile(
		path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600,
	)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Sync(); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Close(); err != nil {
		return err
	}
	// Sync the parent directory so the new entry is durable. Ledger does this
	// after every durable append (ledger.go:197); the optional output must be
	// equally durable or a crash could lose a receipt the ledger already
	// committed while the output appears to have succeeded.
	dir := filepath.Dir(path)
	// #nosec G304 -- dir is the parent of an administrator-supplied output path.
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return errors.Join(syncErr, closeErr)
	}
	return nil
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("private key path is required")
	}
	data, err := securefile.ReadPrivateLimited(
		path, ed25519.PrivateKeySize,
	)
	if err != nil {
		return nil, err
	}
	if len(data) != ed25519.PrivateKeySize {
		return nil, errors.New("Ed25519 private key has the wrong size")
	}
	return ed25519.PrivateKey(data), nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ANCHOR_FAIL:", err)
	os.Exit(1)
}

func reject(err error) {
	fmt.Fprintln(os.Stderr, "ANCHOR_REJECT:", err)
	os.Exit(1)
}
