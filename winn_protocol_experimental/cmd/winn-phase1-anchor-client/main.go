package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"winsvpn.local/winnprotocol/internal/phase1anchor"
	"winsvpn.local/winnprotocol/internal/securefile"
)

const (
	requestFileLimit   = 64 << 10
	receiptFileLimit   = 64 << 10
	publicKeyFileLimit = 4 << 10
	exclusiveFileMode  = 0o600
)

func main() {
	mode := flag.String(
		"mode", "", "canonicalize or verify",
	)
	requestPath := flag.String(
		"request", "", "archive-pin request JSON",
	)
	outputPath := flag.String(
		"output", "", "exclusive canonical request output",
	)
	receiptPath := flag.String(
		"receipt", "", "provider receipt JSON",
	)
	publicKeyPath := flag.String(
		"public-key", "", "base64 Ed25519 public key",
	)
	providerID := flag.String(
		"provider-id", "", "expected provider identity",
	)
	previousDigest := flag.String(
		"previous-receipt-digest", "", "expected previous receipt digest",
	)
	flag.Parse()
	if flag.NArg() != 0 {
		fatal(errors.New("positional arguments are forbidden"))
	}
	request := mustRequest(*requestPath)
	switch *mode {
	case "canonicalize":
		if *outputPath == "" {
			fatal(errors.New("canonicalize mode requires output"))
		}
		canonical, err := request.Canonical()
		if err != nil {
			fatal(err)
		}
		if err := createExclusive(
			*outputPath, append(canonical, '\n'), exclusiveFileMode,
		); err != nil {
			fatal(err)
		}
		if err := printCanonicalRequest(os.Stdout, request); err != nil {
			fatal(err)
		}
	case "verify":
		receipt := mustReceipt(*receiptPath)
		public := mustPublicKey(*publicKeyPath)
		if err := receipt.Verify(
			request, *providerID, public, *previousDigest,
		); err != nil {
			fatal(err)
		}
		if err := printVerifiedReceipt(os.Stdout, receipt); err != nil {
			fatal(err)
		}
	default:
		fatal(errors.New("mode must be canonicalize or verify"))
	}
}

func printCanonicalRequest(out io.Writer, request phase1anchor.Request) error {
	requestDigest, err := request.Digest()
	if err != nil {
		return err
	}
	idempotencyKey, err := request.IdempotencyKey()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(
		out,
		"REQUEST_SHA256=%s\nIDEMPOTENCY_KEY=%s\n",
		requestDigest, idempotencyKey,
	)
	return err
}

func printVerifiedReceipt(out io.Writer, receipt phase1anchor.Receipt) error {
	digest, err := receipt.Digest()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "RECEIPT_SHA256=%s\n", digest)
	return err
}

func mustRequest(path string) phase1anchor.Request {
	data, err := securefile.ReadPublicIntegrity(path, requestFileLimit)
	if err != nil {
		fatal(err)
	}
	request, err := phase1anchor.DecodeRequest(bytes.NewReader(data))
	if err != nil {
		fatal(err)
	}
	return request
}

func mustReceipt(path string) phase1anchor.Receipt {
	data, err := securefile.ReadPublicIntegrity(path, receiptFileLimit)
	if err != nil {
		fatal(err)
	}
	receipt, err := phase1anchor.DecodeReceipt(bytes.NewReader(data))
	if err != nil {
		fatal(err)
	}
	return receipt
}

func mustPublicKey(path string) ed25519.PublicKey {
	data, err := securefile.ReadPublicIntegrity(path, publicKeyFileLimit)
	if err != nil {
		fatal(err)
	}
	public, err := parseProviderPublicKey(data)
	if err != nil {
		fatal(err)
	}
	return public
}

func parseProviderPublicKey(data []byte) (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(
		string(bytes.TrimSpace(data)),
	)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("provider public key is invalid")
	}
	return ed25519.PublicKey(decoded), nil
}

func createExclusive(
	path string,
	content []byte,
	mode os.FileMode,
) error {
	// #nosec G304 -- output is an explicit caller path and O_EXCL prevents
	// replacement of an existing pending request.
	file, err := os.OpenFile(
		path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode,
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
	return file.Close()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ANCHOR_CLIENT_FAIL:", err)
	os.Exit(1)
}
