package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/phase1anchor"
)

func genesisRequest() phase1anchor.Request {
	return phase1anchor.Request{
		Schema:             phase1anchor.RequestSchema,
		Kind:               phase1anchor.KindGenesis,
		MatrixID:           "matrix-one",
		SourceDigest:       strings.Repeat("1", 64),
		AutoArtifactDigest: strings.Repeat("2", 64),
		ProfileDigest:      strings.Repeat("3", 64),
		ScheduleDigest:     strings.Repeat("4", 64),
		ExpectedBatchCount: 2,
		Ordinal:            0,
	}
}

func testPrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(
		[]byte("0123456789abcdef0123456789abcdef"),
	)
}

type errWriter struct {
	err error
}

func (writer errWriter) Write([]byte) (int, error) {
	return 0, writer.err
}

func TestPrintCanonicalRequestEmitsDigests(t *testing.T) {
	var out bytes.Buffer
	request := genesisRequest()
	if err := printCanonicalRequest(&out, request); err != nil {
		t.Fatal(err)
	}
	wantDigest, err := request.Digest()
	if err != nil {
		t.Fatal(err)
	}
	wantKey, err := request.IdempotencyKey()
	if err != nil {
		t.Fatal(err)
	}
	want := "REQUEST_SHA256=" + wantDigest + "\nIDEMPOTENCY_KEY=" + wantKey + "\n"
	if out.String() != want {
		t.Fatalf("stdout=%q want %q", out.String(), want)
	}
}

func TestPrintCanonicalRequestRefusesInvalidRequest(t *testing.T) {
	var out bytes.Buffer
	err := printCanonicalRequest(&out, phase1anchor.Request{})
	if err == nil {
		t.Fatal("invalid request printed as success")
	}
	if out.Len() != 0 {
		t.Fatalf("wrote %q on error", out.Bytes())
	}
}

func TestPrintCanonicalRequestReportsStdoutFailure(t *testing.T) {
	err := printCanonicalRequest(
		errWriter{err: errors.New("stdout closed")},
		genesisRequest(),
	)
	if err == nil {
		t.Fatal("stdout failure was ignored")
	}
	if !strings.Contains(err.Error(), "stdout closed") {
		t.Fatalf("error=%v", err)
	}
}

func TestPrintVerifiedReceiptRefusesInvalidReceipt(t *testing.T) {
	var out bytes.Buffer
	err := printVerifiedReceipt(&out, phase1anchor.Receipt{})
	if err == nil {
		t.Fatal("invalid receipt printed as success")
	}
	if out.Len() != 0 {
		t.Fatalf("wrote %q on error", out.Bytes())
	}
}

func TestPrintVerifiedReceiptReportsStdoutFailure(t *testing.T) {
	private := testPrivateKey()
	receipt, err := phase1anchor.NewReceipt(
		genesisRequest(),
		"provider-one",
		phase1anchor.ZeroDigest,
		"2026-07-25T00:00:00Z",
		private,
	)
	if err != nil {
		t.Fatal(err)
	}
	err = printVerifiedReceipt(
		errWriter{err: errors.New("stdout closed")},
		receipt,
	)
	if err == nil {
		t.Fatal("stdout failure was ignored")
	}
	if !strings.Contains(err.Error(), "stdout closed") {
		t.Fatalf("error=%v", err)
	}
}

func TestParseProviderPublicKeyAcceptsTrimmedStdEncoding(t *testing.T) {
	public := testPrivateKey().Public().(ed25519.PublicKey)
	encoded := []byte("  " + base64.StdEncoding.EncodeToString(public) + "\n")
	got, err := parseProviderPublicKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, public) {
		t.Fatalf("parsed key mismatch")
	}
}

func TestParseProviderPublicKeyRejectsInvalidMaterial(t *testing.T) {
	public := testPrivateKey().Public().(ed25519.PublicKey)
	cases := [][]byte{
		[]byte("not-base64"),
		[]byte(base64.StdEncoding.EncodeToString(public[:31])),
		[]byte(""),
	}
	for _, data := range cases {
		_, err := parseProviderPublicKey(data)
		if err == nil {
			t.Fatalf("accepted %q", data)
		}
		if err.Error() != "provider public key is invalid" {
			t.Fatalf("error=%v", err)
		}
	}
}

func TestCreateExclusiveRefusesReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "canonical.json")
	if err := createExclusive(path, []byte("first\n"), exclusiveFileMode); err != nil {
		t.Fatal(err)
	}
	if err := createExclusive(path, []byte("second\n"), exclusiveFileMode); err == nil {
		t.Fatal("O_EXCL allowed replacement")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "first\n" {
		t.Fatalf("content=%q", got)
	}
}

func TestLimitsMatchTheDocumentedKiBBounds(t *testing.T) {
	if requestFileLimit != 64<<10 || receiptFileLimit != 64<<10 {
		t.Fatalf(
			"request=%d receipt=%d",
			requestFileLimit, receiptFileLimit,
		)
	}
	if publicKeyFileLimit != 4<<10 {
		t.Fatalf("publicKey=%d", publicKeyFileLimit)
	}
	if exclusiveFileMode != 0o600 {
		t.Fatalf("mode=%o", exclusiveFileMode)
	}
}

func writePublicFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func buildClient(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "winn-phase1-anchor-client")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, output)
	}
	return bin
}

func runClient(t *testing.T, bin string, args ...string) (stdout, stderr string, exit int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	exit = 0
	if err != nil {
		exitError, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatal(err)
		}
		exit = exitError.ExitCode()
	}
	return outBuf.String(), errBuf.String(), exit
}

func TestCLICanonicalizeThenVerifyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	request := genesisRequest()
	canonical, err := request.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(dir, "request.json")
	writePublicFile(t, requestPath, append(canonical, '\n'))
	outputPath := filepath.Join(dir, "canonical.json")
	bin := buildClient(t)

	stdout, stderr, exit := runClient(
		t, bin,
		"-mode", "canonicalize",
		"-request", requestPath,
		"-output", outputPath,
	)
	if exit != 0 {
		t.Fatalf("canonicalize exit=%d stderr=%q stdout=%q", exit, stderr, stdout)
	}
	if stderr != "" {
		t.Fatalf("canonicalize stderr=%q", stderr)
	}
	wantDigest, err := request.Digest()
	if err != nil {
		t.Fatal(err)
	}
	wantKey, err := request.IdempotencyKey()
	if err != nil {
		t.Fatal(err)
	}
	wantOut := "REQUEST_SHA256=" + wantDigest + "\nIDEMPOTENCY_KEY=" + wantKey + "\n"
	if stdout != wantOut {
		t.Fatalf("canonicalize stdout=%q want %q", stdout, wantOut)
	}
	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, append(canonical, '\n')) {
		t.Fatalf("canonical file=%q", got)
	}

	stdout, stderr, exit = runClient(
		t, bin,
		"-mode", "canonicalize",
		"-request", requestPath,
		"-output", outputPath,
	)
	if exit != 1 {
		t.Fatalf("replacement exit=%d stderr=%q", exit, stderr)
	}
	if !strings.Contains(stderr, "ANCHOR_CLIENT_FAIL:") {
		t.Fatalf("replacement stderr=%q", stderr)
	}

	private := testPrivateKey()
	receipt, err := phase1anchor.NewReceipt(
		request,
		"provider-one",
		phase1anchor.ZeroDigest,
		"2026-07-25T00:00:00Z",
		private,
	)
	if err != nil {
		t.Fatal(err)
	}
	receiptBytes, err := receipt.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(dir, "receipt.json")
	writePublicFile(t, receiptPath, append(receiptBytes, '\n'))
	publicPath := filepath.Join(dir, "provider.pub")
	writePublicFile(
		t,
		publicPath,
		[]byte(base64.StdEncoding.EncodeToString(
			private.Public().(ed25519.PublicKey),
		)+"\n"),
	)

	stdout, stderr, exit = runClient(
		t, bin,
		"-mode", "verify",
		"-request", requestPath,
		"-receipt", receiptPath,
		"-public-key", publicPath,
		"-provider-id", "provider-one",
		"-previous-receipt-digest", phase1anchor.ZeroDigest,
	)
	if exit != 0 {
		t.Fatalf("verify exit=%d stderr=%q stdout=%q", exit, stderr, stdout)
	}
	wantReceipt, err := receipt.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "RECEIPT_SHA256="+wantReceipt+"\n" {
		t.Fatalf("verify stdout=%q", stdout)
	}

	stdout, stderr, exit = runClient(
		t, bin,
		"-mode", "verify",
		"-request", requestPath,
		"-receipt", receiptPath,
		"-public-key", publicPath,
		"-provider-id", "provider-two",
		"-previous-receipt-digest", phase1anchor.ZeroDigest,
	)
	if exit != 1 {
		t.Fatalf("wrong provider exit=%d stderr=%q", exit, stderr)
	}
	if !strings.Contains(stderr, "ANCHOR_CLIENT_FAIL:") {
		t.Fatalf("wrong provider stderr=%q", stderr)
	}
}

func TestCLIInvalidPublicKeyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	request := genesisRequest()
	canonical, err := request.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(dir, "request.json")
	writePublicFile(t, requestPath, append(canonical, '\n'))
	receipt, err := phase1anchor.NewReceipt(
		request,
		"provider-one",
		phase1anchor.ZeroDigest,
		"2026-07-25T00:00:00Z",
		testPrivateKey(),
	)
	if err != nil {
		t.Fatal(err)
	}
	receiptBytes, err := receipt.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(dir, "receipt.json")
	writePublicFile(t, receiptPath, append(receiptBytes, '\n'))
	publicPath := filepath.Join(dir, "provider.pub")
	writePublicFile(t, publicPath, []byte("not-a-key\n"))
	bin := buildClient(t)
	_, stderr, exit := runClient(
		t, bin,
		"-mode", "verify",
		"-request", requestPath,
		"-receipt", receiptPath,
		"-public-key", publicPath,
		"-provider-id", "provider-one",
		"-previous-receipt-digest", phase1anchor.ZeroDigest,
	)
	if exit != 1 {
		t.Fatalf("exit=%d stderr=%q", exit, stderr)
	}
	if !strings.Contains(stderr, "provider public key is invalid") {
		t.Fatalf("stderr=%q", stderr)
	}
}

func TestCLIPositionalArgumentsAreForbidden(t *testing.T) {
	bin := buildClient(t)
	_, stderr, exit := runClient(t, bin, "-mode", "canonicalize", "extra")
	if exit != 1 {
		t.Fatalf("exit=%d stderr=%q", exit, stderr)
	}
	if !strings.Contains(stderr, "positional arguments are forbidden") {
		t.Fatalf("stderr=%q", stderr)
	}
}

func TestCLIUnknownFlagExitsTwo(t *testing.T) {
	bin := buildClient(t)
	_, stderr, exit := runClient(t, bin, "-nope")
	if exit != 2 {
		t.Fatalf("exit=%d stderr=%q", exit, stderr)
	}
	if !strings.Contains(stderr, "flag provided but not defined: -nope") {
		t.Fatalf("stderr=%q", stderr)
	}
}

var _ io.Writer = errWriter{}
