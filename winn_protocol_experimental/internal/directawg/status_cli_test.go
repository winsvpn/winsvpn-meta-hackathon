package directawg

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSecretFreeStatusParsersSelectExpectedPeer(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x6a}, 32))
	other := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x7b}, 32))
	handshake := time.Now().UTC().Truncate(time.Second)
	handshakeOutput := other + "\t0\n" + key + "\t" +
		strconv.FormatInt(handshake.Unix(), 10) + "\n"
	parsedHandshake, err := parseLatestHandshake(
		[]byte(handshakeOutput), key,
	)
	if err != nil {
		t.Fatal(err)
	}
	rxBytes, txBytes, err := parseTransfer(
		[]byte(other+"\t0\t0\n"+key+"\t123\t456\n"), key,
	)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := parseEndpoint(
		[]byte(other+"\t127.0.0.1:4000\n"+
			key+"\t127.0.0.1:5000\n"), key,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !parsedHandshake.Equal(handshake) ||
		rxBytes != 123 || txBytes != 456 ||
		endpoint != "127.0.0.1:5000" {
		t.Fatalf(
			"parsed status = handshake=%s rx=%d tx=%d endpoint=%q",
			parsedHandshake, rxBytes, txBytes, endpoint,
		)
	}
}

func TestSecretFreeStatusParsersRejectMalformedMissingAndDuplicatePeer(
	t *testing.T,
) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x6a}, 32))
	other := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x1}, 32))
	tests := []struct {
		name  string
		parse func() error
	}{
		{"duplicate", func() error {
			_, err := parseLatestHandshake(
				[]byte(key+"\t0\n"+key+"\t1\n"), key,
			)
			return err
		}},
		{"missing", func() error {
			_, _, err := parseTransfer([]byte(other+"\t1\t2\n"), key)
			return err
		}},
		{"bad-field-count", func() error {
			_, err := parseEndpoint([]byte(key+"\tendpoint\textra\n"), key)
			return err
		}},
		{"bad-counter", func() error {
			_, _, err := parseTransfer([]byte(key+"\tbad\t2\n"), key)
			return err
		}},
		{"bad-key", func() error {
			_, err := parseEndpoint([]byte("not-a-key\t(none)\n"), key)
			return err
		}},
		{"empty-interior-line", func() error {
			_, err := parseEndpoint(
				[]byte(other+"\t(none)\n\n"+key+"\t(none)\n"), key,
			)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.parse(); err == nil {
				t.Fatal("invalid AWG status output was accepted")
			}
		})
	}
}

func TestBoundedStatusQueryRejectsOversizedOutputAndUnsupportedField(
	t *testing.T,
) {
	source := &CLIStatusSource{}
	if _, err := source.query(context.Background(), "dump"); err == nil {
		t.Fatal("secret-bearing dump query was accepted")
	}

	if testing.Short() {
		t.Skip("helper executable test")
	}
	if runtime.GOOS == "windows" {
		t.Skip("POSIX helper executable test")
	}
	script := filepath.Join(t.TempDir(), "oversized-status")
	body := "#!/bin/sh\nhead -c 1048577 /dev/zero\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	source.binary = script
	source.interfaceName = "awg0"
	if _, err := source.query(
		context.Background(), "latest-handshakes",
	); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("oversized query error = %v", err)
	}
}

func TestBoundedBufferReportsTruncationWithoutShortWrite(t *testing.T) {
	var buffer boundedBuffer
	buffer.limit = 4
	count, err := buffer.Write([]byte("123456"))
	if err != nil || count != 6 || !buffer.exceeded ||
		!bytes.Equal(buffer.Bytes(), []byte("1234")) {
		t.Fatalf(
			"bounded write = count=%d err=%v exceeded=%t data=%q",
			count, err, buffer.exceeded, buffer.Bytes(),
		)
	}
}
