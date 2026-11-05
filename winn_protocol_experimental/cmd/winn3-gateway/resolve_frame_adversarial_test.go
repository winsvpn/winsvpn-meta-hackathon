package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// TestReadDNSTCPFrameAdversarialInputs is the 2-byte length-prefix decoder
// that sits on the resolver's TCP/53 path. A hostile prefix of 0xFFFF
// allocates at most 65535 bytes (uint16); a prefix of 0 or 11 must not
// deliver a body; a truncated header must not look like a message.
func TestReadDNSTCPFrameAdversarialInputs(t *testing.T) {
	query := dnsQueryBytes(0x1111)
	ok := dnsTCPFrameMust(t, query)

	cases := []struct {
		name    string
		in      []byte
		wantErr error
		accept  bool
	}{
		{"round-trip query", ok, nil, true},
		{"length zero", []byte{0, 0}, errDNSTCPLengthZero, false},
		{"length 1", func() []byte {
			var b [3]byte
			binary.BigEndian.PutUint16(b[0:2], 1)
			b[2] = 0
			return b[:]
		}(), errDNSTCPTooShort, false},
		{"length 11 with 11 body bytes", func() []byte {
			b := make([]byte, 2+11)
			binary.BigEndian.PutUint16(b[0:2], 11)
			return b
		}(), errDNSTCPTooShort, false},
		{"length 12 exact (minimum DNS header)", func() []byte {
			body := make([]byte, dnsHeaderBytes)
			b := make([]byte, 2+dnsHeaderBytes)
			binary.BigEndian.PutUint16(b[0:2], uint16(dnsHeaderBytes))
			copy(b[2:], body)
			return b
		}(), nil, true},
		{"one-byte truncated header", []byte{0x00}, io.ErrUnexpectedEOF, false},
		{"empty stream", nil, io.EOF, false},
		{"length 20, five body bytes then EOF", func() []byte {
			b := make([]byte, 2+5)
			binary.BigEndian.PutUint16(b[0:2], 20)
			return b
		}(), io.ErrUnexpectedEOF, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readDNSTCPFrame(bytes.NewReader(tc.in))
			if tc.accept {
				if err != nil {
					t.Fatalf("accepted case returned %v", err)
				}
				if len(got) < dnsHeaderBytes {
					t.Fatalf("delivered %d bytes, below a DNS header", len(got))
				}
				return
			}
			if err == nil {
				t.Fatalf("malformed input was accepted (%d bytes)", len(got))
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if got != nil {
				t.Fatalf("error path delivered %d bytes; must be nil", len(got))
			}
		})
	}
}

// TestDNSQuestionSectionEndRefuses0x40Label pins the other reserved length
// encoding. TestDNSQuestionSectionEndRefusesWhatItWillNotParse already has
// 0xC0 (pointer) and 0x80 (10xxxxxx). 0x40 is 01xxxxxx, also reserved, and
// l&0xc0 != 0 is what rejects it. A decoder that only masked 0x80 would
// treat 0x40 as a 64-byte label and over-read.
func TestDNSQuestionSectionEndRefuses0x40Label(t *testing.T) {
	q := dnsQueryBytes(1)
	q[dnsHeaderBytes] = 0x40
	if _, ok := dnsQuestionSectionEnd(q); ok {
		t.Fatal("a 0x40 (01xxxxxx) label length was accepted")
	}
}

// TestDNSQuestionSectionEndRefusesUnterminatedName is the under-read of a
// name that never writes a zero label before the buffer ends.
func TestDNSQuestionSectionEndRefusesUnterminatedName(t *testing.T) {
	q := dnsQueryBytes(1)
	// Drop the root label and QTYPE/QCLASS, leave "example.com" labels only.
	// dnsQueryBytes is header + example + com + 0 + type + class.
	end, ok := dnsQuestionSectionEnd(q)
	if !ok {
		t.Fatal("control query was refused")
	}
	unterminated := q[:end-4] // strip QTYPE/QCLASS; last byte should be the root 0
	// Strip the root 0 as well if present.
	if len(unterminated) > 0 && unterminated[len(unterminated)-1] == 0 {
		unterminated = unterminated[:len(unterminated)-1]
	}
	if _, ok := dnsQuestionSectionEnd(unterminated); ok {
		t.Fatal("an unterminated name was accepted")
	}
}

// TestWriteDNSTCPFrameRefusesOversize is the encoder ceiling. The reader
// cannot see more than uint16 anyway; this pins the write-side refusal so
// a 65536-byte answer is not silently truncated to 0 on the wire
// (uint16(65536) == 0).
func TestWriteDNSTCPFrameRefusesOversize(t *testing.T) {
	if _, err := dnsTCPFrame(make([]byte, dnsTCPMaxMessage+1)); !errors.Is(err, errDNSTCPTooLong) {
		t.Fatalf("oversize = %v, want errDNSTCPTooLong", err)
	}
	if _, err := dnsTCPFrame(nil); !errors.Is(err, errDNSTCPLengthZero) {
		t.Fatalf("empty = %v, want errDNSTCPLengthZero", err)
	}
}
