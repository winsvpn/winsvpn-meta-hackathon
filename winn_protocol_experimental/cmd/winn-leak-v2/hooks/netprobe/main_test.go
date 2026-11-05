package main

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestParseConfigRejectsSecretOrHostnameEndpoints(t *testing.T) {
	t.Parallel()
	_, err := parseConfig([]string{
		"-operation=http",
		"-expect=success",
		"-endpoint=observer.example:80",
		"-run-id=11111111111111111111111111111111",
		"-nonce=22222222222222222222222222222222",
		"-expected-peer=192.0.2.1",
	})
	if err == nil {
		t.Fatal("hostname endpoint unexpectedly accepted")
	}
	_, err = parseConfig([]string{
		"-operation=udp-echo",
		"-expect=success",
		"-endpoint=192.0.2.1:7007",
		"-payload=unsafe\npayload-value",
	})
	if err == nil {
		t.Fatal("unsafe payload unexpectedly accepted")
	}
}

func TestReachedEndpointErrorIsDistinguishable(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("invalid response")
	current := reached(sentinel)
	var reachable *reachedEndpointError
	if !errors.As(current, &reachable) || !errors.Is(current, sentinel) {
		t.Fatal("reached endpoint error lost its classification or cause")
	}
}

func TestParseSTUNXORMappedIPv4(t *testing.T) {
	t.Parallel()
	transaction := []byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	}
	expected := netip.MustParseAddrPort("192.0.2.44:51820")
	value := make([]byte, 8)
	value[1] = 0x01
	binary.BigEndian.PutUint16(
		value[2:4],
		expected.Port()^uint16(stunCookie>>16),
	)
	cookie := make([]byte, 4)
	binary.BigEndian.PutUint32(cookie, stunCookie)
	address := expected.Addr().As4()
	for index := range address {
		value[4+index] = address[index] ^ cookie[index]
	}
	response := stunResponse(transaction, value)
	actual, err := parseSTUN(response, transaction)
	if err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("mapped address = %s, want %s", actual, expected)
	}
}

func TestParseSTUNXORMappedIPv6(t *testing.T) {
	t.Parallel()
	transaction := []byte{
		11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
	}
	expected := netip.MustParseAddrPort("[2001:db8::44]:46379")
	value := make([]byte, 20)
	value[1] = 0x02
	binary.BigEndian.PutUint16(
		value[2:4],
		expected.Port()^uint16(stunCookie>>16),
	)
	mask := make([]byte, 16)
	binary.BigEndian.PutUint32(mask[:4], stunCookie)
	copy(mask[4:], transaction)
	address := expected.Addr().As16()
	for index := range address {
		value[4+index] = address[index] ^ mask[index]
	}
	response := stunResponse(transaction, value)
	actual, err := parseSTUN(response, transaction)
	if err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("mapped address = %s, want %s", actual, expected)
	}
}

func stunResponse(transaction, value []byte) []byte {
	response := make([]byte, 24+len(value))
	binary.BigEndian.PutUint16(response[0:2], 0x0101)
	binary.BigEndian.PutUint16(response[2:4], uint16(4+len(value))) // #nosec G115 -- test values are tiny.
	binary.BigEndian.PutUint32(response[4:8], stunCookie)
	copy(response[8:20], transaction)
	binary.BigEndian.PutUint16(response[20:22], 0x0020)
	binary.BigEndian.PutUint16(response[22:24], uint16(len(value))) // #nosec G115 -- test values are tiny.
	copy(response[24:], value)
	return response
}

func TestValidateDNSResponse(t *testing.T) {
	t.Parallel()
	answer := netip.MustParseAddr("198.51.100.9")
	name := dnsmessage.MustNewName("probe.leak-v2.invalid.")
	message := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
			},
			Body: &dnsmessage.AResource{A: answer.As4()},
		}},
	}
	payload, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	detail, err := validateDNSResponse(config{
		queryType: dnsmessage.TypeA, expectedAnswer: answer,
	}, payload)
	if err != nil || detail == "" {
		t.Fatalf("validateDNSResponse() = %q, %v", detail, err)
	}
}
