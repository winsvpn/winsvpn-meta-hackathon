package main

import (
	"encoding/base64"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestDecodeKey(t *testing.T) {
	want := strings.Repeat("ab", 32)
	encoded := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\xab", 32)))
	got, err := decodeKey(encoded)
	if err != nil {
		t.Fatalf("decodeKey returned an error: %v", err)
	}
	if got != want {
		t.Fatalf("decodeKey = %q, want %q", got, want)
	}
	if _, err := decodeKey(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("decodeKey accepted a key that was not 32 bytes")
	}
}

func TestSplitParamsAndUAPIValue(t *testing.T) {
	want := []string{"jc=4", "h1=1234", "s4=64"}
	if got := splitParams(" jc=4, h1=1234 ,, s4=64 "); !reflect.DeepEqual(got, want) {
		t.Fatalf("splitParams = %#v, want %#v", got, want)
	}
	document := "private_key=ignored\nlast_handshake_time_sec=42\nerrno=0\n"
	if got := uapiValue(document, "last_handshake_time_sec"); got != "42" {
		t.Fatalf("uapiValue = %q, want 42", got)
	}
}

func TestStubTUNCloseUnblocksRead(t *testing.T) {
	stub := newStubTUN(1280)
	result := make(chan error, 1)
	go func() {
		_, err := stub.Read([][]byte{make([]byte, 1280)}, []int{0}, 0)
		result <- err
	}()
	if err := stub.Close(); err != nil {
		t.Fatalf("Close returned an error: %v", err)
	}
	if err := stub.Close(); err != nil {
		t.Fatalf("second Close returned an error: %v", err)
	}
	if err := <-result; !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Read after Close returned %v, want os.ErrClosed", err)
	}
}
