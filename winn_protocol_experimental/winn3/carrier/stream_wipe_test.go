package carrier

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// TestStreamCloseZeroisesPartialRecvSaltAndSecret is the carrier half of
// session key wipe: Stream.Close already cleared the admission-secret copy
// and sendSalt, but left a mid-handshake recvSalt (and, after a successful
// Recv, niled recvSalt without clear). A crash dump of a stream that died
// during the peer-salt read would still hold that salt next to a secret
// that Close had already zeroised — or, before Close, both.
//
// Client-visible: the stream is closed. The assertion is that secret,
// sendSalt and recvSalt are gone, not that Recv failed.
func TestStreamCloseZeroisesPartialRecvSaltAndSecret(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })

	secret := testSecret(t)
	gateway, err := NewStream(StreamConfig{
		Conn: b, Secret: secret, Role: RoleGateway, Class: ClassTCP,
		Rand: &countingRand{}, Clock: newFakeClock(),
	})
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}

	partial := make([]byte, 8)
	for i := range partial {
		partial[i] = byte(0xA0 + i)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := a.Write(partial)
		writeDone <- err
	}()

	short, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	_, recvErr := gateway.Recv(short)
	cancel()
	if recvErr == nil {
		t.Fatal("Recv returned a message from 8 bytes of salt")
	}
	if !isTimeout(recvErr) && !errors.Is(recvErr, context.DeadlineExceeded) {
		t.Fatalf("partial Recv returned %v, want a timeout", recvErr)
	}
	if werr := <-writeDone; werr != nil {
		t.Fatalf("partial write: %v", werr)
	}
	if gateway.recvSaltGot != len(partial) {
		t.Fatalf("recvSaltGot=%d, want %d; the partial salt was not kept", gateway.recvSaltGot, len(partial))
	}
	if !secretHeld(gateway.recvSalt) {
		t.Fatal("recvSalt was empty after a mid-salt timeout; Close would have nothing to wipe")
	}
	if !secretHeld(gateway.secret) {
		t.Fatal("secret was empty before Close; the test cannot see a wipe")
	}
	if !secretHeld(gateway.sendSalt) {
		t.Fatal("sendSalt was empty before Close; NewStream did not draw a salt")
	}

	if err := gateway.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if secretHeld(gateway.secret) {
		t.Fatal("Close left the admission-secret copy reachable")
	}
	if secretHeld(gateway.sendSalt) {
		t.Fatal("Close left sendSalt reachable")
	}
	if secretHeld(gateway.recvSalt) {
		t.Fatal("Close left recvSalt reachable")
	}
	if gateway.recvSaltGot != 0 {
		t.Fatalf("Close left recvSaltGot=%d, want 0", gateway.recvSaltGot)
	}
}

func secretHeld(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return true
		}
	}
	return false
}
