package decoy

import (
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestListener(t *testing.T, peek time.Duration) (net.Listener, string) {
	t.Helper()
	return newTestListenerFor(t, peek, originFor(t, "www.example.test"))
}

func newTestListenerFor(
	t *testing.T, peek time.Duration, origin *Origin,
) (net.Listener, string) {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	guarded := TLSOnlyListener(inner, peek, origin)
	t.Cleanup(func() { _ = guarded.Close() })
	return guarded, inner.Addr().String()
}

// plaintextProbe is the probe a bulk scanner performs against port 443: a
// cleartext HTTP request, answered before any TLS handshake happens.
func plaintextProbe(t *testing.T, address string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	body, _ := io.ReadAll(conn)
	return string(body)
}

func acceptAndClose(listener net.Listener) {
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
}

// TestPlaintextGetsAnOrdinaryBadRequest is the regression test for the fifth
// discriminator: net/http answers cleartext on a TLS port with a string unique
// to the Go standard library.
func TestPlaintextGetsAnOrdinaryBadRequest(t *testing.T) {
	listener, address := newTestListener(t, 2*time.Second)
	acceptAndClose(listener)
	text := plaintextProbe(t, address)

	if !strings.HasPrefix(text, "HTTP/1.1 400 Bad Request") {
		t.Fatalf("response did not start with an ordinary 400: %q", text)
	}
	if strings.Contains(text, "Client sent an HTTP request to an HTTPS server") {
		t.Fatal("the Go standard library marker is still present")
	}
	if strings.Contains(strings.ToLower(text), "winn") {
		t.Fatal("the response identifies the service")
	}
	// No Server header: claiming to be software this is not would be a
	// fingerprint in the other direction.
	if strings.Contains(strings.ToLower(text), "\r\nserver:") {
		t.Fatalf("response advertises a Server header: %q", text)
	}
	// RFC 9110 requires HTTP dates to end in GMT. time.RFC1123 renders the
	// zone abbreviation, so a UTC clock produced "UTC" here - a discriminator
	// sitting inside the response whose job is to look unremarkable.
	if !strings.Contains(text, " GMT\r\n") {
		t.Fatalf("Date header is not an HTTP-date ending in GMT: %q", text)
	}
}

// TestPlaintextBadRequestDiffersAcrossDeployments closes the same correlator
// one layer below the cover site. A cleartext GET at port 443 is a probe bulk
// scanners already perform, it is answered before any handshake, and the body
// used to be a compiled-in constant identical on every Winn gateway - so it
// carried the whole fleet just as the index page did.
func TestPlaintextBadRequestDiffersAcrossDeployments(t *testing.T) {
	bodies := map[string]string{}
	for _, name := range []string{
		"www.example.test", "status.example.invalid", "cdn.node7.example", "a.example",
	} {
		listener, address := newTestListenerFor(t, 2*time.Second, originFor(t, name))
		acceptAndClose(listener)
		text := plaintextProbe(t, address)
		_, body, found := strings.Cut(text, "\r\n\r\n")
		if !found {
			t.Fatalf("%s: response has no body: %q", name, text)
		}
		if previous, clash := bodies[body]; clash {
			t.Fatalf(
				"%s and %s answer a cleartext probe with an identical body, which "+
					"is the fleet-wide identifier this was meant to remove",
				previous, name,
			)
		}
		bodies[body] = name
	}
}

func TestTLSBytesArePassedThroughIntact(t *testing.T) {
	listener, address := newTestListener(t, 2*time.Second)
	received := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buffer := make([]byte, 5)
		n, _ := io.ReadFull(conn, buffer)
		received <- buffer[:n]
	}()

	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	// A TLS record header: the classifier must replay the byte it consumed.
	want := []byte{0x16, 0x03, 0x01, 0x00, 0x2f}
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case got := <-received:
		if string(got) != string(want) {
			t.Fatalf("server saw % x, want % x", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("TLS connection never reached the server")
	}
}

// TestSilentConnectionDoesNotStallTheListener is why classification runs off
// the accept path: a peer that connects and says nothing must not be able to
// block everyone else.
func TestSilentConnectionDoesNotStallTheListener(t *testing.T) {
	listener, address := newTestListener(t, 30*time.Second)
	accepted := make(chan struct{}, 4)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			_ = conn.Close()
		}
	}()

	// One peer connects and stays silent for longer than the test runs.
	silent, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatalf("dial silent: %v", err)
	}
	defer silent.Close()

	// A TLS peer arriving afterwards must still be served promptly.
	speaker, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatalf("dial speaker: %v", err)
	}
	defer speaker.Close()
	if _, err := speaker.Write([]byte{0x16, 0x03, 0x01}); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("a silent peer stalled the accept path")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	guarded := TLSOnlyListener(inner, time.Second, originFor(t, "www.example.test"))
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = guarded.Close()
		}()
	}
	wg.Wait()
	if _, err := guarded.Accept(); err == nil {
		t.Fatal("Accept succeeded after Close")
	}
}
