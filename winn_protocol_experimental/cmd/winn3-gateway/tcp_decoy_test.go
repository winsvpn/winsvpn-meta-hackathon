package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/decoy"
	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/driver"
)

type recordedTCPWrite struct {
	net.Conn
	written []byte
}

func (c *recordedTCPWrite) Write(src []byte) (int, error) {
	n, err := c.Conn.Write(src)
	c.written = append(c.written, src[:n]...)
	return n, err
}

func decoyReply(t *testing.T, endpoint string, wire []byte) []byte {
	t.Helper()
	conn, err := net.Dial("tcp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(7 * time.Second))
	if _, err := conn.Write(wire); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(conn)
	if err != nil && !(len(reply) > 0 && errors.Is(err, syscall.ECONNRESET)) {
		t.Fatal(err)
	}
	return reply
}

func observedDecoyReply(t *testing.T, endpoint string, wire []byte, spacing time.Duration) ([]byte, time.Duration, time.Duration) {
	t.Helper()
	conn, err := net.Dial("tcp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	started := time.Now()
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		if spacing == 0 {
			_, _ = conn.Write(wire)
			return
		}
		for _, b := range wire {
			if _, err := conn.Write([]byte{b}); err != nil {
				return
			}
			time.Sleep(spacing)
		}
	}()
	var first [1]byte
	n, err := conn.Read(first[:])
	firstByte := time.Since(started)
	if err != nil || n != 1 {
		t.Fatalf("decoy first byte n=%d err=%v", n, err)
	}
	rest, err := io.ReadAll(conn)
	closed := time.Since(started)
	<-sent
	if err != nil && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatal(err)
	}
	return append(first[:], rest...), firstByte, closed
}

func withoutDate(response []byte) []byte {
	lines := bytes.Split(response, []byte("\r\n"))
	for n, line := range lines {
		if bytes.HasPrefix(line, []byte("Date: ")) {
			lines[n] = []byte("Date: <clock>")
		}
	}
	return bytes.Join(lines, []byte("\r\n"))
}

func TestTCPIngressPreservesPristineDecoyBytes(t *testing.T) {
	dir := t.TempDir()
	if err := runKeygen(dir, io.Discard); err != nil {
		t.Fatal(err)
	}
	cfg, err := buildSessionConfig(serveOptions{
		staticPath: filepath.Join(dir, "static.key"),
		admission:  filepath.Join(dir, "admission.key"), gatewayID: testGatewayID,
	})
	if err != nil {
		t.Fatal(err)
	}
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP, carrier.ClassTCP)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := decoy.NewOrigin(decoy.Config{})
	if err != nil {
		t.Fatal(err)
	}
	pristineRaw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pristine := decoy.TLSOnlyListener(pristineRaw, 5*time.Second, origin)
	defer pristine.Close()
	newRaw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ingress := newTCPIngress(newRaw, cfg.Core.Gateway.AdmissionKeys[0], cfg, sizing)
	ingress.setAdmissionGate(func() bool { return true })
	withTCP := decoy.TLSOnlyListener(ingress, 5*time.Second, origin)
	defer withTCP.Close()
	cover := writeLabCover(t)
	certificate, err := tls.LoadX509KeyPair(cover.coverCertPath, cover.coverKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	serveTLS := func(listener net.Listener) {
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				go func() {
					_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
					server := tls.Server(conn, &tls.Config{
						Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13,
					})
					_ = server.Handshake()
					_ = server.Close()
				}()
			}
		}()
	}
	serveTLS(pristine)
	serveTLS(withTCP)
	acceptedOnce := make(chan struct{}, 1)
	go func() {
		for {
			select {
			case accepted := <-ingress.accepted:
				select {
				case acceptedOnce <- struct{}{}:
				default:
				}
				_ = accepted.stream.Close()
			case <-ingress.done:
				return
			}
		}
	}()
	for _, tc := range []struct {
		name    string
		wire    []byte
		spacing time.Duration
	}{
		{"garbage", bytes.Repeat([]byte{0}, 64), 0},
		{"partial first record", bytes.Repeat([]byte{0x42}, 10), 0},
		{"cleartext HTTP", []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"), 0},
		{"slow drip", bytes.Repeat([]byte{0x42}, 10), 100 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want, pristineFirst, pristineClose := observedDecoyReply(t, pristine.Addr().String(), tc.wire, tc.spacing)
			got, ingressFirst, ingressClose := observedDecoyReply(t, withTCP.Addr().String(), tc.wire, tc.spacing)
			if !bytes.Equal(withoutDate(got), withoutDate(want)) {
				t.Fatalf("TCP ingress changed the pristine decoy reply for %s", tc.name)
			}
			if ingressFirst > pristineFirst+400*time.Millisecond || ingressClose > pristineClose+400*time.Millisecond {
				t.Fatalf("TCP ingress delayed %s: pristine first=%v close=%v, ingress first=%v close=%v",
					tc.name, pristineFirst, pristineClose, ingressFirst, ingressClose)
			}
			t.Logf("pristine first=%v close=%v; ingress first=%v close=%v", pristineFirst, pristineClose, ingressFirst, ingressClose)
		})
	}
	partialTLSClose := func(t *testing.T, endpoint string) ([]byte, time.Duration) {
		t.Helper()
		conn, err := net.Dial("tcp", endpoint)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		started := time.Now()
		_ = conn.SetDeadline(started.Add(8 * time.Second))
		if _, err := conn.Write([]byte{0x16, 0x03, 0x01, 0x00}); err != nil {
			t.Fatal(err)
		}
		response, err := io.ReadAll(conn)
		if err != nil && !errors.Is(err, syscall.ECONNRESET) {
			t.Fatal(err)
		}
		return response, time.Since(started)
	}
	pristinePartial, pristineClose := partialTLSClose(t, pristine.Addr().String())
	ingressPartial, ingressClose := partialTLSClose(t, withTCP.Addr().String())
	if !bytes.Equal(ingressPartial, pristinePartial) || ingressClose > pristineClose+400*time.Millisecond {
		t.Fatalf("partial TLS decoy changed: pristine bytes=%x close=%v, ingress bytes=%x close=%v",
			pristinePartial, pristineClose, ingressPartial, ingressClose)
	}
	t.Logf("partial TLS close: pristine=%v ingress=%v", pristineClose, ingressClose)
	first := capturedInitiation(t, dir, cfg)
	sendStream := func(t *testing.T, salt byte, secret []byte, record bool) ([]byte, []byte) {
		t.Helper()
		raw, err := net.Dial("tcp", withTCP.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conn := &recordedTCPWrite{Conn: raw}
		stream, err := carrier.NewStream(carrier.StreamConfig{
			Conn: conn, Secret: secret,
			Role: carrier.RoleClient, Rand: bytes.NewReader(bytes.Repeat([]byte{salt}, 16)),
			MaxMessageSize: sizing.MessageSize, PathMTU: sizing.PathMTU, TCPFirstFlight: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := stream.Send(context.Background(), first); err != nil {
			t.Fatal(err)
		}
		wire := bytes.Clone(conn.written)
		if len(wire) < 5 || !bytes.Equal(wire[:3], []byte{0x16, 0x03, 0x01}) {
			t.Fatal("TCP first flight is not ClientHello shaped")
		}
		if !record {
			select {
			case <-acceptedOnce:
			case <-time.After(3 * time.Second):
				t.Fatal("fresh TCP initiation was not authenticated")
			}
			_ = stream.Close()
			return wire, nil
		}
		_ = raw.SetReadDeadline(time.Now().Add(7 * time.Second))
		reply, err := io.ReadAll(raw)
		if err != nil && !(len(reply) > 0 && errors.Is(err, syscall.ECONNRESET)) {
			t.Fatal(err)
		}
		_ = stream.Close()
		return wire, reply
	}
	_, _ = sendStream(t, 0x41, cfg.Core.Gateway.AdmissionKeys[0], false)
	for _, tc := range []struct {
		name   string
		salt   byte
		secret []byte
	}{
		{"replayed initiation", 0x42, cfg.Core.Gateway.AdmissionKeys[0]},
		{"unauthenticated stream", 0x43, bytes.Repeat([]byte{0x55}, len(cfg.Core.Gateway.AdmissionKeys[0]))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, got := sendStream(t, tc.salt, tc.secret, true)
			want := decoyReply(t, pristine.Addr().String(), wire)
			if !bytes.Equal(withoutDate(got), withoutDate(want)) {
				t.Fatalf("%s did not receive the pristine decoy reply", tc.name)
			}
		})
	}
	ingress.setAdmissionGate(func() bool { return false })
	wire, got := sendStream(t, 0x44, cfg.Core.Gateway.AdmissionKeys[0], true)
	want := decoyReply(t, pristine.Addr().String(), wire)
	if !bytes.Equal(withoutDate(got), withoutDate(want)) {
		t.Fatal("closed TCP handshake admission did not use the pristine decoy")
	}
}
