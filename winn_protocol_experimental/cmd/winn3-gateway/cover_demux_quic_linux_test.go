//go:build linux

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func selfSignedTLS(t *testing.T, alpn string) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "l4-cover-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"l4-cover-test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{alpn},
		MinVersion:   tls.VersionTLS13,
	}
}

// TestNetnsRealQUICCoverConnectionSurvivesFqRefusal wires a REAL quic-go server
// on the shared demux socket (split.quic, exactly as cover.go does) and dials
// two real quic-go clients from the client netns. The handshake completes under
// a permissive qdisc; then an fq flow_limit qdisc throttles the gateway's egress
// while the server streams a payload to each client. quic-go v0.60.0 destroys a
// connection on any non-EMSGSIZE write error, so if the cover WriteTo returned
// ENOBUFS the transfer would fail. It must instead survive: both connections
// complete their transfers on the same shared socket.
func TestNetnsRealQUICCoverConnectionSurvivesFqRefusal(t *testing.T) {
	requireGatewayL4Netns(t)
	// Permissive during the handshake.
	gatewayL4Sh(t, "ip", "netns", "exec", "l4g", "tc", "qdisc", "replace", "dev", "l4g0", "root", "pfifo", "limit", "5000")
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "exec", "l4g", "tc", "qdisc", "replace", "dev", "l4g0", "root", "pfifo", "limit", "1000").Run()
	})

	real := gatewayL4UDP(t, "l4g", netip.MustParseAddrPort("10.44.1.1:0"))
	setRawRecvErrOn(t, real)
	split := newSplitUDP(real, demuxDatagramMin)
	defer split.stop()

	serverTLS := selfSignedTLS(t, "l4-cover")
	tr := &quic.Transport{
		Conn:                  split.quic,
		ConnectionIDLength:    split.cidGen.ConnectionIDLen(),
		ConnectionIDGenerator: split.cidGen,
	}
	defer tr.Close()
	// InitialPacketSize 1200 (the QUIC minimum): the lab client link is MTU
	// 1280, and quic-go's default 1280-byte UDP payload plus 28 header bytes
	// would not fit it.
	qconf := &quic.Config{
		InitialPacketSize:    1200,
		HandshakeIdleTimeout: 8 * time.Second,
		MaxIdleTimeout:       60 * time.Second,
		KeepAlivePeriod:      2 * time.Second,
	}
	ln, err := tr.Listen(serverTLS, qconf)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const payloadLen = 64 * 1024
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = byte(i * 7)
	}

	srvCtx, srvCancel := context.WithCancel(context.Background())
	defer srvCancel()
	go func() {
		for {
			conn, err := ln.Accept(srvCtx)
			if err != nil {
				return
			}
			go func(c *quic.Conn) {
				for {
					st, err := c.AcceptStream(srvCtx)
					if err != nil {
						return
					}
					go func(s *quic.Stream) {
						defer s.Close()
						buf := make([]byte, 2)
						_, _ = io.ReadFull(s, buf) // wait for the client's "go"
						_, _ = s.Write(payload)
					}(st)
				}
			}(conn)
		}
	}()

	serverAddr := net.UDPAddrFromAddrPort(real.LocalAddr().(*net.UDPAddr).AddrPort())
	clientTLS := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"l4-cover"}, MinVersion: tls.VersionTLS13}

	// Dial both connections up front, under the permissive qdisc.
	dial := func() (*quic.Conn, error) {
		pc := gatewayL4UDP(t, "l4c", netip.MustParseAddrPort("10.44.2.3:0"))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return quic.Dial(ctx, pc, serverAddr, clientTLS, qconf)
	}
	conns := make([]*quic.Conn, 2)
	for i := range conns {
		c, err := dial()
		if err != nil {
			t.Fatalf("handshake for connection %d failed under the permissive qdisc: %v", i, err)
		}
		conns[i] = c
		defer c.CloseWithError(0, "done")
	}

	// Now throttle the gateway egress so the bulk transfer draws fq refusals.
	gatewayL4Sh(t, "ip", "netns", "exec", "l4g", "tc", "qdisc", "replace", "dev", "l4g0", "root",
		"fq", "flow_limit", "16", "maxrate", "30mbit")

	receive := func(c *quic.Conn) error {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		st, err := c.OpenStreamSync(ctx)
		if err != nil {
			return err
		}
		if _, err := st.Write([]byte("go")); err != nil {
			return err
		}
		got := make([]byte, 0, payloadLen)
		buf := make([]byte, 16<<10)
		for len(got) < payloadLen {
			_ = st.SetReadDeadline(time.Now().Add(45 * time.Second))
			n, err := st.Read(buf)
			got = append(got, buf[:n]...)
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
		}
		if len(got) != payloadLen {
			return fmt.Errorf("read %d of %d bytes", len(got), payloadLen)
		}
		return nil
	}

	var wg sync.WaitGroup
	errs := make([]error, len(conns))
	for i := range conns {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = receive(conns[i])
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Fatalf("connection %d failed under fq refusal (quic-go would have destroyed it on a returned ENOBUFS): %v", i, e)
		}
	}
	st := split.errq.Stats()
	if st.ScalarRefused == 0 {
		t.Fatalf("no scalar fq refusal occurred, so the test did not exercise refusal handling; scalar stats=%+v", st)
	}
	t.Logf("both cover connections completed %d bytes under fq flow_limit; scalar stats=%+v", payloadLen, st)
}
