package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestUDPSocketBufferConstantsSitInTheBriefedRange(t *testing.T) {
	if udpSocketBufferBytes < 4<<20 || udpSocketBufferBytes > 16<<20 {
		t.Fatalf("udpSocketBufferBytes is %d; the brief is 4–16 MiB", udpSocketBufferBytes)
	}
	if udpSocketBufferMinBytes < 4<<20 {
		t.Fatalf("udpSocketBufferMinBytes is %d; refusing below 4MiB is the floor", udpSocketBufferMinBytes)
	}
	if udpSocketBufferMinBytes > udpSocketBufferBytes {
		t.Fatalf("min %d > requested %d", udpSocketBufferMinBytes, udpSocketBufferBytes)
	}
}

func TestASocketLeftAtDefaultIsBelowTheFloorThisGuardExistsToCatch(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	got, err := udpSockoptInt(conn, syscall.SO_RCVBUF)
	if err != nil {
		t.Fatal(err)
	}
	if got >= udpSocketBufferMinBytes {
		t.Fatalf("kernel default SO_RCVBUF is %d, already >= the %d floor; "+
			"skipping SetReadBuffer would not be refused, so this guard is a zero-clause on this host",
			got, udpSocketBufferMinBytes)
	}
	err = udpBuffersTooSmall(got, got)
	if err == nil {
		t.Fatalf("udpBuffersTooSmall accepted the kernel default %d", got)
	}
	for _, needle := range []string{
		"rmem_max",
		"wins_winn3_gateway_install.sh",
		"UdpRcvbufErrors",
	} {
		if !strings.Contains(err.Error(), needle) {
			t.Errorf("refusal does not name %q:\n  %v", needle, err)
		}
	}
}

func TestConfigureUDPSocketBuffersRaisesAboveTheFloor(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	before, err := udpSockoptInt(conn, syscall.SO_RCVBUF)
	if err != nil {
		t.Fatal(err)
	}
	gotRead, gotWrite, err := configureUDPSocketBuffers(conn)
	if err != nil {
		t.Fatalf("configureUDPSocketBuffers: %v", err)
	}
	if gotRead < udpSocketBufferMinBytes {
		t.Fatalf("granted read %d < floor %d", gotRead, udpSocketBufferMinBytes)
	}
	if gotWrite < udpSocketBufferMinBytes {
		t.Fatalf("granted write %d < floor %d", gotWrite, udpSocketBufferMinBytes)
	}
	if gotRead <= before {
		t.Fatalf("SO_RCVBUF did not rise: before=%d after=%d (SetReadBuffer was a no-op)", before, gotRead)
	}
}

func TestUdpBuffersTooSmallAcceptsAGrantAtTheFloor(t *testing.T) {
	if err := udpBuffersTooSmall(udpSocketBufferMinBytes, udpSocketBufferMinBytes); err != nil {
		t.Fatalf("floor grant was refused: %v", err)
	}
	if err := udpBuffersTooSmall(udpSocketBufferBytes, udpSocketBufferBytes); err != nil {
		t.Fatalf("requested grant was refused: %v", err)
	}
}

func TestUdpBuffersTooSmallRefusesAQuarterMegabyteGrant(t *testing.T) {
	err := udpBuffersTooSmall(262144, 262144)
	if err == nil {
		t.Fatal("rmem_default-sized grant was accepted")
	}
	if !strings.Contains(err.Error(), "262144") {
		t.Errorf("refusal does not name the granted size: %v", err)
	}
}

func TestUDPBufferKeysReachTheWireAndSurviveZero(t *testing.T) {
	encoded, err := json.Marshal(serveStatus{
		Event:                  "listening",
		UdpReadBufferRequested: udpSocketBufferBytes,
		UdpReadBuffer:          8388608,
		UdpWriteBuffer:         8388608,
	})
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatal(err)
	}
	want := map[string]float64{
		"udp_read_buffer_requested": float64(udpSocketBufferBytes),
		"udp_read_buffer":           8388608,
		"udp_write_buffer":          8388608,
	}
	for key, n := range want {
		got, ok := back[key]
		if !ok {
			t.Fatalf("status must publish %q; body=%s", key, encoded)
		}
		if got != n {
			t.Fatalf("%s is %v, want %v: %s", key, got, n, encoded)
		}
	}
	zero, err := json.Marshal(serveStatus{Event: "posture"})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		`"udp_read_buffer_requested":0`,
		`"udp_read_buffer":0`,
		`"udp_write_buffer":0`,
	} {
		if !strings.Contains(string(zero), key) {
			t.Fatalf("%s omitted at zero (omitempty would hide a socket still at default): %s", key, zero)
		}
	}
	if strings.Contains(string(zero), "udp_rcvbuf_errors") {
		t.Fatalf("udp_rcvbuf_errors must be omitted when unread, not published as a fake 0: %s", zero)
	}
}

func TestStatusCopiesUDPBufferFields(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	for _, n := range []string{
		"UdpReadBufferRequested: udpSocketBufferBytes",
		"UdpReadBuffer:          s.udpReadBuffer",
		"UdpWriteBuffer:         s.udpWriteBuffer",
		"configureUDPSocketBuffers(conn)",
	} {
		if !strings.Contains(body, n) {
			t.Fatalf("main.go no longer contains %q; the JSON key would be a permanent zero", n)
		}
	}
	s := &server{
		peers:          make(map[netip.AddrPort]*peerSession),
		udpReadBuffer:  8388608,
		udpWriteBuffer: 4194304,
	}
	st := s.status()
	if st.UdpReadBuffer != 8388608 {
		t.Fatalf("status UdpReadBuffer is %d, want 8388608", st.UdpReadBuffer)
	}
	if st.UdpWriteBuffer != 4194304 {
		t.Fatalf("status UdpWriteBuffer is %d, want 4194304", st.UdpWriteBuffer)
	}
	if st.UdpReadBufferRequested != udpSocketBufferBytes {
		t.Fatalf("status UdpReadBufferRequested is %d, want %d", st.UdpReadBufferRequested, udpSocketBufferBytes)
	}
}

func TestListeningStatusPublishesGrantedUDPBuffers(t *testing.T) {
	var buf bytes.Buffer
	opts := operatorValueOptions(t)
	if err := runServe(opts, &buf); err != nil {
		t.Fatal(err)
	}
	var listening serveStatus
	found := false
	for _, line := range bytes.Split(buf.Bytes(), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var ev serveStatus
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("status line is not JSON: %s (%v)", line, err)
		}
		if ev.Event == "listening" {
			listening = ev
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no listening event in %q", buf.String())
	}
	if listening.UdpReadBufferRequested != udpSocketBufferBytes {
		t.Fatalf("listening udp_read_buffer_requested is %d, want %d",
			listening.UdpReadBufferRequested, udpSocketBufferBytes)
	}
	if listening.UdpReadBuffer < udpSocketBufferMinBytes {
		t.Fatalf("listening udp_read_buffer is %d, below floor %d; SetReadBuffer was skipped or clamped silently",
			listening.UdpReadBuffer, udpSocketBufferMinBytes)
	}
	if listening.UdpWriteBuffer < udpSocketBufferMinBytes {
		t.Fatalf("listening udp_write_buffer is %d, below floor %d",
			listening.UdpWriteBuffer, udpSocketBufferMinBytes)
	}
}

func TestParseUdpRcvbufErrorsReadsTheUdpColumnNotUdpLite(t *testing.T) {
	snmp := "" +
		"Ip: Forwarding DefaultTTL\n" +
		"Ip: 1 64\n" +
		"Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors\n" +
		"Udp: 10 1 2 20 7 3 0 0 0\n" +
		"UdpLite: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti\n" +
		"UdpLite: 0 0 0 0 99 0 0 0\n"
	n, ok := parseUdpRcvbufErrors(snmp)
	if !ok {
		t.Fatal("parser returned not-ok on a well-formed Udp section")
	}
	if n != 7 {
		t.Fatalf("RcvbufErrors is %d, want 7 (UdpLite is 99; a prefix match would steal it)", n)
	}
	if _, ok := parseUdpRcvbufErrors("Tcp: RtoAlgorithm RtoMin\nTcp: 1 200\n"); ok {
		t.Fatal("parser returned ok with no Udp section")
	}
}

func TestHostUdpRcvbufErrorsMatchesProcSnmpPresence(t *testing.T) {
	_, err := os.Stat("/proc/net/snmp")
	got := hostUdpRcvbufErrors()
	if err == nil {
		if got == nil {
			t.Fatal("/proc/net/snmp is readable but hostUdpRcvbufErrors returned nil")
		}
		return
	}
	if got != nil {
		t.Fatalf("/proc/net/snmp is absent but hostUdpRcvbufErrors returned %d", *got)
	}
}

func TestConfigureUDPSocketBuffersSourcePinsTheSets(t *testing.T) {
	src, err := os.ReadFile("udp_socket_buffers.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	for _, n := range []string{
		"conn.SetReadBuffer(udpSocketBufferBytes)",
		"conn.SetWriteBuffer(udpSocketBufferBytes)",
		"udpSockoptInt(conn, syscall.SO_RCVBUF)",
		"udpSockoptInt(conn, syscall.SO_SNDBUF)",
		"udpBuffersTooSmall(gotRead, gotWrite)",
	} {
		if !strings.Contains(body, n) {
			t.Fatalf("udp_socket_buffers.go no longer contains %q", n)
		}
	}
}
