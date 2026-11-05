package main

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDNSResponseRequiresNonceAndForcesTCP(t *testing.T) {
	t.Parallel()
	config := observerConfig{
		nonce:    "00112233445566778899aabbccddeeff",
		zone:     "leak-v2.invalid",
		answerV4: netip.MustParseAddr("203.0.113.99"),
		answerV6: netip.MustParseAddr("2001:db8::99"),
	}
	udpName := dnsmessage.MustNewName(
		"00112233445566778899aabbccddeeff.udp.leak-v2.invalid.",
	)
	tcpName := dnsmessage.MustNewName(
		"00112233445566778899aabbccddeeff.tcp.leak-v2.invalid.",
	)
	makeQuery := func(name dnsmessage.Name, queryType dnsmessage.Type) []byte {
		message := dnsmessage.Message{
			Header: dnsmessage.Header{ID: 42, RecursionDesired: true},
			Questions: []dnsmessage.Question{{
				Name: name, Type: queryType, Class: dnsmessage.ClassINET,
			}},
		}
		payload, err := message.Pack()
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}

	payload, event, ok := config.dnsResponse(
		makeQuery(udpName, dnsmessage.TypeA), "udp",
	)
	if !ok || event.Detail != "answered" {
		t.Fatalf("UDP response ok=%v event=%+v", ok, event)
	}
	var response dnsmessage.Message
	if err := response.Unpack(payload); err != nil {
		t.Fatal(err)
	}
	if response.Truncated || len(response.Answers) != 1 {
		t.Fatalf("UDP response = %+v", response)
	}

	payload, event, ok = config.dnsResponse(
		makeQuery(tcpName, dnsmessage.TypeAAAA), "udp",
	)
	if !ok || event.Detail != "force_tcp" {
		t.Fatalf("forced response ok=%v event=%+v", ok, event)
	}
	response = dnsmessage.Message{}
	if err := response.Unpack(payload); err != nil {
		t.Fatal(err)
	}
	if !response.Truncated || len(response.Answers) != 0 {
		t.Fatalf("forced response = %+v", response)
	}

	payload, event, ok = config.dnsResponse(
		makeQuery(tcpName, dnsmessage.TypeAAAA), "tcp",
	)
	if !ok || event.Detail != "answered" {
		t.Fatalf("TCP response ok=%v event=%+v", ok, event)
	}
	response = dnsmessage.Message{}
	if err := response.Unpack(payload); err != nil {
		t.Fatal(err)
	}
	if response.Truncated || len(response.Answers) != 1 {
		t.Fatalf("TCP response = %+v", response)
	}

	wrong := dnsmessage.MustNewName("wrong.udp.leak-v2.invalid.")
	if payload, _, ok := config.dnsResponse(
		makeQuery(wrong, dnsmessage.TypeA), "udp",
	); ok || payload != nil {
		t.Fatal("wrong nonce was accepted")
	}
}

func TestSTUNBindingResponseIPv4AndIPv6(t *testing.T) {
	t.Parallel()
	request := make([]byte, 20)
	binary.BigEndian.PutUint16(request[0:2], 0x0001)
	binary.BigEndian.PutUint32(request[4:8], stunMagicCookie)
	copy(request[8:20], []byte("transaction!"))

	for _, test := range []struct {
		name       string
		peer       *net.UDPAddr
		wantFamily byte
		wantSize   int
	}{
		{
			name: "v4",
			peer: &net.UDPAddr{
				IP: net.ParseIP("198.51.100.8"), Port: 54321,
			},
			wantFamily: 0x01,
			wantSize:   32,
		},
		{
			name: "v6",
			peer: &net.UDPAddr{
				IP: net.ParseIP("2001:db8::8"), Port: 54321,
			},
			wantFamily: 0x02,
			wantSize:   44,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			response, ok := stunBindingResponse(request, test.peer)
			if !ok {
				t.Fatal("request rejected")
			}
			if len(response) != test.wantSize {
				t.Fatalf("response size=%d want=%d", len(response), test.wantSize)
			}
			if got := binary.BigEndian.Uint16(response[0:2]); got != 0x0101 {
				t.Fatalf("response type=%#x", got)
			}
			if response[25] != test.wantFamily {
				t.Fatalf("family=%#x want=%#x", response[25], test.wantFamily)
			}
			if string(response[8:20]) != "transaction!" {
				t.Fatal("transaction ID changed")
			}
		})
	}
}

func TestHTTPHandlerBindsRunAndNonce(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "events.jsonl")
	writer, err := newEvidenceWriter(
		path, "00112233445566778899aabbccddeeff",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.close()
	config := observerConfig{
		runID:  "00112233445566778899aabbccddeeff",
		nonce:  "ffeeddccbbaa99887766554433221100",
		writer: writer,
	}
	request := httptest.NewRequest(
		http.MethodGet,
		"http://observer/v2/canary?run_id=00112233445566778899aabbccddeeff&nonce=ffeeddccbbaa99887766554433221100",
		nil,
	)
	request.RemoteAddr = "198.51.100.7:45678"
	response := httptest.NewRecorder()
	config.httpHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache-control=%q", got)
	}

	bad := httptest.NewRequest(
		http.MethodGet,
		"http://observer/v2/canary?run_id=00112233445566778899aabbccddeeff&nonce=wrong",
		nil,
	)
	bad.RemoteAddr = "198.51.100.7:45678"
	badResponse := httptest.NewRecorder()
	config.httpHandler().ServeHTTP(badResponse, bad)
	if badResponse.Code != http.StatusNotFound {
		t.Fatalf("bad request status=%d", badResponse.Code)
	}
}

func TestStunBindingResponseRejectsInvalidPort(t *testing.T) {
	t.Parallel()
	request := make([]byte, 20)
	binary.BigEndian.PutUint16(request[0:2], 0x0001)
	binary.BigEndian.PutUint32(request[4:8], stunMagicCookie)
	for _, port := range []int{-1, 0, 65536} {
		if response, ok := stunBindingResponse(
			request,
			&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: port},
		); ok || response != nil {
			t.Fatalf("port %d accepted", port)
		}
	}
}

func TestExclusivePrivateFileRequiresPrivateRealParent(t *testing.T) {
	t.Parallel()
	private := t.TempDir()
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := openExclusivePrivateFile(filepath.Join(private, "evidence.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	public := filepath.Join(t.TempDir(), "public")
	if err := os.Mkdir(public, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := openExclusivePrivateFile(filepath.Join(public, "evidence.jsonl")); err == nil {
		t.Fatal("world-accessible parent accepted")
	}

	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openExclusivePrivateFile(filepath.Join(link, "evidence.jsonl")); err == nil {
		t.Fatal("symlink parent accepted")
	}
}

func TestObserverValidation(t *testing.T) {
	t.Parallel()
	if err := validateZone("leak-v2.example."); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", "-bad.example", "bad_.example", "bad..example"} {
		if err := validateZone(invalid); err == nil {
			t.Fatalf("zone %q accepted", invalid)
		}
	}
	if _, err := parseListenList("127.0.0.1:8080,[::1]:8080"); err != nil {
		t.Fatal(err)
	}
	if _, err := parseListenList("0.0.0.0:8080"); err == nil {
		t.Fatal("unspecified listener was accepted")
	}
}

func TestDNSStreamRecordsFramingFailures(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		write  func(net.Conn)
		detail string
	}{
		{
			name: "truncated_length",
			write: func(conn net.Conn) {
				conn.Close()
			},
			detail: "truncated_length",
		},
		{
			name: "invalid_length_zero",
			write: func(conn net.Conn) {
				var size [2]byte
				_, _ = conn.Write(size[:])
				conn.Close()
			},
			detail: "invalid_length",
		},
		{
			name: "invalid_length_oversize",
			write: func(conn net.Conn) {
				var size [2]byte
				binary.BigEndian.PutUint16(size[:], 4097)
				_, _ = conn.Write(size[:])
				conn.Close()
			},
			detail: "invalid_length",
		},
		{
			name: "truncated_query",
			write: func(conn net.Conn) {
				var size [2]byte
				binary.BigEndian.PutUint16(size[:], 10)
				_, _ = conn.Write(size[:])
				_, _ = conn.Write([]byte{1, 2, 3})
				conn.Close()
			},
			detail: "truncated_query",
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config, path := testObserver(t)
			client, server := net.Pipe()
			done := make(chan error, 1)
			go func() {
				done <- config.handleDNSStreamConn(server)
			}()
			test.write(client)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			event := readLastEvidence(t, path)
			if event.Kind != "dns_query" || event.Transport != "tcp" ||
				event.Accepted || event.Detail != test.detail {
				t.Fatalf("evidence=%+v want detail=%q", event, test.detail)
			}
		})
	}
}

func TestDNSStreamAnswersValidTCPQuery(t *testing.T) {
	t.Parallel()
	config, path := testObserver(t)
	name := dnsmessage.MustNewName(
		"00112233445566778899aabbccddeeff.tcp.leak-v2.invalid.",
	)
	message := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 7, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
		}},
	}
	payload, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- config.handleDNSStreamConn(server)
	}()
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(payload)))
	if _, err := client.Write(append(size[:], payload...)); err != nil {
		t.Fatal(err)
	}
	var responseSize [2]byte
	if _, err := client.Read(responseSize[:]); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, binary.BigEndian.Uint16(responseSize[:]))
	if _, err := client.Read(response); err != nil {
		t.Fatal(err)
	}
	client.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var unpacked dnsmessage.Message
	if err := unpacked.Unpack(response); err != nil || len(unpacked.Answers) != 1 {
		t.Fatalf("response unpack=%v answers=%d", err, len(unpacked.Answers))
	}
	event := readLastEvidence(t, path)
	if !event.Accepted || event.Detail != "answered" {
		t.Fatalf("evidence=%+v", event)
	}
}

func TestHTTPHandlerMismatchEvidenceWriteFailureReturns500(t *testing.T) {
	t.Parallel()
	config, _ := testObserver(t)
	if err := config.writer.close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodGet,
		"http://observer/v2/canary?run_id=wrong&nonce=wrong",
		nil,
	)
	request.RemoteAddr = "198.51.100.7:45678"
	response := httptest.NewRecorder()
	config.httpHandler().ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func testObserver(t *testing.T) (observerConfig, string) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "events.jsonl")
	writer, err := newEvidenceWriter(path, "00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.close() })
	return observerConfig{
		runID:    "00112233445566778899aabbccddeeff",
		nonce:    "00112233445566778899aabbccddeeff",
		zone:     "leak-v2.invalid",
		answerV4: netip.MustParseAddr("203.0.113.99"),
		answerV6: netip.MustParseAddr("2001:db8::99"),
		writer:   writer,
	}, path
}

func readLastEvidence(t *testing.T, path string) evidenceEvent {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatal("evidence log is empty")
	}
	var event evidenceEvent
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &event); err != nil {
		t.Fatal(err)
	}
	return event
}
