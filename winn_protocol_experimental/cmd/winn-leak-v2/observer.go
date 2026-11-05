package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const stunMagicCookie uint32 = 0x2112a442

type evidenceEvent struct {
	Sequence  uint64 `json:"sequence"`
	At        string `json:"at"`
	RunID     string `json:"run_id"`
	Kind      string `json:"kind"`
	Transport string `json:"transport,omitempty"`
	PeerIP    string `json:"peer_ip,omitempty"`
	PeerPort  uint16 `json:"peer_port,omitempty"`
	QueryName string `json:"query_name,omitempty"`
	QueryType string `json:"query_type,omitempty"`
	Accepted  bool   `json:"accepted"`
	Detail    string `json:"detail,omitempty"`
}

type evidenceWriter struct {
	mu       sync.Mutex
	file     *os.File
	path     string
	encoder  *json.Encoder
	runID    string
	sequence uint64
}

func newEvidenceWriter(path, runID string) (*evidenceWriter, error) {
	file, err := openExclusivePrivateFile(path)
	if err != nil {
		return nil, fmt.Errorf("create observer evidence: %w", err)
	}
	return &evidenceWriter{
		file: file, path: path, encoder: json.NewEncoder(file), runID: runID,
	}, nil
}

func (writer *evidenceWriter) append(event evidenceEvent) error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	writer.sequence++
	event.Sequence = writer.sequence
	event.At = time.Now().UTC().Format(time.RFC3339Nano)
	event.RunID = writer.runID
	if err := writer.encoder.Encode(event); err != nil {
		return err
	}
	return writer.file.Sync()
}

func (writer *evidenceWriter) close() error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return errors.Join(writer.file.Sync(), writer.file.Close())
}

type observerConfig struct {
	runID      string
	nonce      string
	zone       string
	answerV4   netip.Addr
	answerV6   netip.Addr
	dnsListen  string
	httpListen []string
	stunListen []string
	readyFile  string
	writer     *evidenceWriter
}

type observerReady struct {
	Version     string   `json:"version"`
	RunID       string   `json:"run_id"`
	PID         int      `json:"pid"`
	DNSListen   string   `json:"dns_listen"`
	HTTPListen  []string `json:"http_listen"`
	STUNListen  []string `json:"stun_listen"`
	EvidenceLog string   `json:"evidence_log"`
}

func runObserver(args []string) error {
	flags := flag.NewFlagSet("observer", flag.ContinueOnError)
	runID := flags.String("run-id", "", "lowercase 32-hex run identifier")
	nonce := flags.String("nonce", "", "lowercase 32-hex per-run canary nonce")
	zone := flags.String("zone", "leak-v2.invalid", "controlled DNS suffix")
	dnsListen := flags.String("dns-listen", "", "IP-literal address:port for both UDP and TCP DNS")
	httpListen := flags.String("http-listen", "", "comma-separated IP-literal HTTP listen addresses")
	stunListen := flags.String("stun-listen", "", "comma-separated IP-literal UDP STUN listen addresses")
	answerV4 := flags.String("answer-v4", "", "controlled A answer")
	answerV6 := flags.String("answer-v6", "", "controlled AAAA answer")
	evidencePath := flags.String("evidence-log", "", "exclusive absolute JSONL evidence path")
	readyFile := flags.String("ready-file", "", "exclusive absolute readiness JSON path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !lowerHex(*runID, 16) || !lowerHex(*nonce, 16) {
		return errors.New("observer run-id and nonce must each be lowercase 32-hex")
	}
	if *dnsListen == "" || *evidencePath == "" || *readyFile == "" {
		return errors.New("observer dns-listen, evidence-log, and ready-file are required")
	}
	if err := validateZone(*zone); err != nil {
		return err
	}
	v4, err := netip.ParseAddr(*answerV4)
	if err != nil || !v4.Is4() || v4.IsUnspecified() {
		return errors.New("observer answer-v4 must be a usable IPv4 literal")
	}
	v6, err := netip.ParseAddr(*answerV6)
	if err != nil || !v6.Is6() || v6.IsUnspecified() {
		return errors.New("observer answer-v6 must be a usable IPv6 literal")
	}
	httpAddresses, err := parseListenList(*httpListen)
	if err != nil {
		return fmt.Errorf("observer HTTP listeners: %w", err)
	}
	stunAddresses, err := parseListenList(*stunListen)
	if err != nil {
		return fmt.Errorf("observer STUN listeners: %w", err)
	}
	if !filepath.IsAbs(*readyFile) {
		return errors.New("observer ready-file must be absolute")
	}
	writer, err := newEvidenceWriter(*evidencePath, *runID)
	if err != nil {
		return err
	}
	config := observerConfig{
		runID: *runID, nonce: *nonce, zone: strings.TrimSuffix(*zone, "."),
		answerV4: v4, answerV6: v6, dnsListen: *dnsListen,
		httpListen: httpAddresses, stunListen: stunAddresses,
		readyFile: *readyFile, writer: writer,
	}
	runErr := config.serve()
	return errors.Join(runErr, writer.close())
}

func (config observerConfig) serve() error {
	ctx, cancel := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
	defer cancel()

	dnsPacket, err := net.ListenPacket(networkFor(config.dnsListen, "udp"), config.dnsListen)
	if err != nil {
		return fmt.Errorf("listen DNS UDP: %w", err)
	}
	defer dnsPacket.Close()
	dnsStream, err := net.Listen(networkFor(config.dnsListen, "tcp"), config.dnsListen)
	if err != nil {
		return fmt.Errorf("listen DNS TCP: %w", err)
	}
	defer dnsStream.Close()

	var listeners []io.Closer
	var group sync.WaitGroup
	errs := make(chan error, 2+len(config.httpListen)+len(config.stunListen))
	start := func(run func() error) {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := run(); err != nil && !errors.Is(err, net.ErrClosed) &&
				!errors.Is(err, http.ErrServerClosed) {
				errs <- err
				cancel()
			}
		}()
	}
	start(func() error { return config.serveDNSPacket(dnsPacket) })
	start(func() error { return config.serveDNSStream(dnsStream) })

	for _, address := range config.httpListen {
		listener, listenErr := net.Listen(networkFor(address, "tcp"), address)
		if listenErr != nil {
			return fmt.Errorf("listen HTTP %s: %w", address, listenErr)
		}
		server := &http.Server{
			Handler:           config.httpHandler(),
			ReadHeaderTimeout: 3 * time.Second,
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      5 * time.Second,
			IdleTimeout:       10 * time.Second,
		}
		listeners = append(listeners, server)
		start(func() error { return server.Serve(listener) })
	}
	for _, address := range config.stunListen {
		packet, listenErr := net.ListenPacket(networkFor(address, "udp"), address)
		if listenErr != nil {
			return fmt.Errorf("listen STUN %s: %w", address, listenErr)
		}
		listeners = append(listeners, packet)
		start(func() error { return config.serveSTUN(packet) })
	}

	ready := observerReady{
		Version: "winn-leak-observer/v2", RunID: config.runID,
		PID: os.Getpid(), DNSListen: config.dnsListen,
		HTTPListen: config.httpListen, STUNListen: config.stunListen,
		EvidenceLog: config.writer.path,
	}
	if err := writeExclusiveJSON(config.readyFile, ready); err != nil {
		return fmt.Errorf("write observer readiness: %w", err)
	}
	if err := config.writer.append(evidenceEvent{
		Kind: "observer_ready", Accepted: true,
	}); err != nil {
		return err
	}

	<-ctx.Done()
	_ = dnsPacket.Close()
	_ = dnsStream.Close()
	for _, listener := range listeners {
		switch current := listener.(type) {
		case *http.Server:
			shutdownCtx, shutdownCancel := context.WithTimeout(
				context.Background(), 3*time.Second,
			)
			_ = current.Shutdown(shutdownCtx)
			shutdownCancel()
		default:
			_ = current.Close()
		}
	}
	group.Wait()
	close(errs)
	return errors.Join(channelErrors(errs)...)
}

func (config observerConfig) serveDNSPacket(connection net.PacketConn) error {
	buffer := make([]byte, 4096)
	for {
		count, peer, err := connection.ReadFrom(buffer)
		if err != nil {
			return err
		}
		response, event, accepted := config.dnsResponse(buffer[:count], "udp")
		ip, port := splitPeer(peer)
		event.PeerIP, event.PeerPort = ip, port
		event.Accepted = accepted
		if err := config.writer.append(event); err != nil {
			return err
		}
		if len(response) != 0 {
			if _, err := connection.WriteTo(response, peer); err != nil {
				return err
			}
		}
	}
}

func (config observerConfig) serveDNSStream(listener net.Listener) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			_ = config.handleDNSStreamConn(connection)
		}()
	}
}

// handleDNSStreamConn records every TCP DNS framing outcome in the evidence
// log. A silent close here is indistinguishable from a censor dropping the
// path, so truncated or oversized frames are logged as rejected queries
// rather than discarded.
func (config observerConfig) handleDNSStreamConn(connection net.Conn) error {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(connection)
	ip, port := splitPeer(connection.RemoteAddr())
	reject := func(detail string) error {
		return config.writer.append(evidenceEvent{
			Kind: "dns_query", Transport: "tcp",
			PeerIP: ip, PeerPort: port, Accepted: false, Detail: detail,
		})
	}
	var sizeBytes [2]byte
	if _, err := io.ReadFull(reader, sizeBytes[:]); err != nil {
		return reject("truncated_length")
	}
	size := int(binary.BigEndian.Uint16(sizeBytes[:]))
	if size == 0 || size > 4096 {
		return reject("invalid_length")
	}
	query := make([]byte, size)
	if _, err := io.ReadFull(reader, query); err != nil {
		return reject("truncated_query")
	}
	response, event, accepted := config.dnsResponse(query, "tcp")
	event.PeerIP, event.PeerPort = ip, port
	event.Accepted = accepted
	if err := config.writer.append(event); err != nil {
		return err
	}
	if len(response) == 0 {
		return nil
	}
	responseLength, ok := exactUint16Length(response)
	if !ok {
		return nil
	}
	var responseSize [2]byte
	binary.BigEndian.PutUint16(responseSize[:], responseLength)
	_, err := connection.Write(append(responseSize[:], response...))
	return err
}

func exactUint16Length(value []byte) (uint16, bool) {
	if len(value) > 65535 {
		return 0, false
	}
	var result uint16
	for range value {
		result++
	}
	return result, true
}

func (config observerConfig) dnsResponse(
	queryBytes []byte,
	transport string,
) ([]byte, evidenceEvent, bool) {
	event := evidenceEvent{Kind: "dns_query", Transport: transport}
	var query dnsmessage.Message
	if err := query.Unpack(queryBytes); err != nil || query.Header.Response ||
		len(query.Questions) != 1 {
		event.Detail = "malformed"
		return nil, event, false
	}
	question := query.Questions[0]
	name := strings.ToLower(question.Name.String())
	event.QueryName = name
	event.QueryType = question.Type.String()
	udpName := config.nonce + ".udp." + config.zone + "."
	tcpName := config.nonce + ".tcp." + config.zone + "."
	if name != udpName && name != tcpName {
		event.Detail = "wrong_name"
		return nil, event, false
	}
	if question.Class != dnsmessage.ClassINET ||
		(question.Type != dnsmessage.TypeA && question.Type != dnsmessage.TypeAAAA) {
		event.Detail = "wrong_question"
		return nil, event, false
	}
	if name == tcpName && transport == "udp" {
		response := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID: query.ID, Response: true, Truncated: true,
			},
			Questions: query.Questions,
		}
		payload, err := response.Pack()
		if err != nil {
			event.Detail = "pack_error"
			return nil, event, false
		}
		event.Detail = "force_tcp"
		return payload, event, true
	}
	if name == udpName && transport == "tcp" {
		event.Detail = "unexpected_transport"
		return nil, event, false
	}
	header := dnsmessage.ResourceHeader{
		Name: question.Name, Type: question.Type,
		Class: dnsmessage.ClassINET, TTL: 5,
	}
	var body dnsmessage.ResourceBody
	if question.Type == dnsmessage.TypeA {
		body = &dnsmessage.AResource{A: config.answerV4.As4()}
	} else {
		body = &dnsmessage.AAAAResource{AAAA: config.answerV6.As16()}
	}
	response := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: query.ID, Response: true},
		Questions: query.Questions,
		Answers:   []dnsmessage.Resource{{Header: header, Body: body}},
	}
	payload, err := response.Pack()
	if err != nil {
		event.Detail = "pack_error"
		return nil, event, false
	}
	event.Detail = "answered"
	return payload, event, true
}

func (config observerConfig) httpHandler() http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		peerIP, peerPort := splitPeerString(request.RemoteAddr)
		accepted := request.Method == http.MethodGet &&
			request.URL.Path == "/v2/canary" &&
			request.URL.Query().Get("run_id") == config.runID &&
			request.URL.Query().Get("nonce") == config.nonce
		event := evidenceEvent{
			Kind: "http_canary", Transport: "tcp",
			PeerIP: peerIP, PeerPort: peerPort, Accepted: accepted,
		}
		if !accepted {
			event.Detail = "request_mismatch"
			if err := config.writer.append(event); err != nil {
				http.Error(response, "evidence failure", http.StatusInternalServerError)
				return
			}
			http.Error(response, "not found", http.StatusNotFound)
			return
		}
		event.Detail = "observed"
		if err := config.writer.append(event); err != nil {
			http.Error(response, "evidence failure", http.StatusInternalServerError)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(response).Encode(map[string]any{
			"version": "winn-leak-http/v2",
			"run_id":  config.runID,
			"nonce":   config.nonce,
			"peer_ip": peerIP,
		})
	})
}

func (config observerConfig) serveSTUN(connection net.PacketConn) error {
	buffer := make([]byte, 2048)
	for {
		count, peer, err := connection.ReadFrom(buffer)
		if err != nil {
			return err
		}
		response, ok := stunBindingResponse(buffer[:count], peer)
		ip, port := splitPeer(peer)
		event := evidenceEvent{
			Kind: "stun_binding", Transport: "udp",
			PeerIP: ip, PeerPort: port, Accepted: ok,
		}
		if ok {
			event.Detail = "observed"
		} else {
			event.Detail = "malformed"
		}
		if err := config.writer.append(event); err != nil {
			return err
		}
		if ok {
			if _, err := connection.WriteTo(response, peer); err != nil {
				return err
			}
		}
	}
}

func stunBindingResponse(request []byte, peer net.Addr) ([]byte, bool) {
	if len(request) < 20 || binary.BigEndian.Uint16(request[0:2]) != 0x0001 ||
		binary.BigEndian.Uint32(request[4:8]) != stunMagicCookie {
		return nil, false
	}
	declared := int(binary.BigEndian.Uint16(request[2:4]))
	if declared%4 != 0 || declared > len(request)-20 {
		return nil, false
	}
	address, ok := peer.(*net.UDPAddr)
	if !ok || address.Port <= 0 || address.Port > 65535 {
		return nil, false
	}
	port := uint16(address.Port)
	ip, ok := netip.AddrFromSlice(address.IP)
	if !ok {
		return nil, false
	}
	ip = ip.Unmap()
	var attribute []byte
	if ip.Is4() {
		attribute = make([]byte, 12)
		binary.BigEndian.PutUint16(attribute[0:2], 0x0020)
		binary.BigEndian.PutUint16(attribute[2:4], 8)
		attribute[5] = 0x01
		binary.BigEndian.PutUint16(
			attribute[6:8], port^uint16(stunMagicCookie>>16),
		)
		raw := ip.As4()
		cookie := [4]byte{0x21, 0x12, 0xa4, 0x42}
		for index := range raw {
			attribute[8+index] = raw[index] ^ cookie[index]
		}
	} else {
		attribute = make([]byte, 24)
		binary.BigEndian.PutUint16(attribute[0:2], 0x0020)
		binary.BigEndian.PutUint16(attribute[2:4], 20)
		attribute[5] = 0x02
		binary.BigEndian.PutUint16(
			attribute[6:8], port^uint16(stunMagicCookie>>16),
		)
		raw := ip.As16()
		var mask [16]byte
		binary.BigEndian.PutUint32(mask[0:4], stunMagicCookie)
		copy(mask[4:], request[8:20])
		for index := range raw {
			attribute[8+index] = raw[index] ^ mask[index]
		}
	}
	response := make([]byte, 20+len(attribute))
	binary.BigEndian.PutUint16(response[0:2], 0x0101)
	if ip.Is4() {
		binary.BigEndian.PutUint16(response[2:4], 12)
	} else {
		binary.BigEndian.PutUint16(response[2:4], 24)
	}
	binary.BigEndian.PutUint32(response[4:8], stunMagicCookie)
	copy(response[8:20], request[8:20])
	copy(response[20:], attribute)
	return response, true
}

func validateZone(value string) error {
	value = strings.TrimSuffix(strings.ToLower(value), ".")
	if value == "" || len(value) > 200 {
		return errors.New("observer DNS zone is invalid")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 {
			return errors.New("observer DNS zone is invalid")
		}
		for index, character := range label {
			if (character >= 'a' && character <= 'z') ||
				(character >= '0' && character <= '9') ||
				(character == '-' && index > 0 && index < len(label)-1) {
				continue
			}
			return errors.New("observer DNS zone is invalid")
		}
	}
	return nil
}

func parseListenList(value string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		address, err := netip.ParseAddrPort(part)
		if err != nil || address.Port() == 0 || address.Addr().IsUnspecified() {
			return nil, fmt.Errorf("%q is not a usable IP-literal listener", part)
		}
		if _, duplicate := seen[part]; duplicate {
			return nil, fmt.Errorf("%q is duplicated", part)
		}
		seen[part] = struct{}{}
		result = append(result, part)
	}
	return result, nil
}

func networkFor(address, base string) string {
	parsed, err := netip.ParseAddrPort(address)
	if err == nil && parsed.Addr().Is6() {
		return base + "6"
	}
	return base + "4"
}

func splitPeer(peer net.Addr) (string, uint16) {
	return splitPeerString(peer.String())
}

func splitPeerString(value string) (string, uint16) {
	address, err := netip.ParseAddrPort(value)
	if err != nil {
		return "", 0
	}
	return address.Addr().Unmap().String(), address.Port()
}

func writeExclusiveJSON(path string, value any) error {
	directory := filepath.Dir(path)
	temp, err := os.CreateTemp(directory, ".winn-leak-ready-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	_ = os.Chmod(tempName, 0o600)
	defer os.Remove(tempName)
	encoder := json.NewEncoder(temp)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		if err == nil {
			return os.ErrExist
		}
		return err
	}
	return os.Rename(tempName, path)
}

func channelErrors(channel <-chan error) []error {
	var result []error
	for err := range channel {
		result = append(result, err)
	}
	return result
}

func lowerHex(value string, bytes int) bool {
	if len(value) != bytes*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == bytes
}
