// Command winn-leak-netprobe-v2 performs real, bounded network probes for the
// external acceptance hook. It has no synthetic-success path: success requires
// a valid response from the configured IP-literal endpoint, while blocked
// requires the operation to fail before any valid response is received.
package main

import (
	"context"
	"crypto/rand"
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
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const stunCookie uint32 = 0x2112a442

type config struct {
	operation      string
	expect         string
	endpoint       netip.AddrPort
	timeout        time.Duration
	runID          string
	nonce          string
	query          string
	queryType      dnsmessage.Type
	expectedAnswer netip.Addr
	expectedPeer   netip.Addr
	payload        []byte
	bindInterface  string
}

type result struct {
	Version   string `json:"version"`
	At        string `json:"at"`
	Operation string `json:"operation"`
	Expect    string `json:"expect"`
	Endpoint  string `json:"endpoint"`
	Blocked   bool   `json:"blocked"`
	Detail    string `json:"detail"`
}

type reachedEndpointError struct {
	err error
}

func (current *reachedEndpointError) Error() string {
	return "endpoint was reachable but response validation failed: " + current.err.Error()
}

func (current *reachedEndpointError) Unwrap() error { return current.err }

func reached(err error) error {
	if err == nil {
		return nil
	}
	return &reachedEndpointError{err: err}
}

func main() {
	cfg, err := parseConfig(os.Args[1:])
	if err != nil {
		fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()
	detail, probeErr := run(ctx, cfg)
	output := result{
		Version:   "winn-leak-netprobe/v2",
		At:        time.Now().UTC().Format(time.RFC3339Nano),
		Operation: cfg.operation, Expect: cfg.expect,
		Endpoint: cfg.endpoint.String(), Detail: detail,
	}
	switch cfg.expect {
	case "success":
		if probeErr != nil {
			fatal(probeErr)
		}
	case "blocked":
		if probeErr == nil {
			fatal(errors.New("probe unexpectedly received a valid response"))
		}
		var reachable *reachedEndpointError
		if errors.As(probeErr, &reachable) {
			fatal(reachable)
		}
		output.Blocked = true
		output.Detail = probeErr.Error()
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(output); err != nil {
		fatal(err)
	}
}

func parseConfig(args []string) (config, error) {
	var cfg config
	flags := flag.NewFlagSet("winn-leak-netprobe-v2", flag.ContinueOnError)
	operation := flags.String("operation", "", "http, dns-udp, dns-tcp, udp-echo, or stun")
	expect := flags.String("expect", "", "success or blocked")
	endpoint := flags.String("endpoint", "", "IP-literal address:port")
	timeout := flags.Duration("timeout", 2*time.Second, "strict probe timeout")
	runID := flags.String("run-id", "", "HTTP run binding")
	nonce := flags.String("nonce", "", "HTTP nonce")
	query := flags.String("query", "", "absolute DNS query name")
	queryType := flags.String("query-type", "", "A or AAAA")
	expectedAnswer := flags.String("expected-answer", "", "expected DNS answer")
	expectedPeer := flags.String("expected-peer", "", "expected HTTP/STUN source reflection")
	payload := flags.String("payload", "", "UDP echo payload")
	bindInterface := flags.String("bind-interface", "", "optional exact source interface")
	if err := flags.Parse(args); err != nil {
		return cfg, err
	}
	if flags.NArg() != 0 {
		return cfg, errors.New("positional arguments are forbidden")
	}
	cfg.operation, cfg.expect, cfg.timeout = *operation, *expect, *timeout
	cfg.bindInterface = *bindInterface
	if cfg.bindInterface != "" {
		if len(cfg.bindInterface) > 15 || cfg.bindInterface[0] == '-' ||
			strings.ContainsAny(cfg.bindInterface, "\x00\r\n /") {
			return cfg, errors.New("bind-interface is invalid")
		}
	}
	if cfg.expect != "success" && cfg.expect != "blocked" {
		return cfg, errors.New("expect must be success or blocked")
	}
	if cfg.timeout < 100*time.Millisecond || cfg.timeout > 10*time.Second {
		return cfg, errors.New("timeout must be 100ms..10s")
	}
	address, err := netip.ParseAddrPort(*endpoint)
	if err != nil || address.Addr().IsUnspecified() || address.Port() == 0 {
		return cfg, errors.New("endpoint must be a usable IP-literal address:port")
	}
	cfg.endpoint = address
	switch cfg.operation {
	case "http":
		if !lowerHex(*runID, 16) || !lowerHex(*nonce, 16) {
			return cfg, errors.New("HTTP run-id and nonce must be lowercase 32-hex")
		}
		cfg.runID, cfg.nonce = *runID, *nonce
		cfg.expectedPeer, err = requiredAddress(*expectedPeer, address.Addr().Is4())
	case "dns-udp", "dns-tcp":
		if err = validateDNSName(*query); err != nil {
			return cfg, err
		}
		cfg.query = strings.ToLower(*query)
		switch *queryType {
		case "A":
			cfg.queryType = dnsmessage.TypeA
		case "AAAA":
			cfg.queryType = dnsmessage.TypeAAAA
		default:
			return cfg, errors.New("query-type must be A or AAAA")
		}
		cfg.expectedAnswer, err = requiredAddress(*expectedAnswer, cfg.queryType == dnsmessage.TypeA)
	case "udp-echo":
		if len(*payload) < 16 || len(*payload) > 512 ||
			strings.ContainsAny(*payload, "\x00\r\n") {
			return cfg, errors.New("UDP echo payload must be 16..512 safe bytes")
		}
		cfg.payload = []byte(*payload)
	case "stun":
		cfg.expectedPeer, err = requiredAddress(*expectedPeer, address.Addr().Is4())
	default:
		return cfg, errors.New("operation is not recognized")
	}
	if err != nil {
		return cfg, err
	}
	return cfg, nil
}

func requiredAddress(raw string, wantV4 bool) (netip.Addr, error) {
	address, err := netip.ParseAddr(raw)
	if err != nil || address.IsUnspecified() || address.Is4() != wantV4 {
		return netip.Addr{}, errors.New("expected address is invalid or has the wrong family")
	}
	return address.Unmap(), nil
}

func validateDNSName(raw string) error {
	if raw == "" || !strings.HasSuffix(raw, ".") || len(raw) > 253 {
		return errors.New("DNS query must be a bounded absolute name")
	}
	for _, label := range strings.Split(strings.TrimSuffix(raw, "."), ".") {
		if label == "" || len(label) > 63 {
			return errors.New("DNS query contains an invalid label")
		}
		for _, current := range label {
			if (current < 'a' || current > 'z') &&
				(current < 'A' || current > 'Z') &&
				(current < '0' || current > '9') &&
				current != '-' {
				return errors.New("DNS query contains an invalid character")
			}
		}
	}
	return nil
}

func run(ctx context.Context, cfg config) (string, error) {
	switch cfg.operation {
	case "http":
		return probeHTTP(ctx, cfg)
	case "dns-udp":
		return probeDNS(ctx, cfg, "udp")
	case "dns-tcp":
		return probeDNS(ctx, cfg, "tcp")
	case "udp-echo":
		return probeUDPEcho(ctx, cfg)
	case "stun":
		return probeSTUN(ctx, cfg)
	default:
		panic("validated operation is missing")
	}
}

func network(prefix string, address netip.Addr) string {
	if address.Is4() {
		return prefix + "4"
	}
	return prefix + "6"
}

func probeDialer(cfg config) (*net.Dialer, error) {
	dialer := &net.Dialer{}
	control, err := bindControl(cfg.bindInterface)
	if err != nil {
		return nil, err
	}
	dialer.Control = control
	return dialer, nil
}

func probeHTTP(ctx context.Context, cfg config) (string, error) {
	target := url.URL{
		Scheme: "http",
		Host:   cfg.endpoint.String(),
		Path:   "/v2/canary",
	}
	query := target.Query()
	query.Set("run_id", cfg.runID)
	query.Set("nonce", cfg.nonce)
	target.RawQuery = query.Encode()
	dialer, err := probeDialer(cfg)
	if err != nil {
		return "", err
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network("tcp", cfg.endpoint.Addr()), cfg.endpoint.String())
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects are forbidden")
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil {
		return "", reached(err)
	}
	if response.StatusCode != http.StatusOK || len(body) > 4096 {
		return "", reached(errors.New("HTTP response was not a bounded 200"))
	}
	var decoded struct {
		Version string `json:"version"`
		RunID   string `json:"run_id"`
		Nonce   string `json:"nonce"`
		PeerIP  string `json:"peer_ip"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", reached(err)
	}
	peer, err := netip.ParseAddr(decoded.PeerIP)
	if err != nil || decoded.Version != "winn-leak-http/v2" ||
		decoded.RunID != cfg.runID || decoded.Nonce != cfg.nonce ||
		peer.Unmap() != cfg.expectedPeer {
		return "", reached(errors.New("HTTP reflection did not match the expected gateway egress"))
	}
	return "valid controlled HTTP reflection", nil
}

func dnsQuery(cfg config) ([]byte, error) {
	name, err := dnsmessage.NewName(cfg.query)
	if err != nil {
		return nil, err
	}
	idBytes := make([]byte, 2)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	message := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               binary.BigEndian.Uint16(idBytes),
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{{
			Name: name, Type: cfg.queryType, Class: dnsmessage.ClassINET,
		}},
	}
	return message.Pack()
}

func probeDNS(ctx context.Context, cfg config, transport string) (string, error) {
	query, err := dnsQuery(cfg)
	if err != nil {
		return "", err
	}
	dialer, err := probeDialer(cfg)
	if err != nil {
		return "", err
	}
	connection, err := dialer.DialContext(
		ctx, network(transport, cfg.endpoint.Addr()), cfg.endpoint.String(),
	)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	deadline, ok := ctx.Deadline()
	if ok {
		_ = connection.SetDeadline(deadline)
	}
	if transport == "tcp" {
		if len(query) > 65535 {
			return "", errors.New("DNS query is too large")
		}
		frame := make([]byte, 2+len(query))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(query))) // #nosec G115 -- bounded above.
		copy(frame[2:], query)
		if _, err := connection.Write(frame); err != nil {
			return "", reached(err)
		}
		var length [2]byte
		if _, err := io.ReadFull(connection, length[:]); err != nil {
			return "", reached(err)
		}
		size := int(binary.BigEndian.Uint16(length[:]))
		if size == 0 || size > 4096 {
			return "", reached(errors.New("DNS TCP response length is invalid"))
		}
		response := make([]byte, size)
		if _, err := io.ReadFull(connection, response); err != nil {
			return "", reached(err)
		}
		detail, validateErr := validateDNSResponse(cfg, response)
		return detail, reached(validateErr)
	}
	if _, err := connection.Write(query); err != nil {
		return "", err
	}
	response := make([]byte, 4096)
	count, err := connection.Read(response)
	if err != nil {
		return "", err
	}
	detail, validateErr := validateDNSResponse(cfg, response[:count])
	return detail, reached(validateErr)
}

func validateDNSResponse(cfg config, payload []byte) (string, error) {
	var response dnsmessage.Message
	if err := response.Unpack(payload); err != nil {
		return "", err
	}
	if !response.Header.Response || len(response.Answers) == 0 {
		return "", errors.New("DNS response omitted an answer")
	}
	for _, answer := range response.Answers {
		switch body := answer.Body.(type) {
		case *dnsmessage.AResource:
			if netip.AddrFrom4(body.A).Unmap() == cfg.expectedAnswer {
				return "valid controlled DNS answer", nil
			}
		case *dnsmessage.AAAAResource:
			if netip.AddrFrom16(body.AAAA).Unmap() == cfg.expectedAnswer {
				return "valid controlled DNS answer", nil
			}
		}
	}
	return "", errors.New("DNS response omitted the expected address")
}

func probeUDPEcho(ctx context.Context, cfg config) (string, error) {
	dialer, err := probeDialer(cfg)
	if err != nil {
		return "", err
	}
	connection, err := dialer.DialContext(
		ctx, network("udp", cfg.endpoint.Addr()), cfg.endpoint.String(),
	)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if _, err := connection.Write(cfg.payload); err != nil {
		return "", err
	}
	response := make([]byte, len(cfg.payload)+1)
	count, err := connection.Read(response)
	if err != nil {
		return "", err
	}
	if string(response[:count]) != string(cfg.payload) {
		return "", reached(errors.New("UDP echo response mismatch"))
	}
	return "valid controlled UDP echo", nil
}

func probeSTUN(ctx context.Context, cfg config) (string, error) {
	transaction := make([]byte, 12)
	if _, err := rand.Read(transaction); err != nil {
		return "", err
	}
	request := make([]byte, 20)
	binary.BigEndian.PutUint16(request[0:2], 0x0001)
	binary.BigEndian.PutUint32(request[4:8], stunCookie)
	copy(request[8:], transaction)
	dialer, err := probeDialer(cfg)
	if err != nil {
		return "", err
	}
	connection, err := dialer.DialContext(
		ctx, network("udp", cfg.endpoint.Addr()), cfg.endpoint.String(),
	)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if _, err := connection.Write(request); err != nil {
		return "", err
	}
	response := make([]byte, 2048)
	count, err := connection.Read(response)
	if err != nil {
		return "", err
	}
	mapped, err := parseSTUN(response[:count], transaction)
	if err != nil {
		return "", reached(err)
	}
	if mapped.Addr().Unmap() != cfg.expectedPeer {
		return "", reached(errors.New("STUN reflection did not match the expected gateway egress"))
	}
	return "valid controlled STUN reflection", nil
}

func parseSTUN(response, transaction []byte) (netip.AddrPort, error) {
	if len(response) < 20 || binary.BigEndian.Uint16(response[0:2]) != 0x0101 ||
		binary.BigEndian.Uint32(response[4:8]) != stunCookie ||
		!equal(response[8:20], transaction) {
		return netip.AddrPort{}, errors.New("STUN response header is invalid")
	}
	length := int(binary.BigEndian.Uint16(response[2:4]))
	if length > len(response)-20 {
		return netip.AddrPort{}, errors.New("STUN response length is invalid")
	}
	for attributes := response[20 : 20+length]; len(attributes) >= 4; {
		kind := binary.BigEndian.Uint16(attributes[:2])
		size := int(binary.BigEndian.Uint16(attributes[2:4]))
		if size > len(attributes)-4 {
			return netip.AddrPort{}, errors.New("STUN attribute length is invalid")
		}
		value := attributes[4 : 4+size]
		if kind == 0x0020 {
			return decodeXORMapped(value, transaction)
		}
		padded := (size + 3) &^ 3
		if padded > len(attributes)-4 {
			return netip.AddrPort{}, errors.New("STUN padding is invalid")
		}
		attributes = attributes[4+padded:]
	}
	return netip.AddrPort{}, errors.New("STUN response omitted XOR-MAPPED-ADDRESS")
}

func decodeXORMapped(value, transaction []byte) (netip.AddrPort, error) {
	if len(value) < 8 {
		return netip.AddrPort{}, errors.New("STUN mapped address is truncated")
	}
	port := binary.BigEndian.Uint16(value[2:4]) ^ uint16(stunCookie>>16)
	switch value[1] {
	case 0x01:
		var bytes [4]byte
		cookie := make([]byte, 4)
		binary.BigEndian.PutUint32(cookie, stunCookie)
		for index := range bytes {
			bytes[index] = value[4+index] ^ cookie[index]
		}
		return netip.AddrPortFrom(netip.AddrFrom4(bytes), port), nil
	case 0x02:
		if len(value) < 20 {
			return netip.AddrPort{}, errors.New("STUN IPv6 address is truncated")
		}
		mask := make([]byte, 16)
		binary.BigEndian.PutUint32(mask[:4], stunCookie)
		copy(mask[4:], transaction)
		var bytes [16]byte
		for index := range bytes {
			bytes[index] = value[4+index] ^ mask[index]
		}
		return netip.AddrPortFrom(netip.AddrFrom16(bytes), port), nil
	default:
		return netip.AddrPort{}, errors.New("STUN mapped family is invalid")
	}
}

func equal(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

func lowerHex(value string, bytes int) bool {
	if len(value) != bytes*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == bytes
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
