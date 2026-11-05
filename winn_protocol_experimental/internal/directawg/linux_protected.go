package directawg

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"winsvpn.local/winnprotocol/internal/connectivity"
)

const (
	defaultLinuxProbeTimeout     = 3 * time.Second
	linuxProbeRetransmitInterval = 200 * time.Millisecond
	linuxInterfaceNameMax        = 15
)

// LinuxProtectedUDPDialerConfig is local trusted state. InterfaceName names the
// physical underlay selected by the platform route monitor; FirewallMark is a
// privileged, process-owned bypass mark admitted by the nftables policy.
type LinuxProtectedUDPDialerConfig struct {
	InterfaceName string
	FirewallMark  uint32
}

type linuxSocketSetter interface {
	Set(uintptr, string, uint32) error
}

type linuxProtectedUDPDialer struct {
	config LinuxProtectedUDPDialerConfig
	setter linuxSocketSetter
}

// NewLinuxProtectedUDPDialer returns a raw AWG socket dialer which cannot move
// onto a VPN route: Linux binds it to the selected underlay and applies the
// policy-owned bypass mark before connect(2).
func NewLinuxProtectedUDPDialer(
	config LinuxProtectedUDPDialerConfig,
) (RemoteDialer, error) {
	if err := validateLinuxProtectedSocket(
		config.InterfaceName, config.FirewallMark,
	); err != nil {
		return nil, err
	}
	return &linuxProtectedUDPDialer{
		config: config,
		setter: linuxPlatformSocketSetter(),
	}, nil
}

func (dialer *linuxProtectedUDPDialer) Dial(
	ctx context.Context,
	endpoint string,
) (net.PacketConn, error) {
	if ctx == nil {
		return nil, errors.New("protected UDP dial context is required")
	}
	if err := validateIPLiteralEndpoint(endpoint, false); err != nil {
		return nil, err
	}
	connection, err := dialLinuxProtected(
		ctx, udpNetwork(endpoint), endpoint,
		dialer.config.InterfaceName,
		dialer.config.FirewallMark,
		dialer.setter,
	)
	if err != nil {
		return nil, err
	}
	udp, ok := connection.(*net.UDPConn)
	if !ok {
		_ = connection.Close()
		return nil, errors.New(
			"protected UDP dial did not return a UDP socket",
		)
	}
	remote, err := net.ResolveUDPAddr(udpNetwork(endpoint), endpoint)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	return &connectedPacketConn{UDPConn: udp, remote: remote}, nil
}

func dialLinuxProtected(
	ctx context.Context,
	network string,
	endpoint string,
	interfaceName string,
	firewallMark uint32,
	setter linuxSocketSetter,
) (net.Conn, error) {
	if setter == nil {
		return nil, errors.New("linux socket setter is required")
	}
	var controlError error
	dialer := net.Dialer{
		Control: func(_, _ string, raw syscall.RawConn) error {
			err := raw.Control(func(fd uintptr) {
				controlError = setter.Set(
					fd, interfaceName, firewallMark,
				)
			})
			if err != nil {
				return err
			}
			return controlError
		},
	}
	connection, err := dialer.DialContext(ctx, network, endpoint)
	if err != nil {
		return nil, fmt.Errorf("dial protected Linux socket: %w", err)
	}
	return connection, nil
}

// LinuxVerificationConfig is copied from a verified deployment profile. Both
// endpoints are IP literals, so verification never invokes the host resolver.
// ExpectedDNSAnswers binds the DNS response to the signed canary address.
type LinuxVerificationConfig struct {
	DNSResolver        string
	DNSQueryName       string
	ExpectedDNSAnswers []netip.Addr
	CanaryEndpoint     string
	Timeout            time.Duration
}

type linuxProtectedConnDialer interface {
	Dial(
		context.Context,
		string,
		string,
		string,
		uint32,
	) (net.Conn, error)
}

type linuxNetProtectedConnDialer struct {
	setter linuxSocketSetter
}

func (dialer linuxNetProtectedConnDialer) Dial(
	ctx context.Context,
	network string,
	endpoint string,
	interfaceName string,
	firewallMark uint32,
) (net.Conn, error) {
	return dialLinuxProtected(
		ctx, network, endpoint, interfaceName, firewallMark, dialer.setter,
	)
}

type linuxProtectedVerifier struct {
	config LinuxVerificationConfig
	dialer linuxProtectedConnDialer
}

// NewLinuxProtectedVerifier constructs the production candidate verifier.
func NewLinuxProtectedVerifier(
	config LinuxVerificationConfig,
) (LinuxProtectedVerifier, error) {
	if err := validateLinuxVerificationConfig(config); err != nil {
		return nil, err
	}
	if config.Timeout == 0 {
		config.Timeout = defaultLinuxProbeTimeout
	}
	config.ExpectedDNSAnswers = slices.Clone(config.ExpectedDNSAnswers)
	return &linuxProtectedVerifier{
		config: config,
		dialer: linuxNetProtectedConnDialer{
			setter: linuxPlatformSocketSetter(),
		},
	}, nil
}

func (verifier *linuxProtectedVerifier) VerifyProtectedDNS(
	ctx context.Context,
	probe LinuxProbeContext,
) error {
	if err := validateLinuxProbeContext(probe); err != nil {
		return err
	}
	resolver, err := parseIPLiteralAddrPort(verifier.config.DNSResolver)
	if err != nil {
		return err
	}
	if !linuxProbeRouteContains(
		probe.VerificationRoutes, resolver.Addr(),
	) {
		return errors.New(
			"protected DNS resolver is outside signed verification routes",
		)
	}
	queryType := dnsmessage.TypeA
	if verifier.config.ExpectedDNSAnswers[0].Is6() {
		queryType = dnsmessage.TypeAAAA
	}
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return fmt.Errorf("generate protected DNS query ID: %w", err)
	}
	id := uint16(idBytes[0])<<8 | uint16(idBytes[1])
	name, err := dnsmessage.NewName(
		strings.TrimSuffix(verifier.config.DNSQueryName, ".") + ".",
	)
	if err != nil {
		return fmt.Errorf("encode protected DNS name: %w", err)
	}
	query := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               id,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{{
			Name: name, Type: queryType, Class: dnsmessage.ClassINET,
		}},
	}
	payload, err := query.Pack()
	if err != nil {
		return fmt.Errorf("pack protected DNS query: %w", err)
	}
	probeContext, cancel := verifier.probeContext(ctx)
	defer cancel()
	connection, err := verifier.dialer.Dial(
		probeContext,
		udpNetwork(verifier.config.DNSResolver),
		verifier.config.DNSResolver,
		probe.InterfaceName,
		probe.FirewallMark,
	)
	if err != nil {
		return fmt.Errorf("open protected DNS socket: %w", err)
	}
	stopClose := context.AfterFunc(probeContext, func() {
		_ = connection.Close()
	})
	defer func() {
		stopClose()
		_ = connection.Close()
	}()
	responseBytes := make([]byte, 4096)
	count, err := exchangeLinuxProtectedUDP(
		probeContext,
		connection,
		payload,
		responseBytes,
		"protected DNS",
	)
	if err != nil {
		return err
	}
	var response dnsmessage.Message
	if err := response.Unpack(responseBytes[:count]); err != nil {
		return fmt.Errorf("unpack protected DNS response: %w", err)
	}
	if !response.Response || response.ID != id || response.Truncated ||
		response.RCode != dnsmessage.RCodeSuccess ||
		len(response.Questions) != 1 ||
		response.Questions[0].Name != name ||
		response.Questions[0].Type != queryType ||
		response.Questions[0].Class != dnsmessage.ClassINET {
		return errors.New("protected DNS response failed strict validation")
	}
	for _, answer := range response.Answers {
		var address netip.Addr
		switch body := answer.Body.(type) {
		case *dnsmessage.AResource:
			address = netip.AddrFrom4(body.A)
		case *dnsmessage.AAAAResource:
			address = netip.AddrFrom16(body.AAAA)
		default:
			continue
		}
		if slices.Contains(verifier.config.ExpectedDNSAnswers, address) {
			return nil
		}
	}
	return errors.New(
		"protected DNS response omitted every signed expected address",
	)
}

func (verifier *linuxProtectedVerifier) VerifyTunnelCanary(
	ctx context.Context,
	probe LinuxProbeContext,
) error {
	if err := validateLinuxProbeContext(probe); err != nil {
		return err
	}
	canary, err := parseIPLiteralAddrPort(verifier.config.CanaryEndpoint)
	if err != nil {
		return err
	}
	if !linuxProbeRouteContains(
		probe.VerificationRoutes, canary.Addr(),
	) {
		return errors.New(
			"tunnel canary is outside signed verification routes",
		)
	}
	challenge, err := linuxCanaryChallenge(probe.Binding)
	if err != nil {
		return fmt.Errorf("generate tunnel canary challenge: %w", err)
	}
	defer clear(challenge)
	probeContext, cancel := verifier.probeContext(ctx)
	defer cancel()
	connection, err := verifier.dialer.Dial(
		probeContext,
		udpNetwork(verifier.config.CanaryEndpoint),
		verifier.config.CanaryEndpoint,
		probe.InterfaceName,
		probe.FirewallMark,
	)
	if err != nil {
		return fmt.Errorf("open protected canary socket: %w", err)
	}
	stopClose := context.AfterFunc(probeContext, func() {
		_ = connection.Close()
	})
	defer func() {
		stopClose()
		_ = connection.Close()
	}()
	response := make([]byte, len(challenge)+1)
	count, err := exchangeLinuxProtectedUDP(
		probeContext,
		connection,
		challenge,
		response,
		"tunnel canary",
	)
	if err != nil {
		return err
	}
	if count != len(challenge) ||
		!slices.Equal(response[:count], challenge) {
		return errors.New("tunnel canary response did not echo challenge")
	}
	return nil
}

// exchangeLinuxProtectedUDP repeats one authenticated UDP request while
// retaining a single hard probe deadline. A shaped or congested path may drop
// an individual datagram; treating that as proof that the tunnel is invalid
// makes verification less reliable precisely when Auto is supposed to recover.
// Reusing the same per-probe request is safe: DNS still requires the random
// query ID and exact question, while the canary challenge contains a fresh
// random nonce and the complete signed candidate binding.
func exchangeLinuxProtectedUDP(
	ctx context.Context,
	connection net.Conn,
	request []byte,
	response []byte,
	name string,
) (int, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0, fmt.Errorf("%s deadline is required", name)
	}
	if err := connection.SetWriteDeadline(deadline); err != nil {
		return 0, fmt.Errorf("set %s write deadline: %w", name, err)
	}
	for {
		if cause := context.Cause(ctx); cause != nil {
			return 0, cause
		}
		count, err := connection.Write(request)
		if err != nil {
			if cause := context.Cause(ctx); cause != nil {
				return 0, cause
			}
			return 0, fmt.Errorf("write %s request: %w", name, err)
		}
		if count != len(request) {
			return 0, fmt.Errorf(
				"write %s request: short datagram write %d/%d",
				name, count, len(request),
			)
		}
		readDeadline := time.Now().Add(linuxProbeRetransmitInterval)
		if deadline.Before(readDeadline) {
			readDeadline = deadline
		}
		if err := connection.SetReadDeadline(readDeadline); err != nil {
			return 0, fmt.Errorf("set %s read deadline: %w", name, err)
		}
		count, err = connection.Read(response)
		if err == nil {
			return count, nil
		}
		if cause := context.Cause(ctx); cause != nil {
			return 0, cause
		}
		var networkError net.Error
		if !errors.As(err, &networkError) || !networkError.Timeout() {
			return 0, fmt.Errorf("read %s response: %w", name, err)
		}
		if !time.Now().Before(deadline) {
			if cause := context.Cause(ctx); cause != nil {
				return 0, cause
			}
			return 0, context.DeadlineExceeded
		}
	}
}

type linuxCanaryBinding struct {
	AttemptID      string `json:"attempt_id"`
	Profile        string `json:"profile"`
	Mode           string `json:"mode"`
	ManifestDigest string `json:"manifest_digest"`
	CandidateID    string `json:"candidate_id"`
	NodeID         string `json:"node_id"`
	SessionID      string `json:"session_id"`
	PSKGeneration  uint64 `json:"psk_generation"`
	SequenceEpoch  uint64 `json:"sequence_epoch"`
	Nonce          string `json:"nonce"`
	ExpiresAt      string `json:"expires_at"`
}

func linuxCanaryChallenge(
	binding connectivity.Binding,
) ([]byte, error) {
	canonical, err := json.Marshal(linuxCanaryBinding{
		AttemptID:      binding.AttemptID,
		Profile:        binding.Profile,
		Mode:           string(binding.Mode),
		ManifestDigest: binding.ManifestDigest,
		CandidateID:    binding.CandidateID,
		NodeID:         binding.NodeID,
		SessionID:      binding.SessionID,
		PSKGeneration:  binding.PSKGeneration,
		SequenceEpoch:  binding.SequenceEpoch,
		Nonce:          binding.Nonce,
		ExpiresAt: binding.ExpiresAt.UTC().Format(
			time.RFC3339Nano,
		),
	})
	if err != nil {
		return nil, err
	}
	bindingDigest := sha256.Sum256(append(
		[]byte("winn-linux-canary-binding/v1\x00"), canonical...,
	))
	clear(canonical)
	challenge := make([]byte, 1+sha256.Size+32)
	challenge[0] = 1
	copy(challenge[1:1+sha256.Size], bindingDigest[:])
	clear(bindingDigest[:])
	if _, err := rand.Read(challenge[1+sha256.Size:]); err != nil {
		clear(challenge)
		return nil, err
	}
	return challenge, nil
}

func (verifier *linuxProtectedVerifier) probeContext(
	ctx context.Context,
) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, verifier.config.Timeout)
}

func validateLinuxVerificationConfig(
	config LinuxVerificationConfig,
) error {
	resolver, err := parseIPLiteralAddrPort(config.DNSResolver)
	if err != nil || resolver.Port() == 0 {
		return errors.New("linux protected DNS resolver is invalid")
	}
	canary, err := parseIPLiteralAddrPort(config.CanaryEndpoint)
	if err != nil || canary.Port() == 0 {
		return errors.New("linux tunnel canary endpoint is invalid")
	}
	if resolver.Addr().Is4() != canary.Addr().Is4() {
		return errors.New(
			"linux verifier endpoints must use one address family",
		)
	}
	if !validDNSName(config.DNSQueryName) {
		return errors.New("linux protected DNS query name is invalid")
	}
	if len(config.ExpectedDNSAnswers) == 0 ||
		len(config.ExpectedDNSAnswers) > 8 {
		return errors.New(
			"linux protected DNS expected-answer count is invalid",
		)
	}
	seen := make(map[netip.Addr]struct{}, len(config.ExpectedDNSAnswers))
	for _, answer := range config.ExpectedDNSAnswers {
		if !answer.IsValid() || answer.IsUnspecified() ||
			answer.IsMulticast() ||
			answer.Is4() != resolver.Addr().Is4() {
			return errors.New(
				"linux protected DNS expected answer is invalid",
			)
		}
		if _, duplicate := seen[answer]; duplicate {
			return errors.New(
				"linux protected DNS expected answer is duplicated",
			)
		}
		seen[answer] = struct{}{}
	}
	if config.Timeout < 0 || config.Timeout > 10*time.Second {
		return errors.New("linux protected probe timeout is invalid")
	}
	return nil
}

func validateLinuxProbeContext(probe LinuxProbeContext) error {
	if err := validateLinuxProtectedSocket(
		probe.InterfaceName, probe.FirewallMark,
	); err != nil {
		return err
	}
	if !probe.InnerAddress.IsValid() ||
		probe.InnerAddress.Bits() != probe.InnerAddress.Addr().BitLen() {
		return errors.New("linux probe inner address is invalid")
	}
	if len(probe.VerificationRoutes) == 0 {
		return errors.New("linux probe verification routes are missing")
	}
	return nil
}

func validateLinuxProtectedSocket(
	interfaceName string,
	firewallMark uint32,
) error {
	if len(interfaceName) == 0 ||
		len(interfaceName) > linuxInterfaceNameMax {
		return errors.New("linux protected interface name is invalid")
	}
	for _, character := range interfaceName {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '_' || character == '-' || character == '.' {
			continue
		}
		return errors.New("linux protected interface name is invalid")
	}
	if firewallMark == 0 {
		return errors.New("linux protected socket mark is required")
	}
	return nil
}

func parseIPLiteralAddrPort(endpoint string) (netip.AddrPort, error) {
	if err := validateIPLiteralEndpoint(endpoint, false); err != nil {
		return netip.AddrPort{}, err
	}
	return netip.ParseAddrPort(endpoint)
}

func udpNetwork(endpoint string) string {
	address, err := netip.ParseAddrPort(endpoint)
	if err == nil && address.Addr().Is4() {
		return "udp4"
	}
	return "udp6"
}

func linuxProbeRouteContains(
	routes []netip.Prefix,
	address netip.Addr,
) bool {
	for _, route := range routes {
		if route.Contains(address) {
			return true
		}
	}
	return false
}

func validDNSName(name string) bool {
	name = strings.TrimSuffix(name, ".")
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 ||
			label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') ||
				(character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') ||
				character == '-' {
				continue
			}
			return false
		}
	}
	return true
}
