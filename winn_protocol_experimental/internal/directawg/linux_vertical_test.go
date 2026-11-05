package directawg

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/gatewaymanifest"
	"winsvpn.local/winnprotocol/internal/pqauth"
)

func TestLinuxPolicyMarkMatchesRealNftListWidth(t *testing.T) {
	// Found by running the real controller and policy factory against a
	// real cloud gateway over the real internet: a committed connection's
	// own post-commit health check reported the underlay mark "missing"
	// from nftables every single time, because `nft list set` always
	// renders a mark as 8 zero-padded hex digits regardless of magnitude,
	// while linuxPolicyMark previously rendered it unpadded — so the
	// substring check in verifySetMembership could never succeed. This
	// pins the exact real-world output shape rather than an assumption.
	cases := []struct {
		value uint32
		want  string
	}{
		{value: 0x9001, want: "0x00009001"},
		{value: 0x1, want: "0x00000001"},
		{value: 0xffffffff, want: "0xffffffff"},
		{value: 0, want: "0x00000000"},
	}
	for _, testCase := range cases {
		if got := linuxPolicyMark(testCase.value); got != testCase.want {
			t.Errorf(
				"linuxPolicyMark(%#x) = %q, want %q",
				testCase.value, got, testCase.want,
			)
		}
	}
}

func TestLinuxProtectedVerifierDNSAndCanaryAreMarkedAndBound(
	t *testing.T,
) {
	dialer := &verticalProbeDialer{}
	verifier := &linuxProtectedVerifier{
		config: LinuxVerificationConfig{
			DNSResolver:        "10.66.0.53:53",
			DNSQueryName:       "canary.winn.invalid",
			ExpectedDNSAnswers: []netip.Addr{netip.MustParseAddr("10.66.0.9")},
			CanaryEndpoint:     "10.66.0.9:7007",
			Timeout:            time.Second,
		},
		dialer: dialer,
	}
	probe := LinuxProbeContext{
		Binding:       verticalBinding(time.Now().UTC()),
		InterfaceName: "winn123",
		InnerAddress:  netip.MustParsePrefix("10.77.0.2/32"),
		FirewallMark:  0x1234,
		VerificationRoutes: []netip.Prefix{
			netip.MustParsePrefix("10.66.0.0/24"),
		},
	}
	if err := verifier.VerifyProtectedDNS(
		context.Background(), probe,
	); err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyTunnelCanary(
		context.Background(), probe,
	); err != nil {
		t.Fatal(err)
	}
	if dialer.calls != 2 {
		t.Fatalf("protected dial calls = %d", dialer.calls)
	}
	for _, call := range dialer.seen {
		if call.interfaceName != probe.InterfaceName ||
			call.mark != probe.FirewallMark ||
			!strings.HasPrefix(call.network, "udp") {
			t.Fatalf("protected dial = %#v", call)
		}
	}
}

func TestLinuxProtectedVerifierRetransmitsDNSAndCanaryAfterLoss(
	t *testing.T,
) {
	dialer := &verticalProbeDialer{readTimeouts: 1}
	verifier := &linuxProtectedVerifier{
		config: LinuxVerificationConfig{
			DNSResolver:        "10.66.0.53:53",
			DNSQueryName:       "canary.winn.invalid",
			ExpectedDNSAnswers: []netip.Addr{netip.MustParseAddr("10.66.0.9")},
			CanaryEndpoint:     "10.66.0.9:7007",
			Timeout:            time.Second,
		},
		dialer: dialer,
	}
	probe := LinuxProbeContext{
		Binding:       verticalBinding(time.Now().UTC()),
		InterfaceName: "winn123",
		InnerAddress:  netip.MustParsePrefix("10.77.0.2/32"),
		FirewallMark:  0x1234,
		VerificationRoutes: []netip.Prefix{
			netip.MustParsePrefix("10.66.0.0/24"),
		},
	}
	if err := verifier.VerifyProtectedDNS(
		context.Background(), probe,
	); err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyTunnelCanary(
		context.Background(), probe,
	); err != nil {
		t.Fatal(err)
	}
	if len(dialer.connections) != 2 {
		t.Fatalf("protected connections = %d, want 2", len(dialer.connections))
	}
	for index, connection := range dialer.connections {
		if connection.writeCalls != 2 {
			t.Errorf(
				"protected connection %d writes = %d, want 2",
				index, connection.writeCalls,
			)
		}
	}
}

func TestLinuxProtectedUDPAcceptsDelayedFirstResponseAfterRetransmit(
	t *testing.T,
) {
	server, err := net.ListenUDP(
		"udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	request := []byte("signed-probe-request")
	observed := make(chan [][]byte, 1)
	go func() {
		buffer := make([]byte, 256)
		count, remote, readErr := server.ReadFromUDP(buffer)
		if readErr != nil {
			observed <- nil
			return
		}
		first := slices.Clone(buffer[:count])
		time.Sleep(250 * time.Millisecond)
		if _, writeErr := server.WriteToUDP(first, remote); writeErr != nil {
			observed <- nil
			return
		}
		_ = server.SetReadDeadline(time.Now().Add(time.Second))
		count, _, readErr = server.ReadFromUDP(buffer)
		if readErr != nil {
			observed <- nil
			return
		}
		observed <- [][]byte{first, slices.Clone(buffer[:count])}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := time.Now()
	response := make([]byte, 256)
	count, err := exchangeLinuxProtectedUDP(
		ctx, client, request, response, "delayed probe",
	)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed < 225*time.Millisecond ||
		elapsed > 750*time.Millisecond {
		t.Fatalf("delayed response completed after %s", elapsed)
	}
	if !slices.Equal(response[:count], request) {
		t.Fatalf("response = %q, want %q", response[:count], request)
	}
	transmissions := <-observed
	if len(transmissions) != 2 ||
		!slices.Equal(transmissions[0], request) ||
		!slices.Equal(transmissions[1], request) {
		t.Fatalf("retransmitted requests = %q", transmissions)
	}
}

func TestLinuxProtectedUDPAllLossObeysHardDeadline(t *testing.T) {
	server, err := net.ListenUDP(
		"udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(
		context.Background(), 80*time.Millisecond,
	)
	defer cancel()
	started := time.Now()
	_, err = exchangeLinuxProtectedUDP(
		ctx,
		client,
		[]byte("drop-every-request"),
		make([]byte, 256),
		"all-loss probe",
	)
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("all-loss error = %v, want deadline exceeded", err)
	}
	if elapsed < 60*time.Millisecond || elapsed > 300*time.Millisecond {
		t.Fatalf("all-loss deadline completed after %s", elapsed)
	}
}

func TestLinuxProtectedVerifierRejectsProbeOutsideSignedRoutes(
	t *testing.T,
) {
	dialer := &verticalProbeDialer{}
	verifier := &linuxProtectedVerifier{
		config: LinuxVerificationConfig{
			DNSResolver:        "10.66.0.53:53",
			DNSQueryName:       "canary.winn.invalid",
			ExpectedDNSAnswers: []netip.Addr{netip.MustParseAddr("10.66.0.9")},
			CanaryEndpoint:     "10.66.0.9:7007",
			Timeout:            time.Second,
		},
		dialer: dialer,
	}
	probe := LinuxProbeContext{
		Binding:       verticalBinding(time.Now().UTC()),
		InterfaceName: "winn123",
		InnerAddress:  netip.MustParsePrefix("10.77.0.2/32"),
		FirewallMark:  0x1234,
		VerificationRoutes: []netip.Prefix{
			netip.MustParsePrefix("10.67.0.0/24"),
		},
	}
	if err := verifier.VerifyProtectedDNS(
		context.Background(), probe,
	); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("route-bound DNS error = %v", err)
	}
	if dialer.calls != 0 {
		t.Fatalf("untrusted probe opened %d sockets", dialer.calls)
	}
}

func TestLinuxNftResolvedPolicyFailClosedLifecycle(t *testing.T) {
	runner := &verticalPolicyRunner{}
	batch := &verticalBatchRunner{}
	factory := &LinuxNftResolvedPolicyFactory{
		config: LinuxNftResolvedPolicyConfig{
			NftBinary:         "/test/nft",
			ResolvectlBinary:  "/test/resolvectl",
			TableName:         "winn_test",
			UnderlayInterface: "eth0",
			UnderlayMark:      0x9001,
			DNSResolver:       netip.MustParseAddr("10.66.0.53"),
			HealthInterval:    30 * time.Second,
			Runner:            runner,
		},
		batch: batch,
	}
	transaction, err := factory.Prepare(
		context.Background(),
		LinuxPolicySpec{
			Binding:       verticalBinding(time.Now().UTC()),
			InterfaceName: "winn123",
			InnerAddress:  netip.MustParsePrefix("10.77.0.2/32"),
			RouteTable:    10001,
			FirewallMark:  0x1234,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.scripts) != 2 ||
		!strings.Contains(batch.scripts[0], "policy drop") ||
		!strings.Contains(
			batch.scripts[0],
			"ip6 hoplimit 255 ip6 daddr { fe80::/10, ff02::/16 } "+
				"icmpv6 type { nd-router-solicit, nd-neighbor-solicit, "+
				"nd-neighbor-advert } accept",
		) ||
		!strings.Contains(batch.scripts[1], "tunnel_ifaces") ||
		!strings.Contains(batch.scripts[1], "underlay_marks") {
		t.Fatalf("prepare nft batches = %#v", batch.scripts)
	}
	if err := transaction.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(batch.scripts) != 3 ||
		!strings.HasPrefix(batch.scripts[2], "delete element") {
		t.Fatalf("rollback nft batch = %#v", batch.scripts)
	}
	commands := runner.snapshot()
	expected := [][]string{
		{"dns", "winn123", "10.66.0.53"},
		{"default-route", "winn123", "false"},
		{"domain", "winn123", "~."},
		{"default-route", "winn123", "true"},
		{"revert", "winn123"},
	}
	if len(commands) != len(expected) {
		t.Fatalf("resolved command count = %d: %#v", len(commands), commands)
	}
	for index := range expected {
		if !slices.Equal(commands[index].Args, expected[index]) {
			t.Fatalf(
				"resolved command %d = %#v, want %#v",
				index, commands[index].Args, expected[index],
			)
		}
	}
	if factory.active != 0 || factory.underlayReferences != 0 {
		t.Fatalf(
			"policy references active=%d underlay=%d",
			factory.active, factory.underlayReferences,
		)
	}
	if err := factory.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(
		batch.scripts[len(batch.scripts)-1], "delete table",
	) {
		t.Fatalf("release batch = %#v", batch.scripts)
	}
}

func TestLinuxPolicyDoesNotRestoreDNSIfKillSwitchCannotEngage(
	t *testing.T,
) {
	runner := &verticalPolicyRunner{}
	batch := &verticalBatchRunner{}
	factory := &LinuxNftResolvedPolicyFactory{
		config: LinuxNftResolvedPolicyConfig{
			NftBinary:         "/test/nft",
			ResolvectlBinary:  "/test/resolvectl",
			TableName:         "winn_test",
			UnderlayInterface: "eth0",
			UnderlayMark:      0x9001,
			DNSResolver:       netip.MustParseAddr("10.66.0.53"),
			HealthInterval:    30 * time.Second,
			Runner:            runner,
		},
		batch: batch,
	}
	raw, err := factory.Prepare(
		context.Background(),
		LinuxPolicySpec{
			Binding:       verticalBinding(time.Now().UTC()),
			InterfaceName: "winn123",
			InnerAddress:  netip.MustParsePrefix("10.77.0.2/32"),
			RouteTable:    10001,
			FirewallMark:  0x1234,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	batch.failDelete = true
	if err := raw.Rollback(
		context.Background(),
	); err == nil || !strings.Contains(err.Error(), "kill switch") {
		t.Fatalf("fail-closed rollback error = %v", err)
	}
	for _, command := range runner.snapshot() {
		if len(command.Args) > 0 && command.Args[0] == "revert" {
			t.Fatal("DNS was restored before kill switch engagement")
		}
	}
}

func TestLinuxNftResolvedPolicyPrepareRollsBackOnResolverAdmitFailure(
	t *testing.T,
) {
	runner := &verticalPolicyRunner{failDNSAdmit: true}
	batch := &verticalBatchRunner{}
	factory := &LinuxNftResolvedPolicyFactory{
		config: LinuxNftResolvedPolicyConfig{
			NftBinary:         "/test/nft",
			ResolvectlBinary:  "/test/resolvectl",
			TableName:         "winn_test",
			UnderlayInterface: "eth0",
			UnderlayMark:      0x9001,
			DNSResolver:       netip.MustParseAddr("10.66.0.53"),
			HealthInterval:    30 * time.Second,
			Runner:            runner,
		},
		batch: batch,
	}
	_, err := factory.Prepare(
		context.Background(),
		LinuxPolicySpec{
			Binding:       verticalBinding(time.Now().UTC()),
			InterfaceName: "winn123",
			InnerAddress:  netip.MustParsePrefix("10.77.0.2/32"),
			RouteTable:    10001,
			FirewallMark:  0x1234,
		},
	)
	if err == nil {
		t.Fatal("prepare with failing resolver admit unexpectedly succeeded")
	}
	if len(batch.scripts) != 3 ||
		!strings.HasPrefix(batch.scripts[2], "delete element") {
		t.Fatalf("prepare-failure nft batches = %#v", batch.scripts)
	}
	if factory.active != 0 || factory.underlayReferences != 0 {
		t.Fatalf(
			"factory state after failed admit: active=%d underlay=%d",
			factory.active, factory.underlayReferences,
		)
	}
}

func TestLinuxNftResolvedPolicyRollbackRetriesResolverWithoutRepeatingNft(
	t *testing.T,
) {
	runner := &verticalPolicyRunner{
		failRevert: true, resolverStatus: "Link 2 (winn123)\n",
	}
	batch := &verticalBatchRunner{}
	factory := &LinuxNftResolvedPolicyFactory{
		config: LinuxNftResolvedPolicyConfig{
			NftBinary:         "/test/nft",
			ResolvectlBinary:  "/test/resolvectl",
			TableName:         "winn_test",
			UnderlayInterface: "eth0",
			UnderlayMark:      0x9001,
			DNSResolver:       netip.MustParseAddr("10.66.0.53"),
			HealthInterval:    30 * time.Second,
			Runner:            runner,
		},
		batch: batch,
	}
	transaction, err := factory.Prepare(
		context.Background(),
		LinuxPolicySpec{
			Binding:       verticalBinding(time.Now().UTC()),
			InterfaceName: "winn123",
			InnerAddress:  netip.MustParsePrefix("10.77.0.2/32"),
			RouteTable:    10001,
			FirewallMark:  0x1234,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}

	if err := transaction.Rollback(
		context.Background(),
	); err == nil ||
		!strings.Contains(err.Error(), "restore linux resolver state") {
		t.Fatalf("first rollback with failing revert = %v", err)
	}
	nftScriptsAfterFirstAttempt := len(batch.scripts)
	if factory.active == 0 || factory.underlayReferences == 0 {
		t.Fatalf(
			"kill switch references were released before resolver reverted: active=%d underlay=%d",
			factory.active, factory.underlayReferences,
		)
	}
	if err := factory.Release(context.Background()); err == nil {
		t.Fatal("release succeeded while resolver rollback was still outstanding")
	}

	runner.failRevert = false
	if err := transaction.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(batch.scripts) != nftScriptsAfterFirstAttempt {
		t.Fatalf(
			"rollback retry repeated the nft removal: scripts before=%d after=%d",
			nftScriptsAfterFirstAttempt, len(batch.scripts),
		)
	}
	if factory.active != 0 || factory.underlayReferences != 0 {
		t.Fatalf(
			"factory state after successful retry: active=%d underlay=%d",
			factory.active, factory.underlayReferences,
		)
	}
	if err := factory.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxPolicyRollbackAcceptsProvenAbsentResolverLink(t *testing.T) {
	runner := &verticalPolicyRunner{
		failRevert: true, resolverStatus: "Link 2 (eth0)\n",
	}
	batch := &verticalBatchRunner{}
	factory := &LinuxNftResolvedPolicyFactory{
		config: LinuxNftResolvedPolicyConfig{
			NftBinary:         "/test/nft",
			ResolvectlBinary:  "/test/resolvectl",
			TableName:         "winn_test",
			UnderlayInterface: "eth0",
			UnderlayMark:      0x9001,
			DNSResolver:       netip.MustParseAddr("10.66.0.53"),
			HealthInterval:    30 * time.Second,
			Runner:            runner,
		},
		batch: batch,
	}
	transaction, err := factory.Prepare(
		context.Background(),
		LinuxPolicySpec{
			Binding:       verticalBinding(time.Now().UTC()),
			InterfaceName: "winn123",
			InnerAddress:  netip.MustParsePrefix("10.77.0.2/32"),
			RouteTable:    10001,
			FirewallMark:  0x1234,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	commands := runner.snapshot()
	if len(commands) < 4 ||
		!slices.Equal(commands[len(commands)-2].Args, []string{"revert", "winn123"}) ||
		!slices.Equal(commands[len(commands)-1].Args, []string{"status"}) {
		t.Fatalf("resolver absence proof commands = %#v", commands)
	}
	if factory.active != 0 || factory.underlayReferences != 0 {
		t.Fatalf(
			"policy references active=%d underlay=%d",
			factory.active, factory.underlayReferences,
		)
	}
	if err := factory.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxNftResolvedPolicyHealthVerifiesSetMembership(t *testing.T) {
	runner := &verticalPolicyRunner{
		setContents: map[string]string{
			"tunnel_ifaces":   `elements = { "winn123" }`,
			"underlay_ifaces": `elements = { "eth0" }`,
			"underlay_marks":  `elements = { 0x00009001 }`,
		},
	}
	factory := &LinuxNftResolvedPolicyFactory{
		config: LinuxNftResolvedPolicyConfig{
			NftBinary:         "/test/nft",
			ResolvectlBinary:  "/test/resolvectl",
			TableName:         "winn_test",
			UnderlayInterface: "eth0",
			UnderlayMark:      0x9001,
			DNSResolver:       netip.MustParseAddr("10.66.0.53"),
			HealthInterval:    20 * time.Millisecond,
			Runner:            runner,
		},
		batch: &verticalBatchRunner{},
	}
	transaction, err := factory.Prepare(
		context.Background(),
		LinuxPolicySpec{
			Binding:       verticalBinding(time.Now().UTC()),
			InterfaceName: "winn123",
			InnerAddress:  netip.MustParsePrefix("10.77.0.2/32"),
			RouteTable:    10001,
			FirewallMark:  0x1234,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err, ok := <-transaction.Health():
		t.Fatalf(
			"unexpected health event with membership present: err=%v ok=%v",
			err, ok,
		)
	case <-time.After(120 * time.Millisecond):
	}
	if err := transaction.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}

	runner2 := &verticalPolicyRunner{
		setContents: map[string]string{
			"tunnel_ifaces":   `elements = { }`,
			"underlay_ifaces": `elements = { "eth0" }`,
			"underlay_marks":  `elements = { 0x00009001 }`,
		},
	}
	factory2 := &LinuxNftResolvedPolicyFactory{
		config: LinuxNftResolvedPolicyConfig{
			NftBinary:         "/test/nft",
			ResolvectlBinary:  "/test/resolvectl",
			TableName:         "winn_test",
			UnderlayInterface: "eth0",
			UnderlayMark:      0x9001,
			DNSResolver:       netip.MustParseAddr("10.66.0.53"),
			HealthInterval:    20 * time.Millisecond,
			Runner:            runner2,
		},
		batch: &verticalBatchRunner{},
	}
	transaction2, err := factory2.Prepare(
		context.Background(),
		LinuxPolicySpec{
			Binding:       verticalBinding(time.Now().UTC()),
			InterfaceName: "winn123",
			InnerAddress:  netip.MustParsePrefix("10.77.0.2/32"),
			RouteTable:    10001,
			FirewallMark:  0x1234,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction2.Rollback(context.Background()) }()
	select {
	case err := <-transaction2.Health():
		if err == nil || !strings.Contains(err.Error(), "tunnel_ifaces") {
			t.Fatalf(
				"health error = %v, want tunnel_ifaces membership failure",
				err,
			)
		}
	case <-time.After(2 * time.Second):
		t.Fatal(
			"expected health check to detect missing tunnel_ifaces membership",
		)
	}
}

func TestLinuxDeploymentProfileBindsSignedManifest(t *testing.T) {
	now := time.Date(2026, 7, 23, 20, 0, 0, 0, time.UTC)
	signer, pins := verticalSigner(t)
	manifest := verticalManifest(t, now, signer)
	manifestDigest, err := gatewaymanifest.DigestV2(manifest)
	if err != nil {
		t.Fatal(err)
	}
	profile := verticalProfile(now, manifestDigest)
	if err := SignLinuxDeploymentProfile(&profile, signer); err != nil {
		t.Fatal(err)
	}
	interfaceConfig, verifierConfig, err :=
		VerifyLinuxDeploymentProfile(
			profile, manifest, pins, now.Add(time.Minute),
		)
	if err != nil {
		t.Fatal(err)
	}
	if interfaceConfig.MTU != 1280 ||
		verifierConfig.DNSResolver != "10.66.0.53:53" {
		t.Fatalf(
			"verified profile interface=%#v verifier=%#v",
			interfaceConfig, verifierConfig,
		)
	}
	profile.Probe.CanaryEndpoint = "10.66.0.10:7007"
	if _, _, err := VerifyLinuxDeploymentProfile(
		profile, manifest, pins, now.Add(time.Minute),
	); err == nil {
		t.Fatal("tampered Linux deployment profile verified")
	}
}

type verticalProbeDial struct {
	network       string
	endpoint      string
	interfaceName string
	mark          uint32
}

type verticalProbeDialer struct {
	calls        int
	seen         []verticalProbeDial
	readTimeouts int
	connections  []*verticalProbeConnection
}

func (dialer *verticalProbeDialer) Dial(
	_ context.Context,
	network string,
	endpoint string,
	interfaceName string,
	mark uint32,
) (net.Conn, error) {
	dialer.calls++
	dialer.seen = append(dialer.seen, verticalProbeDial{
		network: network, endpoint: endpoint,
		interfaceName: interfaceName, mark: mark,
	})
	connection := &verticalProbeConnection{
		canary:       strings.HasSuffix(endpoint, ":7007"),
		readTimeouts: dialer.readTimeouts,
	}
	dialer.connections = append(dialer.connections, connection)
	return connection, nil
}

type verticalProbeConnection struct {
	canary       bool
	wrote        []byte
	readTimeouts int
	writeCalls   int
}

func (connection *verticalProbeConnection) Read(buffer []byte) (int, error) {
	if connection.readTimeouts > 0 {
		connection.readTimeouts--
		return 0, verticalProbeTimeoutError{}
	}
	if connection.canary {
		return copy(buffer, connection.wrote), nil
	}
	var query dnsmessage.Message
	if err := query.Unpack(connection.wrote); err != nil {
		return 0, err
	}
	response := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:       query.ID,
			Response: true,
		},
		Questions: query.Questions,
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  query.Questions[0].Name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				TTL:   30,
			},
			Body: &dnsmessage.AResource{
				A: [4]byte{10, 66, 0, 9},
			},
		}},
	}
	payload, err := response.Pack()
	if err != nil {
		return 0, err
	}
	return copy(buffer, payload), nil
}

func (connection *verticalProbeConnection) Write(buffer []byte) (int, error) {
	connection.writeCalls++
	connection.wrote = append(connection.wrote[:0], buffer...)
	return len(buffer), nil
}

func (*verticalProbeConnection) Close() error                     { return nil }
func (*verticalProbeConnection) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*verticalProbeConnection) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (*verticalProbeConnection) SetDeadline(time.Time) error      { return nil }
func (*verticalProbeConnection) SetReadDeadline(time.Time) error  { return nil }
func (*verticalProbeConnection) SetWriteDeadline(time.Time) error { return nil }

type verticalProbeTimeoutError struct{}

func (verticalProbeTimeoutError) Error() string   { return "packet lost" }
func (verticalProbeTimeoutError) Timeout() bool   { return true }
func (verticalProbeTimeoutError) Temporary() bool { return true }

type verticalBatchRunner struct {
	scripts    []string
	failDelete bool
}

func (runner *verticalBatchRunner) Run(
	_ context.Context,
	script string,
) error {
	runner.scripts = append(runner.scripts, script)
	if runner.failDelete && strings.HasPrefix(script, "delete element") {
		return errors.New("nft unavailable")
	}
	return nil
}

type verticalPolicyRunner struct {
	mu             sync.Mutex
	commands       []LinuxCommand
	failDNSAdmit   bool
	failRevert     bool
	resolverStatus string
	setContents    map[string]string
}

func (runner *verticalPolicyRunner) Run(
	_ context.Context,
	command LinuxCommand,
) (LinuxCommandResult, error) {
	runner.mu.Lock()
	runner.commands = append(runner.commands, command)
	runner.mu.Unlock()
	if runner.failDNSAdmit && len(command.Args) > 0 &&
		command.Args[0] == "dns" {
		return LinuxCommandResult{}, errors.New(
			"simulated resolvectl dns failure",
		)
	}
	if runner.failRevert && len(command.Args) > 0 &&
		command.Args[0] == "revert" {
		return LinuxCommandResult{}, errors.New(
			"simulated resolvectl revert failure",
		)
	}
	if len(command.Args) == 1 && command.Args[0] == "status" {
		return LinuxCommandResult{
			Stdout: []byte(runner.resolverStatus),
		}, nil
	}
	if len(command.Args) >= 2 && command.Args[0] == "list" &&
		(command.Args[1] == "set" || command.Args[1] == "chain") {
		setName := command.Args[len(command.Args)-1]
		return LinuxCommandResult{
			Stdout: []byte(runner.setContents[setName]),
		}, nil
	}
	return LinuxCommandResult{}, nil
}

func (*verticalPolicyRunner) Start(
	LinuxCommand,
) (LinuxManagedProcess, error) {
	return nil, errors.New("unexpected process start")
}

func (runner *verticalPolicyRunner) snapshot() []LinuxCommand {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	result := make([]LinuxCommand, len(runner.commands))
	copy(result, runner.commands)
	return result
}

func verticalBinding(now time.Time) connectivity.Binding {
	return connectivity.Binding{
		AttemptID:      strings.Repeat("1", 32),
		Profile:        "default",
		Mode:           connectivity.ModeAuto,
		ManifestDigest: strings.Repeat("a", 64),
		CandidateID:    "direct-primary",
		NodeID:         "entry-nyc",
		SessionID:      strings.Repeat("2", 32),
		PSKGeneration:  1,
		SequenceEpoch:  1,
		Nonce:          strings.Repeat("3", 32),
		ExpiresAt:      now.Add(time.Hour),
	}
}

func verticalSigner(
	t *testing.T,
) (*pqauth.Signer, *pqauth.VerifierSet) {
	t.Helper()
	seed := make([]byte, 32)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	signer, err := pqauth.NewSigner(pqauth.MLDSA65, seed)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := signer.PublicBytes()
	verifier, err := pqauth.NewVerifier(pqauth.MLDSA65, publicKey)
	clear(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	pins, err := pqauth.NewVerifierSet(verifier)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pins
}

func verticalManifest(
	t *testing.T,
	now time.Time,
	signer *pqauth.Signer,
) gatewaymanifest.ManifestV2 {
	t.Helper()
	manifest := gatewaymanifest.ManifestV2{
		Format:        gatewaymanifest.FormatV2,
		Sequence:      1,
		IssuedAt:      now.Format(time.RFC3339),
		ExpiresAt:     now.Add(24 * time.Hour).Format(time.RFC3339),
		ControllerID:  "controller-1",
		Suite:         "x25519-mlkem768",
		MinimumClient: gatewaymanifest.MinimumClientV3,
		Capabilities:  gatewaymanifest.RequiredV2Capabilities(),
		Nodes: []gatewaymanifest.NodeV2{{
			ID:           "entry-nyc",
			OperatorID:   "operator-1",
			Provider:     "vultr",
			Roles:        []string{gatewaymanifest.RoleCarrier},
			Capabilities: []string{"candidate-isolated-verification"},
			Transports: []gatewaymanifest.TransportV2{{
				ID:                  "direct-primary",
				Type:                connectivity.CarrierDirectAWG,
				Endpoint:            "192.0.2.10:51820",
				Suite:               "x25519-mlkem768",
				AuthenticationModes: []string{gatewaymanifest.AuthAWGPSK},
				PublicAWGKey: base64.StdEncoding.EncodeToString(
					slices.Repeat([]byte{0x44}, 32),
				),
				MinInnerDatagram: 1200,
				MaxInnerDatagram: 1350,
				Capabilities: []string{
					"awg-handshake-readiness",
					"candidate-isolated-verification",
				},
			}},
		}},
	}
	if err := gatewaymanifest.SignV2(&manifest, signer); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func verticalProfile(
	now time.Time,
	manifestDigest string,
) LinuxDeploymentProfile {
	return LinuxDeploymentProfile{
		Format:         LinuxDeploymentProfileFormat,
		ManifestDigest: manifestDigest,
		NodeID:         "entry-nyc",
		TransportID:    "direct-primary",
		IssuedAt:       now.Format(time.RFC3339),
		ExpiresAt:      now.Add(24 * time.Hour).Format(time.RFC3339),
		Interface: LinuxInterfaceProfile{
			InnerAddressPool:    "10.77.0.0/24",
			AllowedIPs:          []string{"0.0.0.0/0"},
			VerificationRoutes:  []string{"10.66.0.0/24"},
			MTU:                 1280,
			ListenPortMin:       40000,
			ListenPortMax:       40100,
			PersistentKeepalive: 25,
			Obfuscation: AWGObfuscation{
				JC: 4, JMin: 12, JMax: 64,
				S1: 16, S2: 80, S3: 24, S4: 8,
				H1: 101, H2: 202, H3: 303, H4: 404,
			},
		},
		Probe: LinuxProbeProfile{
			DNSResolver:         "10.66.0.53:53",
			DNSQueryName:        "canary.winn.invalid",
			ExpectedDNSAnswers:  []string{"10.66.0.9"},
			CanaryEndpoint:      "10.66.0.9:7007",
			TimeoutMilliseconds: 3000,
		},
	}
}

var _ io.Reader = (*verticalProbeConnection)(nil)
