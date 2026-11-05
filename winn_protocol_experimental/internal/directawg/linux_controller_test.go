package directawg

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
)

func TestLinuxControllerExactLifecycleAndSecretHygiene(t *testing.T) {
	harness := newLinuxHarness(t)
	prepared, err := harness.controller.Prepare(
		context.Background(), harness.preparation,
	)
	if err != nil {
		t.Fatal(err)
	}
	session, ok := prepared.Session.(*linuxTunnelSession)
	if !ok {
		t.Fatalf("session type = %T", prepared.Session)
	}
	identity := deriveLinuxCandidateIdentity(
		harness.binding, harness.signed.InnerAddressPool,
	)
	listenPort := candidateStartPort(identity, harness.signed)
	if prepared.Baseline.LatestHandshake != (time.Time{}) ||
		prepared.Baseline.RxBytes != 0 ||
		prepared.Baseline.TxBytes != 0 {
		t.Fatalf("baseline = %#v", prepared.Baseline)
	}
	if prepared.LocalSourceEndpoint != net.JoinHostPort(
		"127.0.0.1", fmt.Sprint(listenPort),
	) {
		t.Fatalf("local source = %q", prepared.LocalSourceEndpoint)
	}
	if !allZero(harness.keyProvider.private) ||
		!allZero(harness.keyProvider.psk) {
		t.Fatal("key provider buffers were not cleared")
	}
	if !bytes.Equal(harness.runner.privateKey, bytes.Repeat([]byte{0x31}, 32)) ||
		!bytes.Equal(harness.runner.psk, bytes.Repeat([]byte{0x42}, 32)) {
		t.Fatal("secure key files did not contain the expected material")
	}
	for _, path := range harness.runner.secretPaths {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("secret path still exists: %s: %v", path, err)
		}
	}
	harness.assertNoSecretArguments(t)

	expectedPrepare := []string{
		commandEvent(harness.awgGo, "-f", identity.InterfaceName),
		commandEvent(
			harness.ip, "link", "show", "dev", identity.InterfaceName,
		),
		commandEvent(
			harness.awg,
			"set", identity.InterfaceName,
			"private-key", harness.runner.secretPaths[0],
			"listen-port", fmt.Sprint(listenPort),
			"fwmark", fmt.Sprintf("0x%x", uint32(fakeLinuxPolicyUnderlayMark)),
			"jc", "4", "jmin", "12", "jmax", "64",
			"s1", "16", "s2", "80", "s3", "24", "s4", "8",
			"h1", "101", "h2", "202", "h3", "303", "h4", "404",
		),
		commandEvent(
			harness.awg,
			"set", identity.InterfaceName,
			"peer", harness.publicKey,
			"preshared-key", harness.runner.secretPaths[1],
			"endpoint", harness.preparation.RelayEndpoint,
			"allowed-ips", "0.0.0.0/0",
		),
		commandEvent(
			harness.awg,
			"show", identity.InterfaceName, "listen-port",
		),
		commandEvent(
			harness.awg,
			"show", identity.InterfaceName, "latest-handshakes",
		),
		commandEvent(
			harness.awg,
			"show", identity.InterfaceName, "transfer",
		),
		commandEvent(
			harness.awg,
			"show", identity.InterfaceName, "endpoints",
		),
		commandEvent(
			harness.ip,
			"-4", "address", "add", identity.InnerAddress.String(),
			"dev", identity.InterfaceName,
		),
		commandEvent(
			harness.ip,
			"link", "set", "dev", identity.InterfaceName,
			"mtu", "1280",
		),
		commandEvent(
			harness.ip,
			"link", "set", "dev", identity.InterfaceName, "up",
		),
		commandEvent(
			harness.awg,
			"set", identity.InterfaceName,
			"peer", harness.publicKey,
			"persistent-keepalive", "25",
		),
		commandEvent(
			harness.ip,
			"-4", "route", "add", "0.0.0.0/0",
			"dev", identity.InterfaceName,
			"src", identity.InnerAddress.Addr().String(),
			"table", fmt.Sprint(identity.RouteTable),
		),
		commandEvent(
			harness.ip,
			"-4", "rule", "add",
			"priority", fmt.Sprint(identity.VerifyPriority),
			"fwmark", fmt.Sprintf("0x%x", identity.FirewallMark),
			"lookup", fmt.Sprint(identity.RouteTable),
		),
		"policy.prepare",
	}
	if events := harness.events.snapshot(); !slices.Equal(
		events, expectedPrepare,
	) {
		t.Fatalf(
			"prepare events:\n got: %s\nwant: %s",
			strings.Join(events, "\n"),
			strings.Join(expectedPrepare, "\n"),
		)
	}

	if err := session.VerifyProtectedDNS(
		context.Background(), harness.binding,
	); err != nil {
		t.Fatal(err)
	}
	if err := session.VerifyTunnelCanary(
		context.Background(), harness.binding,
	); err != nil {
		t.Fatal(err)
	}
	if harness.verifier.dnsCalls != 1 ||
		harness.verifier.canaryCalls != 1 ||
		harness.verifier.last.InterfaceName != identity.InterfaceName ||
		harness.verifier.last.FirewallMark != identity.FirewallMark ||
		!slices.Equal(
			harness.verifier.last.VerificationRoutes,
			harness.signed.VerificationRoutes,
		) {
		t.Fatalf("protected verifier = %#v", harness.verifier)
	}
	if err := session.Commit(
		context.Background(), harness.binding,
	); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if harness.policy.commitCount != 1 ||
		harness.policy.rollbackCount != 1 ||
		!harness.policy.killSwitch ||
		harness.process.stopCount() != 1 {
		t.Fatalf(
			"policy commits=%d rollbacks=%d kill=%t process stops=%d",
			harness.policy.commitCount,
			harness.policy.rollbackCount,
			harness.policy.killSwitch,
			harness.process.stopCount(),
		)
	}
	expectedTail := []string{
		commandEvent(
			harness.ip,
			"-4", "rule", "add",
			"priority", fmt.Sprint(identity.CommitPriority),
			"lookup", fmt.Sprint(identity.RouteTable),
		),
		"policy.commit",
		"policy.rollback",
		commandEvent(
			harness.ip,
			"-4", "rule", "del",
			"priority", fmt.Sprint(identity.CommitPriority),
			"lookup", fmt.Sprint(identity.RouteTable),
		),
		commandEvent(
			harness.ip,
			"-4", "rule", "del",
			"priority", fmt.Sprint(identity.VerifyPriority),
			"fwmark", fmt.Sprintf("0x%x", identity.FirewallMark),
			"lookup", fmt.Sprint(identity.RouteTable),
		),
		commandEvent(
			harness.ip,
			"-4", "route", "flush", "table",
			fmt.Sprint(identity.RouteTable),
		),
		commandEvent(
			harness.ip,
			"link", "delete", "dev", identity.InterfaceName,
		),
		"process.stop",
	}
	events := harness.events.snapshot()
	if !slices.Equal(events[len(expectedPrepare):], expectedTail) {
		t.Fatalf(
			"commit/close events:\n got: %s\nwant: %s",
			strings.Join(events[len(expectedPrepare):], "\n"),
			strings.Join(expectedTail, "\n"),
		)
	}
	select {
	case _, ok := <-session.Health():
		if ok {
			t.Fatal("normal close published a terminal error")
		}
	default:
		t.Fatal("normal close did not close session health")
	}
	harness.controller.portMu.Lock()
	leasedPortCount := len(harness.controller.leasedPorts)
	harness.controller.portMu.Unlock()
	if leasedPortCount != 0 {
		t.Fatalf("listen-port leases after close = %d", leasedPortCount)
	}
	harness.controller.addressMu.Lock()
	leasedAddressCount := len(harness.controller.leasedAddresses)
	harness.controller.addressMu.Unlock()
	if leasedAddressCount != 0 {
		t.Fatalf("inner-address leases after close = %d", leasedAddressCount)
	}
}

func TestLinuxSessionRefreshesExactPeerWithReacquiredPSK(t *testing.T) {
	harness := newLinuxHarness(t)
	prepared, err := harness.controller.Prepare(
		context.Background(), harness.preparation,
	)
	if err != nil {
		t.Fatal(err)
	}
	session := prepared.Session.(*linuxTunnelSession)
	defer session.Close()

	// The fake provider models a uniquely owned reacquisition by replenishing
	// the buffers that the initial Prepare correctly cleared.
	harness.keyProvider.private = bytes.Repeat([]byte{0x31}, 32)
	harness.keyProvider.psk = bytes.Repeat([]byte{0x42}, 32)
	before := len(harness.runner.commandsSnapshot())
	if err := session.RefreshAWGHandshake(
		context.Background(), harness.binding,
	); err != nil {
		t.Fatalf("RefreshAWGHandshake() error = %v", err)
	}
	commands := harness.runner.commandsSnapshot()
	if len(commands) != before+2 {
		t.Fatalf(
			"refresh command count = %d, want %d",
			len(commands)-before,
			2,
		)
	}
	identity := deriveLinuxCandidateIdentity(
		harness.binding, harness.signed.InnerAddressPool,
	)
	if got := commandEvent(
		commands[before].Path, commands[before].Args...,
	); got != commandEvent(
		harness.awg,
		"set", identity.InterfaceName,
		"peer", harness.publicKey,
		"remove",
	) {
		t.Fatalf("remove command = %s", got)
	}
	refreshPSKPath := commands[before+1].Args[5]
	if got := commandEvent(
		commands[before+1].Path, commands[before+1].Args...,
	); got != commandEvent(
		harness.awg,
		"set", identity.InterfaceName,
		"peer", harness.publicKey,
		"preshared-key", refreshPSKPath,
		"endpoint", harness.preparation.RelayEndpoint,
		"allowed-ips", "0.0.0.0/0",
		"persistent-keepalive", "25",
	) {
		t.Fatalf("re-add command = %s", got)
	}
	if _, err := os.Lstat(refreshPSKPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refresh PSK path still exists: %v", err)
	}
	if !allZero(harness.keyProvider.private) ||
		!allZero(harness.keyProvider.psk) {
		t.Fatal("reacquired key provider buffers were not cleared")
	}
	harness.assertNoSecretArguments(t)
}

func TestLinuxSessionRejectsChangedPSKBeforePeerRemoval(t *testing.T) {
	harness := newLinuxHarness(t)
	prepared, err := harness.controller.Prepare(
		context.Background(), harness.preparation,
	)
	if err != nil {
		t.Fatal(err)
	}
	session := prepared.Session.(*linuxTunnelSession)
	defer session.Close()
	harness.keyProvider.private = bytes.Repeat([]byte{0x31}, 32)
	harness.keyProvider.psk = bytes.Repeat([]byte{0x99}, 32)
	before := len(harness.runner.commandsSnapshot())
	if err := session.RefreshAWGHandshake(
		context.Background(), harness.binding,
	); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("RefreshAWGHandshake() error = %v", err)
	}
	if after := len(harness.runner.commandsSnapshot()); after != before {
		t.Fatalf(
			"changed PSK issued %d commands before rejection",
			after-before,
		)
	}
}

func TestLinuxControllerCapturesBaselineBeforeLinkActivation(t *testing.T) {
	harness := newLinuxHarness(t)
	harness.runner.nonZeroStatusAfterLinkUp = true
	prepared, err := harness.controller.Prepare(
		context.Background(), harness.preparation,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !prepared.Baseline.LatestHandshake.IsZero() ||
		prepared.Baseline.RxBytes != 0 ||
		prepared.Baseline.TxBytes != 0 {
		t.Fatalf("baseline = %#v", prepared.Baseline)
	}
	if err := prepared.Session.Close(); err != nil {
		t.Fatal(err)
	}
	identity := deriveLinuxCandidateIdentity(
		harness.binding, harness.signed.InnerAddressPool,
	)
	events := harness.events.snapshot()
	requireEventOrder(
		t,
		events,
		commandEvent(
			harness.awg,
			"show", identity.InterfaceName, "latest-handshakes",
		),
		commandEvent(
			harness.awg,
			"show", identity.InterfaceName, "transfer",
		),
		commandEvent(
			harness.awg,
			"show", identity.InterfaceName, "endpoints",
		),
		commandEvent(
			harness.ip,
			"link", "set", "dev", identity.InterfaceName, "up",
		),
	)
}

func TestLinuxControllerGenerationMismatchClearsKeysBeforeCommands(
	t *testing.T,
) {
	harness := newLinuxHarness(t)
	harness.keyProvider.generation++
	if _, err := harness.controller.Prepare(
		context.Background(), harness.preparation,
	); err == nil || !strings.Contains(err.Error(), "generation mismatch") {
		t.Fatalf("generation mismatch error = %v", err)
	}
	if !allZero(harness.keyProvider.private) ||
		!allZero(harness.keyProvider.psk) {
		t.Fatal("mismatched key buffers were not cleared")
	}
	if events := harness.events.snapshot(); len(events) != 0 {
		t.Fatalf("commands ran with mismatched keys: %v", events)
	}
}

func TestLinuxControllerResolvesCandidatePortHashCollision(
	t *testing.T,
) {
	harness := newLinuxHarness(t)
	harness.controller.config.Signed.ListenPortMax =
		harness.controller.config.Signed.ListenPortMin + 1
	firstIdentity := deriveLinuxCandidateIdentity(
		harness.binding, harness.signed.InnerAddressPool,
	)
	firstStart := candidateStartPort(
		firstIdentity, harness.controller.config.Signed,
	)
	secondBinding := harness.binding
	var secondIdentity linuxCandidateIdentity
	for counter := uint64(1); counter < 10_000; counter++ {
		secondBinding.AttemptID = fmt.Sprintf("%032x", counter)
		secondIdentity = deriveLinuxCandidateIdentity(
			secondBinding, harness.signed.InnerAddressPool,
		)
		if secondIdentity.InterfaceName != firstIdentity.InterfaceName &&
			candidateStartPort(
				secondIdentity, harness.controller.config.Signed,
			) == firstStart {
			break
		}
	}
	if secondIdentity.InterfaceName == "" ||
		candidateStartPort(
			secondIdentity, harness.controller.config.Signed,
		) != firstStart {
		t.Fatal("could not construct a listen-port hash collision")
	}
	firstPort, releaseFirst, err := harness.controller.reserveListenPort(
		firstIdentity,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseFirst()
	secondPort, releaseSecond, err := harness.controller.reserveListenPort(
		secondIdentity,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseSecond()
	if firstPort == secondPort ||
		firstPort != firstStart {
		t.Fatalf(
			"collision ports first=%d second=%d start=%d",
			firstPort, secondPort, firstStart,
		)
	}
	if _, _, err := harness.controller.reserveListenPort(
		linuxCandidateIdentity{PortSeed: firstIdentity.PortSeed},
	); err == nil || !strings.Contains(err.Error(), "no available port") {
		t.Fatalf("exhausted range error = %v", err)
	}
	releaseFirst()
	reusedPort, releaseReused, err := harness.controller.reserveListenPort(
		linuxCandidateIdentity{PortSeed: firstIdentity.PortSeed},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseReused()
	if reusedPort != firstPort {
		t.Fatalf("released port=%d reused=%d", firstPort, reusedPort)
	}
}

func TestLinuxControllerSkipsExternallyOccupiedListenPort(t *testing.T) {
	harness := newLinuxHarness(t)
	identity := deriveLinuxCandidateIdentity(
		harness.binding, harness.signed.InnerAddressPool,
	)
	start := candidateStartPort(identity, harness.signed)
	harness.controller.config.ListenPortAvailable = func(port uint16) bool {
		return port != start
	}
	port, release, err := harness.controller.reserveListenPort(identity)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if port == start {
		t.Fatalf("occupied start port %d was leased", start)
	}
}

func TestLinuxControllerPartialRouteFailureStrictlyCleansUp(
	t *testing.T,
) {
	harness := newLinuxHarness(t)
	harness.runner.failContains = "|route|add|0.0.0.0/0|"
	if _, err := harness.controller.Prepare(
		context.Background(), harness.preparation,
	); err == nil || !strings.Contains(err.Error(), "route table") {
		t.Fatalf("route failure error = %v", err)
	}
	if harness.process.stopCount() != 1 {
		t.Fatalf("process stop count = %d", harness.process.stopCount())
	}
	identity := deriveLinuxCandidateIdentity(
		harness.binding, harness.signed.InnerAddressPool,
	)
	events := harness.events.snapshot()
	requireEventOrder(t, events,
		commandEvent(
			harness.ip,
			"-4", "route", "add", "0.0.0.0/0",
			"dev", identity.InterfaceName,
			"src", identity.InnerAddress.Addr().String(),
			"table", fmt.Sprint(identity.RouteTable),
		),
		commandEvent(
			harness.ip,
			"-4", "route", "flush", "table",
			fmt.Sprint(identity.RouteTable),
		),
		commandEvent(
			harness.ip,
			"link", "delete", "dev", identity.InterfaceName,
		),
		"process.stop",
	)
	if harness.policy.prepareCount != 0 {
		t.Fatal("policy was prepared after route failure")
	}
	if !allZero(harness.keyProvider.private) ||
		!allZero(harness.keyProvider.psk) {
		t.Fatal("key buffers survived partial failure")
	}
	for _, path := range harness.runner.secretPaths {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("secret path survived partial failure: %s", path)
		}
	}
	harness.controller.portMu.Lock()
	leasedPortCount := len(harness.controller.leasedPorts)
	harness.controller.portMu.Unlock()
	harness.controller.addressMu.Lock()
	leasedAddressCount := len(harness.controller.leasedAddresses)
	harness.controller.addressMu.Unlock()
	if leasedPortCount != 0 || leasedAddressCount != 0 {
		t.Fatalf(
			"leases survived partial failure: ports=%d addresses=%d",
			leasedPortCount, leasedAddressCount,
		)
	}
}

func TestLinuxSessionHealthFailureAutomaticallyRollsBackOnce(
	t *testing.T,
) {
	harness := newLinuxHarness(t)
	prepared, err := harness.controller.Prepare(
		context.Background(), harness.preparation,
	)
	if err != nil {
		t.Fatal(err)
	}
	session := prepared.Session.(*linuxTunnelSession)
	if err := session.Commit(
		context.Background(), harness.binding,
	); err != nil {
		t.Fatal(err)
	}
	harness.policy.fail(errors.New("resolver monitor failed"))
	select {
	case err, ok := <-session.Health():
		if !ok || err == nil ||
			!strings.Contains(err.Error(), "resolver monitor failed") {
			t.Fatalf("terminal health = %v, open=%t", err, ok)
		}
	case <-time.After(time.Second):
		t.Fatal("session health failure was not published")
	}
	select {
	case _, ok := <-session.Health():
		if ok {
			t.Fatal("session health published more than one error")
		}
	case <-time.After(time.Second):
		t.Fatal("session health did not close after terminal error")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		_, rollbackCount, _ := harness.policy.snapshot()
		if rollbackCount == 1 &&
			harness.process.stopCount() == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	_, rollbackCount, killSwitch := harness.policy.snapshot()
	if rollbackCount != 1 ||
		!killSwitch ||
		harness.process.stopCount() != 1 {
		t.Fatalf(
			"health cleanup rollbacks=%d kill=%t stops=%d",
			rollbackCount,
			killSwitch,
			harness.process.stopCount(),
		)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	_, rollbackCount, _ = harness.policy.snapshot()
	if rollbackCount != 1 ||
		harness.process.stopCount() != 1 {
		t.Fatal("health cleanup was not idempotent")
	}
}

func TestNewLinuxControllerUnsupportedOffLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux constructor is supported on this platform")
	}
	if controller, err := NewLinuxController(
		LinuxControllerConfig{},
	); controller != nil || !errors.Is(err, ErrLinuxControllerUnsupported) {
		t.Fatalf("controller=%T error=%v", controller, err)
	}
}

type linuxHarness struct {
	controller  *linuxController
	binding     connectivity.Binding
	preparation Preparation
	signed      LinuxSignedInterfaceConfig
	publicKey   string
	keyProvider *fakeLinuxKeyProvider
	verifier    *fakeLinuxVerifier
	policy      *fakeLinuxPolicy
	runner      *fakeLinuxRunner
	process     *fakeLinuxProcess
	events      *linuxEventLog
	awgGo       string
	awg         string
	ip          string
}

func newLinuxHarness(t *testing.T) *linuxHarness {
	t.Helper()
	root := t.TempDir()
	executable := func(name string) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	now := time.Now().UTC()
	binding := connectivity.Binding{
		AttemptID:      strings.Repeat("1", 32),
		Profile:        "default",
		Mode:           connectivity.ModeAuto,
		ManifestDigest: strings.Repeat("a", 64),
		CandidateID:    "raw-atl-1",
		NodeID:         "entry-atl",
		SessionID:      strings.Repeat("2", 32),
		PSKGeneration:  17,
		SequenceEpoch:  3,
		Nonce:          strings.Repeat("3", 32),
		ExpiresAt:      now.Add(time.Minute),
	}
	publicKey := base64.StdEncoding.EncodeToString(
		bytes.Repeat([]byte{0x73}, 32),
	)
	signed := LinuxSignedInterfaceConfig{
		InnerAddressPool: netip.MustParsePrefix("10.203.0.0/24"),
		AllowedIPs: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
		},
		VerificationRoutes: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.53/32"),
			netip.MustParsePrefix("203.0.113.1/32"),
		},
		MTU:                 1280,
		ListenPortMin:       51820,
		ListenPortMax:       51831,
		PersistentKeepalive: 25,
		Obfuscation: AWGObfuscation{
			JC: 4, JMin: 12, JMax: 64,
			S1: 16, S2: 80, S3: 24, S4: 8,
			H1: 101, H2: 202, H3: 303, H4: 404,
		},
	}
	events := &linuxEventLog{}
	process := newFakeLinuxProcess(events)
	runner := &fakeLinuxRunner{
		events:         events,
		process:        process,
		statusKey:      publicKey,
		statusEndpoint: "127.0.0.1:49201",
	}
	keyProvider := &fakeLinuxKeyProvider{
		generation: binding.PSKGeneration,
		private:    bytes.Repeat([]byte{0x31}, 32),
		psk:        bytes.Repeat([]byte{0x42}, 32),
	}
	verifier := &fakeLinuxVerifier{}
	policy := newFakeLinuxPolicy(events)
	awgGo := executable("amneziawg-go")
	awg := executable("awg")
	ip := executable("ip")
	controller, err := newLinuxController(LinuxControllerConfig{
		AWGGoBinary:         awgGo,
		AWGBinary:           awg,
		IPBinary:            ip,
		TempRoot:            root,
		Signed:              signed,
		KeyProvider:         keyProvider,
		Verifier:            verifier,
		PolicyFactory:       policy,
		Runner:              runner,
		StartupPollInterval: time.Millisecond,
		StopTimeout:         100 * time.Millisecond,
		ListenPortAvailable: func(uint16) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	return &linuxHarness{
		controller: controller,
		binding:    binding,
		preparation: Preparation{
			Binding:          binding,
			RelayEndpoint:    "127.0.0.1:49201",
			GatewayEndpoint:  "198.51.100.8:51820",
			GatewayPublicKey: publicKey,
			MinInnerDatagram: 1200,
			MaxInnerDatagram: 1350,
		},
		signed:      signed,
		publicKey:   publicKey,
		keyProvider: keyProvider,
		verifier:    verifier,
		policy:      policy,
		runner:      runner,
		process:     process,
		events:      events,
		awgGo:       awgGo,
		awg:         awg,
		ip:          ip,
	}
}

func (harness *linuxHarness) assertNoSecretArguments(t *testing.T) {
	t.Helper()
	privateEncoded := base64.StdEncoding.EncodeToString(
		bytes.Repeat([]byte{0x31}, 32),
	)
	pskEncoded := base64.StdEncoding.EncodeToString(
		bytes.Repeat([]byte{0x42}, 32),
	)
	for _, command := range harness.runner.commandsSnapshot() {
		arguments := strings.Join(command.Args, "\x00")
		if strings.Contains(arguments, privateEncoded) ||
			strings.Contains(arguments, pskEncoded) {
			t.Fatalf("secret appeared in argv: %#v", command.Args)
		}
	}
}

type fakeLinuxKeyProvider struct {
	generation uint64
	private    []byte
	psk        []byte
}

func (provider *fakeLinuxKeyProvider) KeyMaterial(
	context.Context,
	connectivity.Binding,
) (LinuxKeyMaterial, error) {
	return LinuxKeyMaterial{
		Generation: provider.generation,
		PrivateKey: provider.private,
		PSK:        provider.psk,
	}, nil
}

type fakeLinuxVerifier struct {
	mu          sync.Mutex
	dnsCalls    int
	canaryCalls int
	last        LinuxProbeContext
}

func (verifier *fakeLinuxVerifier) VerifyProtectedDNS(
	_ context.Context,
	probe LinuxProbeContext,
) error {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	verifier.dnsCalls++
	verifier.last = probe
	return nil
}

func (verifier *fakeLinuxVerifier) VerifyTunnelCanary(
	_ context.Context,
	probe LinuxProbeContext,
) error {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	verifier.canaryCalls++
	verifier.last = probe
	return nil
}

const fakeLinuxPolicyUnderlayMark = 0x9977

type fakeLinuxPolicy struct {
	events *linuxEventLog
	health chan error

	mu            sync.Mutex
	prepareCount  int
	commitCount   int
	rollbackCount int
	killSwitch    bool
	healthOnce    sync.Once
}

func newFakeLinuxPolicy(events *linuxEventLog) *fakeLinuxPolicy {
	return &fakeLinuxPolicy{
		events: events,
		health: make(chan error, 1),
	}
}

func (policy *fakeLinuxPolicy) Prepare(
	_ context.Context,
	_ LinuxPolicySpec,
) (LinuxPolicyTransaction, error) {
	policy.mu.Lock()
	policy.prepareCount++
	policy.killSwitch = true
	policy.mu.Unlock()
	policy.events.add("policy.prepare")
	return policy, nil
}

func (policy *fakeLinuxPolicy) Commit(context.Context) error {
	policy.mu.Lock()
	policy.commitCount++
	policy.killSwitch = false
	policy.mu.Unlock()
	policy.events.add("policy.commit")
	return nil
}

func (policy *fakeLinuxPolicy) Rollback(context.Context) error {
	policy.mu.Lock()
	policy.rollbackCount++
	policy.killSwitch = true
	policy.mu.Unlock()
	policy.events.add("policy.rollback")
	return nil
}

func (policy *fakeLinuxPolicy) Health() <-chan error {
	return policy.health
}

func (*fakeLinuxPolicy) UnderlayMark() uint32 {
	return fakeLinuxPolicyUnderlayMark
}

func (policy *fakeLinuxPolicy) fail(err error) {
	policy.healthOnce.Do(func() {
		policy.health <- err
		close(policy.health)
	})
}

func (policy *fakeLinuxPolicy) snapshot() (int, int, bool) {
	policy.mu.Lock()
	defer policy.mu.Unlock()
	return policy.commitCount, policy.rollbackCount, policy.killSwitch
}

type fakeLinuxRunner struct {
	events         *linuxEventLog
	process        *fakeLinuxProcess
	statusKey      string
	statusEndpoint string

	mu           sync.Mutex
	commands     []LinuxCommand
	privateKey   []byte
	psk          []byte
	secretPaths  []string
	failContains string
	failed       bool
	listenPort   string
	linkUp       bool

	nonZeroStatusAfterLinkUp bool
}

func (runner *fakeLinuxRunner) Start(
	command LinuxCommand,
) (LinuxManagedProcess, error) {
	runner.record(command)
	return runner.process, nil
}

func (runner *fakeLinuxRunner) Run(
	_ context.Context,
	command LinuxCommand,
) (LinuxCommandResult, error) {
	runner.record(command)
	event := commandEvent(command.Path, command.Args...)
	runner.mu.Lock()
	fail := runner.failContains != "" && !runner.failed &&
		strings.Contains(event, runner.failContains)
	if fail {
		runner.failed = true
	}
	runner.mu.Unlock()
	if fail {
		return LinuxCommandResult{}, errors.New("injected command failure")
	}
	if index := slices.Index(command.Args, "private-key"); index >= 0 {
		if err := runner.captureSecret(command.Args[index+1], true); err != nil {
			return LinuxCommandResult{}, err
		}
	}
	if index := slices.Index(command.Args, "preshared-key"); index >= 0 {
		if err := runner.captureSecret(command.Args[index+1], false); err != nil {
			return LinuxCommandResult{}, err
		}
	}
	if index := slices.Index(command.Args, "listen-port"); index >= 0 &&
		command.Args[0] == "set" {
		runner.mu.Lock()
		runner.listenPort = command.Args[index+1]
		runner.mu.Unlock()
	}
	if len(command.Args) == 5 &&
		command.Args[0] == "link" &&
		command.Args[1] == "set" &&
		command.Args[2] == "dev" &&
		command.Args[4] == "up" {
		runner.mu.Lock()
		runner.linkUp = true
		runner.mu.Unlock()
	}
	if len(command.Args) == 3 && command.Args[0] == "show" {
		switch command.Args[2] {
		case "listen-port":
			runner.mu.Lock()
			listenPort := runner.listenPort
			runner.mu.Unlock()
			return LinuxCommandResult{
				Stdout: []byte(listenPort + "\n"),
			}, nil
		case "latest-handshakes":
			runner.mu.Lock()
			nonZero := runner.nonZeroStatusAfterLinkUp && runner.linkUp
			runner.mu.Unlock()
			seconds := "0"
			if nonZero {
				seconds = "1"
			}
			return LinuxCommandResult{
				Stdout: []byte(runner.statusKey + "\t" + seconds + "\n"),
			}, nil
		case "transfer":
			runner.mu.Lock()
			nonZero := runner.nonZeroStatusAfterLinkUp && runner.linkUp
			runner.mu.Unlock()
			counters := "\t0\t0\n"
			if nonZero {
				counters = "\t1\t1\n"
			}
			return LinuxCommandResult{
				Stdout: []byte(runner.statusKey + counters),
			}, nil
		case "endpoints":
			return LinuxCommandResult{
				Stdout: []byte(
					runner.statusKey + "\t" + runner.statusEndpoint + "\n",
				),
			}, nil
		}
	}
	return LinuxCommandResult{}, nil
}

func (runner *fakeLinuxRunner) record(command LinuxCommand) {
	cloned := LinuxCommand{
		Path: command.Path,
		Args: slices.Clone(command.Args),
	}
	runner.mu.Lock()
	runner.commands = append(runner.commands, cloned)
	runner.mu.Unlock()
	runner.events.add(commandEvent(cloned.Path, cloned.Args...))
}

func (runner *fakeLinuxRunner) captureSecret(
	path string,
	private bool,
) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return fmt.Errorf("secret file mode = %s", info.Mode())
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return err
	}
	if !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 ||
		parent.Mode().Perm() != 0o700 {
		return fmt.Errorf("secret directory mode = %s", parent.Mode())
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(
		strings.TrimSpace(string(encoded)),
	)
	clear(encoded)
	if err != nil {
		return err
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if private {
		runner.privateKey = decoded
	} else {
		runner.psk = decoded
	}
	runner.secretPaths = append(runner.secretPaths, path)
	return nil
}

func (runner *fakeLinuxRunner) commandsSnapshot() []LinuxCommand {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	result := make([]LinuxCommand, len(runner.commands))
	for index, command := range runner.commands {
		result[index] = LinuxCommand{
			Path: command.Path,
			Args: slices.Clone(command.Args),
		}
	}
	return result
}

type fakeLinuxProcess struct {
	events *linuxEventLog
	exited chan struct{}

	mu       sync.Mutex
	err      error
	stops    int
	exitOnce sync.Once
}

func newFakeLinuxProcess(events *linuxEventLog) *fakeLinuxProcess {
	return &fakeLinuxProcess{
		events: events,
		exited: make(chan struct{}),
	}
}

func (process *fakeLinuxProcess) Exited() <-chan struct{} {
	return process.exited
}

func (process *fakeLinuxProcess) Err() error {
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.err
}

func (process *fakeLinuxProcess) Stop(context.Context) error {
	process.mu.Lock()
	process.stops++
	process.mu.Unlock()
	process.events.add("process.stop")
	process.exit(nil)
	return nil
}

func (process *fakeLinuxProcess) exit(err error) {
	process.exitOnce.Do(func() {
		process.mu.Lock()
		process.err = err
		process.mu.Unlock()
		close(process.exited)
	})
}

func (process *fakeLinuxProcess) stopCount() int {
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.stops
}

type linuxEventLog struct {
	mu     sync.Mutex
	events []string
}

func (log *linuxEventLog) add(event string) {
	log.mu.Lock()
	log.events = append(log.events, event)
	log.mu.Unlock()
}

func (log *linuxEventLog) snapshot() []string {
	log.mu.Lock()
	defer log.mu.Unlock()
	return slices.Clone(log.events)
}

func commandEvent(path string, args ...string) string {
	parts := append([]string{filepath.Base(path)}, args...)
	return strings.Join(parts, "|")
}

func candidateStartPort(
	identity linuxCandidateIdentity,
	signed LinuxSignedInterfaceConfig,
) uint16 {
	count := uint32(signed.ListenPortMax) -
		uint32(signed.ListenPortMin) + 1
	return uint16(
		uint32(signed.ListenPortMin) +
			uint32(identity.PortSeed)%count,
	)
}

func requireEventOrder(t *testing.T, events []string, ordered ...string) {
	t.Helper()
	cursor := 0
	for _, event := range events {
		if cursor < len(ordered) && event == ordered[cursor] {
			cursor++
		}
	}
	if cursor != len(ordered) {
		t.Fatalf(
			"events missing ordered suffix at %d:\n%s",
			cursor,
			strings.Join(events, "\n"),
		)
	}
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}
