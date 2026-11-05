package h3candidate

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/directawg"
	"winsvpn.local/winnprotocol/internal/wcf3"
)

func TestLinuxProtectedUnderlayBindsFixedPathAndMigration(t *testing.T) {
	opener := &recordingProtectedPacketOpener{}
	inspector := &controllableInterfaceInspector{}
	var dialCalls atomic.Int32
	factory, err := newLinuxProtectedUnderlayFactory(
		LinuxProtectedUnderlayConfig{
			InterfaceName:    "eth0",
			FirewallMark:     0x57494e4e,
			ServerName:       "cover.example",
			RemoteEndpoint:   "198.51.100.20:443",
			SessionExpiresAt: testNow.Add(time.Minute),
			HealthInterval:   100 * time.Millisecond,
		},
		opener,
		inspector,
		func(
			context.Context,
			net.PacketConn,
			*net.UDPAddr,
			*tls.Config,
			*quic.Config,
		) (*quic.Conn, *quic.Transport, error) {
			dialCalls.Add(1)
			return nil, nil, errors.New("synthetic QUIC failure")
		},
		func() time.Time { return testNow },
	)
	if err != nil {
		t.Fatalf("newLinuxProtectedUnderlayFactory() error = %v", err)
	}
	raw, err := factory.Open(context.Background(), validBinding())
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	underlay := raw.(*linuxProtectedUnderlay)
	t.Cleanup(func() {
		_ = underlay.Close(context.Background())
	})
	tlsConfig := &tls.Config{
		ServerName: "cover.example",
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}
	quicConfig := &quic.Config{Allow0RTT: false}

	if _, _, err := underlay.DialQUICPath(
		context.Background(),
		"other.example:443",
		tlsConfig,
		quicConfig,
	); err == nil || !strings.Contains(err.Error(), "fixed path") {
		t.Fatalf("wrong authority error = %v", err)
	}
	if got := opener.opens.Load(); got != 0 {
		t.Fatalf("socket opened for wrong authority: %d", got)
	}
	if _, _, err := underlay.DialQUICPath(
		context.Background(),
		"cover.example:443",
		tlsConfig,
		quicConfig,
	); err == nil || !strings.Contains(err.Error(), "synthetic QUIC") {
		t.Fatalf("protected QUIC error = %v", err)
	}
	if got := opener.opens.Load(); got != 1 {
		t.Fatalf("protected opens = %d, want 1", got)
	}
	if got := dialCalls.Load(); got != 1 {
		t.Fatalf("QUIC calls = %d, want 1", got)
	}
	if opener.lastInterface != "eth0" ||
		opener.lastMark != 0x57494e4e ||
		opener.lastNetwork != "udp4" {
		t.Fatalf(
			"socket protection = %q/%x/%q",
			opener.lastInterface, opener.lastMark, opener.lastNetwork,
		)
	}
	if _, _, err := underlay.DialQUICPath(
		context.Background(),
		"cover.example:443",
		tlsConfig,
		quicConfig,
	); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("second QUIC dial error = %v", err)
	}

	replacement := &fakePacketConn{}
	if err := underlay.ProtectMigrationSocket(
		context.Background(), validBinding(), replacement,
	); err != nil {
		t.Fatalf("ProtectMigrationSocket() error = %v", err)
	}
	if got := opener.protects.Load(); got != 1 {
		t.Fatalf("migration protections = %d, want 1", got)
	}
	mismatch := validBinding()
	mismatch.Nonce = strings.Repeat("e", 32)
	if err := underlay.ProtectMigrationSocket(
		context.Background(), mismatch, &fakePacketConn{},
	); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("mismatched migration error = %v", err)
	}
	if got := opener.protects.Load(); got != 1 {
		t.Fatalf("mismatched socket was protected: count %d", got)
	}
}

func TestLinuxProtectedUnderlayPreparesThenClaimsExactlyOneBinding(
	t *testing.T,
) {
	opener := &recordingProtectedPacketOpener{}
	factory, err := newLinuxProtectedUnderlayFactory(
		LinuxProtectedUnderlayConfig{
			InterfaceName:    "eth0",
			FirewallMark:     0x57494e4e,
			ServerName:       "cover.example",
			RemoteEndpoint:   "198.51.100.20:443",
			SessionExpiresAt: testNow.Add(time.Minute),
			HealthInterval:   100 * time.Millisecond,
		},
		opener,
		&controllableInterfaceInspector{},
		failingQUICDial,
		func() time.Time { return testNow },
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := factory.Prepare(
		context.Background(), testNow.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	underlay := raw.(*linuxProtectedUnderlay)
	t.Cleanup(func() {
		_ = underlay.Close(context.Background())
	})
	if err := underlay.ProtectMigrationSocket(
		context.Background(), validBinding(), &fakePacketConn{},
	); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("unclaimed migration error = %v", err)
	}
	if opener.protects.Load() != 0 {
		t.Fatal("unclaimed prepared underlay protected a migration socket")
	}
	binding := validBinding()
	if err := underlay.Claim(binding); err != nil {
		t.Fatal(err)
	}
	if err := underlay.Claim(binding); err == nil {
		t.Fatal("prepared underlay accepted a second claim")
	}
	if err := underlay.ProtectMigrationSocket(
		context.Background(), binding, &fakePacketConn{},
	); err != nil {
		t.Fatal(err)
	}
	if opener.protects.Load() != 1 {
		t.Fatal("claimed underlay did not protect migration socket")
	}
}

func TestLinuxPreparedH3RaceUsesTwoDistinctProtectedSockets(t *testing.T) {
	opener := &multiRecordingProtectedPacketOpener{}
	factory, err := newLinuxProtectedUnderlayFactory(
		LinuxProtectedUnderlayConfig{
			InterfaceName:    "eth0",
			FirewallMark:     0x57494e4e,
			ServerName:       "cover.example",
			RemoteEndpoint:   "198.51.100.20:443",
			SessionExpiresAt: testNow.Add(time.Minute),
			HealthInterval:   100 * time.Millisecond,
		},
		opener,
		&controllableInterfaceInspector{},
		failingQUICDial,
		func() time.Time { return testNow },
	)
	if err != nil {
		t.Fatal(err)
	}
	underlays := make([]PreparedProtectedUnderlay, 2)
	for index := range underlays {
		underlays[index], err = factory.Prepare(
			context.Background(),
			testNow.Add(time.Minute),
		)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = underlays[index].Close(context.Background())
		})
	}
	tlsConfig := &tls.Config{
		ServerName: "cover.example",
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}
	quicConfig := &quic.Config{Allow0RTT: false}
	for _, underlay := range underlays {
		if _, _, dialErr := underlay.DialQUICPath(
			context.Background(),
			"cover.example:443",
			tlsConfig,
			quicConfig,
		); dialErr == nil {
			t.Fatal("synthetic raced QUIC path unexpectedly succeeded")
		}
	}
	records := opener.Records()
	if len(records) != 2 || records[0].socket == records[1].socket {
		t.Fatalf("protected socket records = %#v, want two distinct sockets", records)
	}
	for index, record := range records {
		if record.network != "udp4" ||
			record.interfaceName != "eth0" ||
			record.mark != 0x57494e4e {
			t.Fatalf("socket %d protection = %#v", index, record)
		}
		if closes := record.socket.closes.Load(); closes != 1 {
			t.Fatalf("failed raced socket %d closes = %d, want 1", index, closes)
		}
	}
	if err := underlays[0].Claim(validBinding()); err != nil {
		t.Fatal(err)
	}
	if err := underlays[1].ProtectMigrationSocket(
		context.Background(),
		validBinding(),
		&fakePacketConn{},
	); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("unclaimed loser migration error = %v", err)
	}
}

func TestLinuxProtectedUnderlayHealthAndValidationFailClosed(t *testing.T) {
	valid := LinuxProtectedUnderlayConfig{
		InterfaceName:    "eth0",
		FirewallMark:     7,
		ServerName:       "cover.example",
		RemoteEndpoint:   "2001:db8::1",
		SessionExpiresAt: testNow.Add(time.Minute),
		HealthInterval:   100 * time.Millisecond,
	}
	tests := []struct {
		name   string
		mutate func(*LinuxProtectedUnderlayConfig)
	}{
		{"missing session expiry", func(config *LinuxProtectedUnderlayConfig) {
			config.SessionExpiresAt = time.Time{}
		}},
		{"zero mark", func(config *LinuxProtectedUnderlayConfig) {
			config.FirewallMark = 0
		}},
		{"hostname endpoint", func(config *LinuxProtectedUnderlayConfig) {
			config.RemoteEndpoint = "cover.example:443"
		}},
		{"bad server name", func(config *LinuxProtectedUnderlayConfig) {
			config.ServerName = "LOCALHOST"
		}},
		{"fast health", func(config *LinuxProtectedUnderlayConfig) {
			config.HealthInterval = time.Millisecond
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if _, err := newLinuxProtectedUnderlayFactory(
				config,
				&recordingProtectedPacketOpener{},
				&controllableInterfaceInspector{},
				failingQUICDial,
				func() time.Time { return testNow },
			); err == nil {
				t.Fatal("invalid underlay configuration was accepted")
			}
		})
	}

	inspector := &controllableInterfaceInspector{}
	factory, err := newLinuxProtectedUnderlayFactory(
		LinuxProtectedUnderlayConfig{
			InterfaceName:    "eth0",
			FirewallMark:     7,
			ServerName:       "cover.example",
			RemoteEndpoint:   "[2001:db8::1]:443",
			SessionExpiresAt: testNow.Add(time.Minute),
			HealthInterval:   100 * time.Millisecond,
		},
		&recordingProtectedPacketOpener{},
		inspector,
		failingQUICDial,
		func() time.Time { return testNow },
	)
	if err != nil {
		t.Fatalf("newLinuxProtectedUnderlayFactory() error = %v", err)
	}
	raw, err := factory.Open(context.Background(), validBinding())
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	underlay := raw.(*linuxProtectedUnderlay)
	inspector.setError(errors.New("link down"))
	select {
	case err, ok := <-underlay.Health():
		if !ok || err == nil || !strings.Contains(err.Error(), "link down") {
			t.Fatalf("health result = (%v, %v)", err, ok)
		}
	case <-time.After(time.Second):
		t.Fatal("interface failure was not published")
	}
	if err := underlay.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestLinuxAWGOverH3PredicatesAndTransactionUseRealSession(t *testing.T) {
	direct := newAdapterDirectSession()
	controller := &adapterDirectController{
		session:   direct,
		publicKey: adapterPublicKey(),
	}
	rawController, err := NewLinuxAWGOverH3Controller(
		validLinuxAWGOverH3Config(controller),
	)
	if err != nil {
		t.Fatalf("NewLinuxAWGOverH3Controller() error = %v", err)
	}
	binding := validBinding()
	frameContext, err := wcf3.ContextFromBinding(binding, testNow)
	if err != nil {
		t.Fatalf("ContextFromBinding() error = %v", err)
	}
	path := newBlockingAdapterPacketConn()
	rawSession, err := rawController.Start(
		context.Background(), path, binding, frameContext,
	)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	session := rawSession.(*linuxAWGOverH3Session)
	t.Cleanup(func() {
		_ = session.Close(context.Background())
		_ = path.Close()
	})
	if controller.preparation.Binding != binding ||
		controller.preparation.GatewayEndpoint != "198.51.100.40:51820" ||
		controller.preparation.GatewayPublicKey != adapterPublicKey() {
		t.Fatalf("DirectAWG preparation = %#v", controller.preparation)
	}

	direct.setStatus(directawg.Status{
		PeerPublicKey:   adapterPublicKey(),
		PeerEndpoint:    controller.preparation.RelayEndpoint,
		LatestHandshake: testNow,
		RxBytes:         10,
		TxBytes:         11,
	})
	if err := session.FreshAWGHandshake(
		context.Background(), binding, frameContext,
	); err != nil {
		t.Fatalf("FreshAWGHandshake() error = %v", err)
	}
	if err := session.VerifyBidirectional(
		context.Background(), binding, frameContext,
	); err != nil {
		t.Fatalf("VerifyBidirectional() error = %v", err)
	}
	verifier := NewLinuxCandidateVerifierAdapter()
	if err := verifier.VerifyProtectedDNS(
		context.Background(), session, binding, frameContext,
	); err != nil {
		t.Fatalf("VerifyProtectedDNS() error = %v", err)
	}
	if err := verifier.VerifyTunnelCanary(
		context.Background(), session, binding, frameContext,
	); err != nil {
		t.Fatalf("VerifyTunnelCanary() error = %v", err)
	}
	if direct.dnsCalls.Load() != 1 || direct.canaryCalls.Load() != 1 {
		t.Fatalf(
			"direct verifier calls = %d/%d",
			direct.dnsCalls.Load(), direct.canaryCalls.Load(),
		)
	}

	transaction, err := NewLinuxRouteDNSTransactionFactory().Prepare(
		context.Background(), session, binding, frameContext,
	)
	if err != nil {
		t.Fatalf("transaction Prepare() error = %v", err)
	}
	if got := direct.commitCalls.Load(); got != 0 {
		t.Fatalf("route/DNS committed during prepare: %d", got)
	}
	if err := transaction.Commit(
		context.Background(), binding, frameContext,
	); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	if err := transaction.Commit(
		context.Background(), binding, frameContext,
	); err != nil {
		t.Fatalf("second Commit() error = %v", err)
	}
	if got := direct.commitCalls.Load(); got != 1 {
		t.Fatalf("direct commit calls = %d, want 1", got)
	}
	if err := transaction.Rollback(context.Background()); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	if err := transaction.Rollback(context.Background()); err != nil {
		t.Fatalf("second Rollback() error = %v", err)
	}
	if got := direct.closeCalls.Load(); got != 1 {
		t.Fatalf("direct close calls after rollback = %d, want 1", got)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("session Close() error = %v", err)
	}
	if got := direct.closeCalls.Load(); got != 2 {
		t.Fatalf("direct Close invocations = %d, want 2 idempotent calls", got)
	}
	if got := path.closeCalls.Load(); got != 0 {
		t.Fatalf("session closed caller-owned carrier path %d times", got)
	}
}

func TestLinuxAWGOverH3ConfigurationFailsClosed(t *testing.T) {
	controller := &adapterDirectController{
		session: newAdapterDirectSession(), publicKey: adapterPublicKey(),
	}
	tests := []struct {
		name   string
		mutate func(*LinuxAWGOverH3Config)
	}{
		{"missing controller", func(config *LinuxAWGOverH3Config) {
			config.Controller = nil
		}},
		{"hostname backend", func(config *LinuxAWGOverH3Config) {
			config.GatewayEndpoint = "vpn.example:51820"
		}},
		{"zero public key", func(config *LinuxAWGOverH3Config) {
			config.GatewayPublicKey = base64.StdEncoding.EncodeToString(
				make([]byte, 32),
			)
		}},
		{"non-loopback relay", func(config *LinuxAWGOverH3Config) {
			config.LocalRelayAddress = "192.0.2.10:0"
		}},
		{"small datagram", func(config *LinuxAWGOverH3Config) {
			config.MinInnerDatagram = 575
		}},
		{"fast polling", func(config *LinuxAWGOverH3Config) {
			config.PollInterval = time.Microsecond
		}},
		{"oversize batch", func(config *LinuxAWGOverH3Config) {
			config.RelayBatchSize = 129
		}},
		{"raw buffer request", func(config *LinuxAWGOverH3Config) {
			config.SocketBufferBytes = 4096
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validLinuxAWGOverH3Config(controller)
			test.mutate(&config)
			if _, err := NewLinuxAWGOverH3Controller(config); err == nil {
				t.Fatal("invalid AWG-over-H3 configuration was accepted")
			}
		})
	}
}

func TestLinuxAdaptersDriveCandidateEndToEnd(t *testing.T) {
	direct := newAdapterDirectSession()
	directController := &adapterDirectController{
		session: direct, publicKey: adapterPublicKey(),
	}
	tunnel, err := NewLinuxAWGOverH3Controller(
		validLinuxAWGOverH3Config(directController),
	)
	if err != nil {
		t.Fatal(err)
	}
	path := newBlockingAdapterPacketConn()
	candidate, err := newCandidate(
		validDescriptor(),
		func(
			context.Context,
			connectivity.Binding,
			ProtectedUnderlay,
		) (net.PacketConn, error) {
			return path, nil
		},
		nil,
		tunnel,
		NewLinuxCandidateVerifierAdapter(),
		NewLinuxRouteDNSTransactionFactory(),
		func() time.Time { return testNow },
		DefaultTeardownTimeout,
	)
	if err != nil {
		t.Fatalf("newCandidate() error = %v", err)
	}
	binding := validBinding()
	connection, err := candidate.Dial(context.Background(), binding)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	direct.setStatus(directawg.Status{
		PeerPublicKey:   adapterPublicKey(),
		PeerEndpoint:    directController.preparation.RelayEndpoint,
		LatestHandshake: testNow,
		RxBytes:         20,
		TxBytes:         21,
	})
	operations := []func(context.Context, connectivity.Binding) error{
		connection.FreshAWGHandshake,
		connection.VerifyBidirectional,
		connection.VerifyProtectedDNS,
		connection.VerifyTunnelCanary,
		connection.Commit,
	}
	for index, operation := range operations {
		if err := operation(context.Background(), binding); err != nil {
			t.Fatalf("candidate operation %d error = %v", index, err)
		}
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("candidate Close() error = %v", err)
	}
	if got := path.closeCalls.Load(); got != 1 {
		t.Fatalf("candidate carrier closes = %d, want 1", got)
	}
	if got := direct.commitCalls.Load(); got != 1 {
		t.Fatalf("candidate DirectAWG commits = %d, want 1", got)
	}
	if got := direct.dnsCalls.Load(); got != 1 {
		t.Fatalf("candidate protected DNS calls = %d, want 1", got)
	}
}

func TestLinuxAWGOverH3RejectsBindingAndBaselineMismatches(t *testing.T) {
	controller := &adapterDirectController{
		session:   newAdapterDirectSession(),
		publicKey: adapterPublicKey(),
	}
	rawController, err := NewLinuxAWGOverH3Controller(
		validLinuxAWGOverH3Config(controller),
	)
	if err != nil {
		t.Fatal(err)
	}
	binding := validBinding()
	frameContext, err := wcf3.ContextFromBinding(binding, testNow)
	if err != nil {
		t.Fatal(err)
	}
	wrongFrame := frameContext
	wrongFrame.SequenceEpoch++
	if _, err := rawController.Start(
		context.Background(),
		newBlockingAdapterPacketConn(),
		binding,
		wrongFrame,
	); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("wrong WCF3 context error = %v", err)
	}

	controller.baselineHandshake = testNow
	path := newBlockingAdapterPacketConn()
	if _, err := rawController.Start(
		context.Background(), path, binding, frameContext,
	); err == nil || !strings.Contains(err.Error(), "fresh zero") {
		t.Fatalf("nonzero baseline error = %v", err)
	}
	if got := controller.session.closeCalls.Load(); got != 1 {
		t.Fatalf("failed baseline direct closes = %d, want 1", got)
	}
	if got := path.closeCalls.Load(); got != 0 {
		t.Fatalf("failed start closed caller-owned carrier path: %d", got)
	}
}

func TestLinuxAWGOverH3RelayAndDirectHealthFailClosed(t *testing.T) {
	direct := newAdapterDirectSession()
	controller := &adapterDirectController{
		session: direct, publicKey: adapterPublicKey(),
	}
	rawController, err := NewLinuxAWGOverH3Controller(
		validLinuxAWGOverH3Config(controller),
	)
	if err != nil {
		t.Fatal(err)
	}
	binding := validBinding()
	frameContext, _ := wcf3.ContextFromBinding(binding, testNow)
	path := newBlockingAdapterPacketConn()
	rawSession, err := rawController.Start(
		context.Background(), path, binding, frameContext,
	)
	if err != nil {
		t.Fatal(err)
	}
	session := rawSession.(*linuxAWGOverH3Session)
	failure := errors.New("AWG process exited")
	direct.health <- failure
	select {
	case err, ok := <-session.Health():
		if !ok || !errors.Is(err, failure) {
			t.Fatalf("session health = (%v, %v)", err, ok)
		}
	case <-time.After(time.Second):
		t.Fatal("direct session health failure was not published")
	}
	if err := session.VerifyBidirectional(
		context.Background(), binding, frameContext,
	); err == nil || !strings.Contains(err.Error(), "health failed") {
		t.Fatalf("predicate after health failure error = %v", err)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestLinuxAWGOverH3RelayFailureIsNotTeardownFailure(t *testing.T) {
	direct := newAdapterDirectSession()
	controller := &adapterDirectController{
		session: direct, publicKey: adapterPublicKey(),
	}
	rawController, err := NewLinuxAWGOverH3Controller(
		validLinuxAWGOverH3Config(controller),
	)
	if err != nil {
		t.Fatal(err)
	}
	binding := validBinding()
	frameContext, _ := wcf3.ContextFromBinding(binding, testNow)
	path := newBlockingAdapterPacketConn()
	rawSession, err := rawController.Start(
		context.Background(), path, binding, frameContext,
	)
	if err != nil {
		t.Fatal(err)
	}
	session := rawSession.(*linuxAWGOverH3Session)
	if err := path.SetDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	select {
	case healthErr, ok := <-session.Health():
		if !ok || healthErr == nil ||
			!strings.Contains(healthErr.Error(), "relay failed") {
			t.Fatalf("relay health = (%v, %v)", healthErr, ok)
		}
	case <-time.After(time.Second):
		t.Fatal("relay failure was not published")
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf(
			"successful rollback was misclassified as relay teardown: %v",
			err,
		)
	}
	if got := direct.contextCloseCalls.Load(); got != 1 {
		t.Fatalf("Direct-AWG teardown calls = %d, want 1", got)
	}
}

func TestLinuxAWGOverH3CloseTimeoutIsBoundedAndRetryable(t *testing.T) {
	direct := newAdapterDirectSession()
	direct.blockFirstContextClose.Store(true)
	direct.contextCloseEntered = make(chan struct{})
	controller := &adapterDirectController{
		session: direct, publicKey: adapterPublicKey(),
	}
	rawController, err := NewLinuxAWGOverH3Controller(
		validLinuxAWGOverH3Config(controller),
	)
	if err != nil {
		t.Fatal(err)
	}
	binding := validBinding()
	frameContext, _ := wcf3.ContextFromBinding(binding, testNow)
	path := newBlockingAdapterPacketConn()
	rawSession, err := rawController.Start(
		context.Background(), path, binding, frameContext,
	)
	if err != nil {
		t.Fatal(err)
	}
	session := rawSession.(*linuxAWGOverH3Session)

	short, cancel := context.WithTimeout(
		context.Background(), 50*time.Millisecond,
	)
	defer cancel()
	first := make(chan error, 1)
	go func() {
		first <- session.Close(short)
	}()
	select {
	case <-direct.contextCloseEntered:
	case <-time.After(time.Second):
		t.Fatal("H3 close did not reach contextual DirectAWG close")
	}
	if err := <-first; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first Close() error = %v, want deadline", err)
	}
	if got := path.closeCalls.Load(); got != 0 {
		t.Fatalf("H3 session closed caller-owned carrier path: %d", got)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("retry Close() error = %v", err)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("idempotent Close() error = %v", err)
	}
	if got := direct.contextCloseCalls.Load(); got != 2 {
		t.Fatalf("contextual direct closes = %d, want 2", got)
	}
	if got := direct.closeCalls.Load(); got != 1 {
		t.Fatalf("successful direct closes = %d, want 1", got)
	}
}

func TestLinuxAWGOverH3RejectsLegacyUnboundedSession(t *testing.T) {
	controller := &legacyAdapterDirectController{
		session:   newLegacyAdapterDirectSession(),
		publicKey: adapterPublicKey(),
	}
	rawController, err := NewLinuxAWGOverH3Controller(
		validLinuxAWGOverH3Config(controller),
	)
	if err != nil {
		t.Fatal(err)
	}
	binding := validBinding()
	frameContext, _ := wcf3.ContextFromBinding(binding, testNow)
	_, err = rawController.Start(
		context.Background(),
		newBlockingAdapterPacketConn(),
		binding,
		frameContext,
	)
	if err == nil || !strings.Contains(err.Error(), "context-bounded") {
		t.Fatalf("legacy session error = %v", err)
	}
	if got := controller.session.closeCalls.Load(); got != 1 {
		t.Fatalf("legacy session cleanup closes = %d, want 1", got)
	}
}

func TestLinuxVerifierAndTransactionRejectForeignSessions(t *testing.T) {
	binding := validBinding()
	frameContext, _ := wcf3.ContextFromBinding(binding, testNow)
	foreign := newFakeSession()
	if err := NewLinuxCandidateVerifierAdapter().VerifyProtectedDNS(
		context.Background(), foreign, binding, frameContext,
	); err == nil {
		t.Fatal("foreign verifier session was accepted")
	}
	if _, err := NewLinuxRouteDNSTransactionFactory().Prepare(
		context.Background(), foreign, binding, frameContext,
	); err == nil {
		t.Fatal("foreign transaction session was accepted")
	}
}

func validLinuxAWGOverH3Config(
	controller directawg.TunnelController,
) LinuxAWGOverH3Config {
	return LinuxAWGOverH3Config{
		Controller:        controller,
		GatewayEndpoint:   "198.51.100.40:51820",
		GatewayPublicKey:  adapterPublicKey(),
		LocalRelayAddress: "127.0.0.1:0",
		MinInnerDatagram:  576,
		MaxInnerDatagram:  1280,
		PollInterval:      time.Millisecond,
		Now:               func() time.Time { return testNow },
	}
}

func adapterPublicKey() string {
	return base64.StdEncoding.EncodeToString(
		[]byte("12345678901234567890123456789012"),
	)
}

type recordingProtectedPacketOpener struct {
	opens         atomic.Int32
	protects      atomic.Int32
	lastNetwork   string
	lastInterface string
	lastMark      uint32
}

type protectedSocketRecord struct {
	network       string
	interfaceName string
	mark          uint32
	socket        *fakePacketConn
}

type multiRecordingProtectedPacketOpener struct {
	mu      sync.Mutex
	records []protectedSocketRecord
}

func (opener *multiRecordingProtectedPacketOpener) Open(
	_ context.Context,
	network string,
	interfaceName string,
	mark uint32,
) (net.PacketConn, error) {
	socket := &fakePacketConn{}
	opener.mu.Lock()
	opener.records = append(opener.records, protectedSocketRecord{
		network:       network,
		interfaceName: interfaceName,
		mark:          mark,
		socket:        socket,
	})
	opener.mu.Unlock()
	return socket, nil
}

func (*multiRecordingProtectedPacketOpener) Protect(
	net.PacketConn,
	string,
	uint32,
) error {
	return nil
}

func (opener *multiRecordingProtectedPacketOpener) Records() []protectedSocketRecord {
	opener.mu.Lock()
	defer opener.mu.Unlock()
	return append([]protectedSocketRecord(nil), opener.records...)
}

func (opener *recordingProtectedPacketOpener) Open(
	_ context.Context,
	network string,
	interfaceName string,
	mark uint32,
) (net.PacketConn, error) {
	opener.opens.Add(1)
	opener.lastNetwork = network
	opener.lastInterface = interfaceName
	opener.lastMark = mark
	return &fakePacketConn{}, nil
}

func (opener *recordingProtectedPacketOpener) Protect(
	net.PacketConn,
	string,
	uint32,
) error {
	opener.protects.Add(1)
	return nil
}

type controllableInterfaceInspector struct {
	mu  sync.Mutex
	err error
}

func (inspector *controllableInterfaceInspector) Check(string) error {
	inspector.mu.Lock()
	defer inspector.mu.Unlock()
	return inspector.err
}

func (inspector *controllableInterfaceInspector) setError(err error) {
	inspector.mu.Lock()
	inspector.err = err
	inspector.mu.Unlock()
}

func failingQUICDial(
	context.Context,
	net.PacketConn,
	*net.UDPAddr,
	*tls.Config,
	*quic.Config,
) (*quic.Conn, *quic.Transport, error) {
	return nil, nil, errors.New("QUIC failed")
}

type adapterDirectController struct {
	session           *adapterDirectSession
	publicKey         string
	baselineHandshake time.Time
	preparation       directawg.Preparation
}

func (controller *adapterDirectController) Prepare(
	_ context.Context,
	preparation directawg.Preparation,
) (directawg.PreparedTunnel, error) {
	controller.preparation = preparation
	controller.session.setStatus(directawg.Status{
		PeerPublicKey: controller.publicKey,
		PeerEndpoint:  preparation.RelayEndpoint,
	})
	return directawg.PreparedTunnel{
		Session: controller.session,
		Baseline: directawg.Status{
			PeerPublicKey:   controller.publicKey,
			PeerEndpoint:    preparation.RelayEndpoint,
			LatestHandshake: controller.baselineHandshake,
		},
		LocalSourceEndpoint: "127.0.0.1:49001",
	}, nil
}

type adapterDirectSession struct {
	mu     sync.Mutex
	status directawg.Status
	health chan error

	dnsCalls    atomic.Int32
	canaryCalls atomic.Int32
	commitCalls atomic.Int32
	closeCalls  atomic.Int32
	closeOnce   sync.Once
	closeErr    error

	contextCloseCalls      atomic.Int32
	blockFirstContextClose atomic.Bool
	contextCloseEntered    chan struct{}
	contextCloseEnterOnce  sync.Once
}

func newAdapterDirectSession() *adapterDirectSession {
	return &adapterDirectSession{health: make(chan error, 1)}
}

func (session *adapterDirectSession) setStatus(status directawg.Status) {
	session.mu.Lock()
	session.status = status
	session.mu.Unlock()
}

func (session *adapterDirectSession) Status(
	context.Context,
) (directawg.Status, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.status, nil
}

func (session *adapterDirectSession) VerifyProtectedDNS(
	context.Context,
	connectivity.Binding,
) error {
	session.dnsCalls.Add(1)
	return nil
}

func (session *adapterDirectSession) VerifyTunnelCanary(
	context.Context,
	connectivity.Binding,
) error {
	session.canaryCalls.Add(1)
	return nil
}

func (session *adapterDirectSession) Commit(
	context.Context,
	connectivity.Binding,
) error {
	session.commitCalls.Add(1)
	return nil
}

func (session *adapterDirectSession) Health() <-chan error {
	return session.health
}

func (session *adapterDirectSession) Close() error {
	session.closeCalls.Add(1)
	session.closeOnce.Do(func() { close(session.health) })
	return session.closeErr
}

func (session *adapterDirectSession) CloseContext(ctx context.Context) error {
	session.contextCloseCalls.Add(1)
	if ctx == nil {
		return errors.New("close context is required")
	}
	if session.blockFirstContextClose.CompareAndSwap(true, false) {
		if session.contextCloseEntered != nil {
			session.contextCloseEnterOnce.Do(func() {
				close(session.contextCloseEntered)
			})
		}
		<-ctx.Done()
		return context.Cause(ctx)
	}
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	return session.Close()
}

type legacyAdapterDirectController struct {
	session   *legacyAdapterDirectSession
	publicKey string
}

func (controller *legacyAdapterDirectController) Prepare(
	_ context.Context,
	preparation directawg.Preparation,
) (directawg.PreparedTunnel, error) {
	controller.session.status = directawg.Status{
		PeerPublicKey: controller.publicKey,
		PeerEndpoint:  preparation.RelayEndpoint,
	}
	return directawg.PreparedTunnel{
		Session: controller.session,
		Baseline: directawg.Status{
			PeerPublicKey: controller.publicKey,
			PeerEndpoint:  preparation.RelayEndpoint,
		},
		LocalSourceEndpoint: "127.0.0.1:49002",
	}, nil
}

type legacyAdapterDirectSession struct {
	status     directawg.Status
	health     chan error
	closeCalls atomic.Int32
}

func newLegacyAdapterDirectSession() *legacyAdapterDirectSession {
	return &legacyAdapterDirectSession{health: make(chan error, 1)}
}

func (session *legacyAdapterDirectSession) Status(
	context.Context,
) (directawg.Status, error) {
	return session.status, nil
}

func (*legacyAdapterDirectSession) VerifyProtectedDNS(
	context.Context,
	connectivity.Binding,
) error {
	return nil
}

func (*legacyAdapterDirectSession) VerifyTunnelCanary(
	context.Context,
	connectivity.Binding,
) error {
	return nil
}

func (*legacyAdapterDirectSession) Commit(
	context.Context,
	connectivity.Binding,
) error {
	return nil
}

func (session *legacyAdapterDirectSession) Health() <-chan error {
	return session.health
}

func (session *legacyAdapterDirectSession) Close() error {
	session.closeCalls.Add(1)
	return nil
}

type blockingAdapterPacketConn struct {
	deadline     chan struct{}
	closed       chan struct{}
	closeOnce    sync.Once
	deadlineOnce sync.Once
	closeCalls   atomic.Int32
}

func newBlockingAdapterPacketConn() *blockingAdapterPacketConn {
	return &blockingAdapterPacketConn{
		deadline: make(chan struct{}),
		closed:   make(chan struct{}),
	}
}

func (packet *blockingAdapterPacketConn) ReadFrom(
	[]byte,
) (int, net.Addr, error) {
	select {
	case <-packet.deadline:
		return 0, nil, errors.New("synthetic deadline")
	case <-packet.closed:
		return 0, nil, net.ErrClosed
	}
}

func (*blockingAdapterPacketConn) WriteTo(
	payload []byte,
	_ net.Addr,
) (int, error) {
	return len(payload), nil
}

func (packet *blockingAdapterPacketConn) Close() error {
	packet.closeCalls.Add(1)
	packet.closeOnce.Do(func() { close(packet.closed) })
	return nil
}

func (*blockingAdapterPacketConn) LocalAddr() net.Addr {
	return fakeAddr("blocking")
}

func (packet *blockingAdapterPacketConn) SetDeadline(time.Time) error {
	packet.deadlineOnce.Do(func() { close(packet.deadline) })
	return nil
}

func (packet *blockingAdapterPacketConn) SetReadDeadline(
	deadline time.Time,
) error {
	return packet.SetDeadline(deadline)
}

func (packet *blockingAdapterPacketConn) SetWriteDeadline(
	time.Time,
) error {
	return nil
}
