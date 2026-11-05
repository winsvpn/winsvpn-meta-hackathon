package directawg

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
)

func TestDirectCandidateSurvivesRaceCancellationAndRelaysUDP(t *testing.T) {
	echo, stopEcho := startUDPEcho(t)
	defer stopEcho()
	controller := &fakeController{}
	now := time.Now().UTC()
	descriptor := connectivity.CandidateDescriptor{
		ID:        "raw-atl-1",
		Carrier:   connectivity.CarrierDirectAWG,
		NodeID:    "entry-atl",
		ExpiresAt: now.Add(time.Minute),
	}
	publicKey := base64.StdEncoding.EncodeToString(
		bytes.Repeat([]byte{0x42}, 32),
	)
	candidate, err := NewCandidate(Config{
		Descriptor:       descriptor,
		Endpoint:         echo.LocalAddr().String(),
		GatewayPublicKey: publicKey,
		MinInnerDatagram: 1200,
		MaxInnerDatagram: 1350,
		Controller:       controller,
		LabMode:          true,
	})
	if err != nil {
		t.Fatal(err)
	}
	readiness := connectivity.Readiness{
		Profile:           "default",
		Mode:              connectivity.ModeAuto,
		ManifestDigest:    strings.Repeat("a", 64),
		ManifestExpiresAt: now.Add(time.Hour),
		PSKGeneration:     7,
		PSKExpiresAt:      now.Add(time.Hour),
		UnusedCredentials: 1,
		PreparedAt:        now.Add(-time.Second),
		ExpiresAt:         now.Add(50 * time.Second),
		Candidates:        []connectivity.CandidateDescriptor{descriptor},
	}
	coordinator := connectivity.NewCoordinator()
	result := coordinator.Connect(context.Background(), connectivity.ConnectRequest{
		Readiness:     readiness,
		Candidates:    []connectivity.Candidate{candidate},
		SessionID:     strings.Repeat("1", 32),
		SequenceEpoch: 1,
		Deadline:      time.Second,
	})
	if !result.Success() {
		t.Fatalf("direct connection failed: %#v", result)
	}
	if !controller.session.committed() {
		t.Fatal("direct tunnel routes were not committed")
	}

	reply, err := controller.roundTrip([]byte("after-race"))
	if err != nil {
		t.Fatal(err)
	}
	if string(reply) != "after-race" {
		t.Fatalf("direct relay reply = %q", reply)
	}
	coordinator.Stop()
	routes, killSwitch, closeCount := controller.session.teardownState()
	if routes || !killSwitch || closeCount != 1 {
		t.Fatalf(
			"coordinator teardown routes=%t killswitch=%t closes=%d",
			routes, killSwitch, closeCount,
		)
	}
}

func TestDirectCandidateRejectsStaleHandshakeAndBindingMismatch(t *testing.T) {
	echo, stopEcho := startUDPEcho(t)
	defer stopEcho()
	now := time.Now().UTC()
	controller := &fakeController{
		staleHandshake: now.Truncate(time.Second),
	}
	descriptor := connectivity.CandidateDescriptor{
		ID:        "raw-nyc-1",
		Carrier:   connectivity.CarrierDirectAWG,
		NodeID:    "entry-nyc",
		ExpiresAt: now.Add(time.Minute),
	}
	publicKey := base64.StdEncoding.EncodeToString(
		bytes.Repeat([]byte{0x24}, 32),
	)
	candidate, err := NewCandidate(Config{
		Descriptor:       descriptor,
		Endpoint:         echo.LocalAddr().String(),
		GatewayPublicKey: publicKey,
		MinInnerDatagram: 1200,
		MaxInnerDatagram: 1350,
		Controller:       controller,
		LabMode:          true,
	})
	if err != nil {
		t.Fatal(err)
	}
	binding := connectivity.Binding{
		AttemptID:      strings.Repeat("2", 32),
		Profile:        "default",
		Mode:           connectivity.ModeAuto,
		ManifestDigest: strings.Repeat("b", 64),
		CandidateID:    descriptor.ID,
		NodeID:         descriptor.NodeID,
		SessionID:      strings.Repeat("3", 32),
		PSKGeneration:  8,
		SequenceEpoch:  2,
		Nonce:          strings.Repeat("4", 32),
		ExpiresAt:      now.Add(time.Minute),
	}
	connection, err := candidate.Dial(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	mismatch := binding
	mismatch.Nonce = strings.Repeat("5", 32)
	if err := connection.VerifyTunnelCanary(
		context.Background(), mismatch,
	); err == nil {
		t.Fatal("direct tunnel accepted a different binding")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if err := connection.FreshAWGHandshake(ctx, binding); !errors.Is(
		err, context.DeadlineExceeded,
	) {
		t.Fatalf("stale handshake error = %v", err)
	}
}

func TestMissingInitialHandshakeUsesOneExactPeerRefresh(t *testing.T) {
	echo, stopEcho := startUDPEcho(t)
	defer stopEcho()
	now := time.Now().UTC()
	controller := &fakeController{
		staleHandshake: now.Add(-time.Minute).Truncate(time.Second),
	}
	descriptor := connectivity.CandidateDescriptor{
		ID:        "raw-hedge-1",
		Carrier:   connectivity.CarrierDirectAWG,
		NodeID:    "entry-hedge",
		ExpiresAt: now.Add(time.Minute),
	}
	candidate, err := NewCandidate(Config{
		Descriptor: descriptor,
		Endpoint:   echo.LocalAddr().String(),
		GatewayPublicKey: base64.StdEncoding.EncodeToString(
			bytes.Repeat([]byte{0x44}, 32),
		),
		MinInnerDatagram: 1200,
		MaxInnerDatagram: 1350,
		Controller:       controller,
		LabMode:          true,
	})
	if err != nil {
		t.Fatal(err)
	}
	binding := testBinding(now, descriptor, 19)
	raw, err := candidate.Dial(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	connection := raw.(*Connection)
	defer connection.Close()

	// Move only the local scheduling origin so the first production hedge is
	// immediately due without slowing the unit test.
	connection.startedAt = time.Now().UTC().Add(
		-initialHandshakeHedgeOffsets[0] - time.Millisecond,
	)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := connection.FreshAWGHandshake(ctx, binding); err != nil {
		t.Fatalf("FreshAWGHandshake() error = %v", err)
	}
	controller.session.mu.Lock()
	refreshes := controller.session.refreshCalls
	controller.session.mu.Unlock()
	if refreshes != 1 {
		t.Fatalf("peer refreshes = %d, want exactly 1", refreshes)
	}
}

func TestProductionCandidateRequiresProtectedDialerAndFreshBaseline(
	t *testing.T,
) {
	echo, stopEcho := startUDPEcho(t)
	defer stopEcho()
	now := time.Now().UTC()
	descriptor := connectivity.CandidateDescriptor{
		ID:        "raw-chi-1",
		Carrier:   connectivity.CarrierDirectAWG,
		NodeID:    "entry-chi",
		ExpiresAt: now.Add(time.Minute),
	}
	publicKey := base64.StdEncoding.EncodeToString(
		bytes.Repeat([]byte{0x37}, 32),
	)
	base := Config{
		Descriptor:       descriptor,
		Endpoint:         echo.LocalAddr().String(),
		GatewayPublicKey: publicKey,
		MinInnerDatagram: 1200,
		MaxInnerDatagram: 1350,
		Controller:       &fakeController{},
	}
	if _, err := NewCandidate(base); err == nil ||
		!strings.Contains(err.Error(), "protected underlay") {
		t.Fatalf("missing protected dialer error = %v", err)
	}
	base.Dialer = UDPDialer{}
	if _, err := NewCandidate(base); err == nil ||
		!strings.Contains(err.Error(), "lab mode") {
		t.Fatalf("generic production dialer error = %v", err)
	}

	controller := &fakeController{
		staleHandshake: now.Truncate(time.Second),
		baselineRx:     1,
		baselineTx:     1,
	}
	base.Controller = controller
	base.Dialer = protectedTestDialer{}
	candidate, err := NewCandidate(base)
	if err != nil {
		t.Fatal(err)
	}
	binding := testBinding(now, descriptor, 9)
	if connection, err := candidate.Dial(
		context.Background(), binding,
	); err == nil {
		_ = connection.Close()
		t.Fatal("production candidate accepted a reused peer baseline")
	} else if !strings.Contains(err.Error(), "fresh isolated") {
		t.Fatalf("reused production baseline error = %v", err)
	}

	controller = &fakeController{}
	base.Controller = controller
	candidate, err = NewCandidate(base)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := candidate.Dial(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.Commit(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	routes, killSwitch, closeCount := controller.session.teardownState()
	if !routes || killSwitch || closeCount != 0 {
		t.Fatalf(
			"pre-close state routes=%t killswitch=%t closes=%d",
			routes, killSwitch, closeCount,
		)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	routes, killSwitch, closeCount = controller.session.teardownState()
	if routes || !killSwitch || closeCount != 1 {
		t.Fatalf(
			"post-close state routes=%t killswitch=%t closes=%d",
			routes, killSwitch, closeCount,
		)
	}
}

func TestDirectConnectionSessionHealthFailureRollsBackAndPublishesOnce(
	t *testing.T,
) {
	echo, stopEcho := startUDPEcho(t)
	defer stopEcho()
	now := time.Now().UTC()
	controller := &fakeController{}
	descriptor := connectivity.CandidateDescriptor{
		ID:        "raw-health-1",
		Carrier:   connectivity.CarrierDirectAWG,
		NodeID:    "entry-health",
		ExpiresAt: now.Add(time.Minute),
	}
	publicKey := base64.StdEncoding.EncodeToString(
		bytes.Repeat([]byte{0x59}, 32),
	)
	candidate, err := NewCandidate(Config{
		Descriptor:       descriptor,
		Endpoint:         echo.LocalAddr().String(),
		GatewayPublicKey: publicKey,
		MinInnerDatagram: 1200,
		MaxInnerDatagram: 1350,
		Controller:       controller,
		LabMode:          true,
	})
	if err != nil {
		t.Fatal(err)
	}
	binding := testBinding(now, descriptor, 21)
	connection, err := candidate.Dial(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.Commit(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	controller.session.failHealth(errors.New("interface monitor failed"))
	select {
	case err, ok := <-connection.Health():
		if !ok || err == nil ||
			!strings.Contains(err.Error(), "interface monitor failed") {
			t.Fatalf("connection health error=%v open=%t", err, ok)
		}
	case <-time.After(time.Second):
		t.Fatal("connection health failure was not published")
	}
	select {
	case _, ok := <-connection.Health():
		if ok {
			t.Fatal("connection health published more than one error")
		}
	case <-time.After(time.Second):
		t.Fatal("connection health did not close")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		routes, killSwitch, closeCount := controller.session.teardownState()
		if !routes && killSwitch && closeCount == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	routes, killSwitch, closeCount := controller.session.teardownState()
	if routes || !killSwitch || closeCount != 1 {
		t.Fatalf(
			"health teardown routes=%t kill=%t closes=%d",
			routes, killSwitch, closeCount,
		)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, closeCount = controller.session.teardownState()
	if closeCount != 1 {
		t.Fatalf("health teardown close count = %d", closeCount)
	}
}

func TestDirectConnectionRelayFailureRollsBackAndPublishesOnce(
	t *testing.T,
) {
	echo, stopEcho := startUDPEcho(t)
	defer stopEcho()
	now := time.Now().UTC()
	controller := &fakeController{}
	descriptor := connectivity.CandidateDescriptor{
		ID:        "raw-relay-health-1",
		Carrier:   connectivity.CarrierDirectAWG,
		NodeID:    "entry-relay-health",
		ExpiresAt: now.Add(time.Minute),
	}
	publicKey := base64.StdEncoding.EncodeToString(
		bytes.Repeat([]byte{0x68}, 32),
	)
	candidate, err := NewCandidate(Config{
		Descriptor:       descriptor,
		Endpoint:         echo.LocalAddr().String(),
		GatewayPublicKey: publicKey,
		MinInnerDatagram: 1200,
		MaxInnerDatagram: 1350,
		Controller:       controller,
		LabMode:          true,
	})
	if err != nil {
		t.Fatal(err)
	}
	binding := testBinding(now, descriptor, 22)
	genericConnection, err := candidate.Dial(
		context.Background(), binding,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := genericConnection.Commit(
		context.Background(), binding,
	); err != nil {
		t.Fatal(err)
	}
	connection := genericConnection.(*Connection)
	if err := connection.local.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err, ok := <-connection.Health():
		if !ok || err == nil ||
			!strings.Contains(err.Error(), "relay stopped") {
			t.Fatalf("relay health error=%v open=%t", err, ok)
		}
	case <-time.After(time.Second):
		t.Fatal("relay failure was not published")
	}
	select {
	case _, ok := <-connection.Health():
		if ok {
			t.Fatal("relay health published more than one error")
		}
	case <-time.After(time.Second):
		t.Fatal("relay health did not close")
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("relay cleanup error = %v", err)
	}
	routes, killSwitch, closeCount := controller.session.teardownState()
	if routes || !killSwitch || closeCount != 1 {
		t.Fatalf(
			"relay teardown routes=%t kill=%t closes=%d",
			routes, killSwitch, closeCount,
		)
	}
}

type protectedTestDialer struct{}

func (protectedTestDialer) Dial(
	ctx context.Context,
	endpoint string,
) (net.PacketConn, error) {
	return (UDPDialer{}).Dial(ctx, endpoint)
}

func testBinding(
	now time.Time,
	descriptor connectivity.CandidateDescriptor,
	generation uint64,
) connectivity.Binding {
	return connectivity.Binding{
		AttemptID:      strings.Repeat("6", 32),
		Profile:        "default",
		Mode:           connectivity.ModeAuto,
		ManifestDigest: strings.Repeat("c", 64),
		CandidateID:    descriptor.ID,
		NodeID:         descriptor.NodeID,
		SessionID:      strings.Repeat("7", 32),
		PSKGeneration:  generation,
		SequenceEpoch:  3,
		Nonce:          strings.Repeat("8", 32),
		ExpiresAt:      now.Add(time.Minute),
	}
}

type fakeController struct {
	mu             sync.Mutex
	preparation    Preparation
	client         *net.UDPConn
	session        *fakeSession
	staleHandshake time.Time
	baselineRx     uint64
	baselineTx     uint64
}

func (controller *fakeController) Prepare(
	_ context.Context,
	preparation Preparation,
) (PreparedTunnel, error) {
	relay, err := net.ResolveUDPAddr("udp", preparation.RelayEndpoint)
	if err != nil {
		return PreparedTunnel{}, err
	}
	client, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		return PreparedTunnel{}, err
	}
	baseline := Status{
		PeerPublicKey:   preparation.GatewayPublicKey,
		PeerEndpoint:    preparation.RelayEndpoint,
		LatestHandshake: controller.staleHandshake,
		RxBytes:         controller.baselineRx,
		TxBytes:         controller.baselineTx,
	}
	session := &fakeSession{
		binding:        preparation.Binding,
		peerPublicKey:  preparation.GatewayPublicKey,
		peerEndpoint:   preparation.RelayEndpoint,
		staleHandshake: controller.staleHandshake,
		baselineRx:     controller.baselineRx,
		baselineTx:     controller.baselineTx,
		client:         client,
		health:         make(chan error, 1),
	}
	controller.mu.Lock()
	controller.preparation = preparation
	controller.client = client
	controller.session = session
	controller.mu.Unlock()
	return PreparedTunnel{
		Session:             session,
		Baseline:            baseline,
		LocalSourceEndpoint: client.LocalAddr().String(),
	}, nil
}

func (controller *fakeController) roundTrip(
	packet []byte,
) ([]byte, error) {
	controller.mu.Lock()
	client := controller.client
	controller.mu.Unlock()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	if _, err := client.Write(packet); err != nil {
		return nil, err
	}
	buffer := make([]byte, 1500)
	count, err := client.Read(buffer)
	return append([]byte(nil), buffer[:count]...), err
}

type fakeSession struct {
	mu              sync.Mutex
	binding         connectivity.Binding
	peerPublicKey   string
	peerEndpoint    string
	staleHandshake  time.Time
	baselineRx      uint64
	baselineTx      uint64
	client          *net.UDPConn
	commitCompleted bool
	routesCommitted bool
	killSwitch      bool
	closeCount      int
	closeFailures   int
	closeFailure    error
	refreshCalls    int
	health          chan error
	healthOnce      sync.Once
}

func (session *fakeSession) Status(context.Context) (Status, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	handshake := time.Now().UTC().Truncate(time.Second)
	if !session.staleHandshake.IsZero() {
		handshake = session.staleHandshake
	}
	return Status{
		PeerPublicKey:   session.peerPublicKey,
		PeerEndpoint:    session.peerEndpoint,
		LatestHandshake: handshake,
		RxBytes:         session.baselineRx + 1,
		TxBytes:         session.baselineTx + 1,
	}, nil
}

func (session *fakeSession) RefreshAWGHandshake(
	_ context.Context,
	binding connectivity.Binding,
) error {
	if err := session.check(binding); err != nil {
		return err
	}
	session.mu.Lock()
	session.refreshCalls++
	session.staleHandshake = time.Time{}
	session.mu.Unlock()
	return nil
}

func (session *fakeSession) VerifyProtectedDNS(
	_ context.Context,
	binding connectivity.Binding,
) error {
	return session.check(binding)
}

func (session *fakeSession) VerifyTunnelCanary(
	_ context.Context,
	binding connectivity.Binding,
) error {
	return session.check(binding)
}

func (session *fakeSession) Commit(
	_ context.Context,
	binding connectivity.Binding,
) error {
	if err := session.check(binding); err != nil {
		return err
	}
	session.mu.Lock()
	session.commitCompleted = true
	session.routesCommitted = true
	session.killSwitch = false
	session.mu.Unlock()
	return nil
}

func (session *fakeSession) Health() <-chan error {
	return session.health
}

func (session *fakeSession) failHealth(err error) {
	session.healthOnce.Do(func() {
		session.health <- err
		close(session.health)
	})
}

func (session *fakeSession) Close() error {
	session.mu.Lock()
	session.closeCount++
	if session.closeFailures > 0 {
		session.closeFailures--
		err := session.closeFailure
		session.mu.Unlock()
		return err
	}
	session.routesCommitted = false
	session.killSwitch = true
	session.mu.Unlock()
	session.healthOnce.Do(func() {
		close(session.health)
	})
	return session.client.Close()
}

func TestDirectConnectionRetryCloseResumesTransientSessionFailure(
	t *testing.T,
) {
	client, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	relayDone := make(chan struct{})
	close(relayDone)
	healthWatchDone := make(chan struct{})
	close(healthWatchDone)
	transient := errors.New("transient route rollback")
	session := &fakeSession{
		client:        client,
		health:        make(chan error, 1),
		closeFailures: 1,
		closeFailure:  transient,
	}
	connection := &Connection{
		session:         session,
		cancel:          func() {},
		relayDone:       relayDone,
		health:          make(chan error, 1),
		healthWatchDone: healthWatchDone,
	}
	if err := connection.Close(); !errors.Is(err, transient) {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := connection.RetryClose(); err != nil {
		t.Fatalf("RetryClose() error = %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("Close() after recovery error = %v", err)
	}
	_, _, count := session.teardownState()
	if count != 2 {
		t.Fatalf("session close attempts = %d, want 2", count)
	}
}

func (session *fakeSession) teardownState() (bool, bool, int) {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.routesCommitted, session.killSwitch, session.closeCount
}

func (session *fakeSession) committed() bool {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.commitCompleted
}

func (session *fakeSession) check(binding connectivity.Binding) error {
	if binding != session.binding {
		return errors.New("fake tunnel binding mismatch")
	}
	return nil
}

func startUDPEcho(t *testing.T) (*net.UDPConn, func()) {
	t.Helper()
	server, err := net.ListenUDP(
		"udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
	)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 1500)
		for {
			count, sender, readErr := server.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			if _, writeErr := server.WriteToUDP(
				buffer[:count], sender,
			); writeErr != nil {
				return
			}
		}
	}()
	return server, func() {
		_ = server.Close()
		<-done
	}
}
