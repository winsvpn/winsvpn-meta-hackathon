package bootstrap_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/awg"
	"winsvpn.local/winnprotocol/internal/bootstrap"
	"winsvpn.local/winnprotocol/internal/observability"
	"winsvpn.local/winnprotocol/internal/pki"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/ratelimit"
	"winsvpn.local/winnprotocol/internal/rotation"
	"winsvpn.local/winnprotocol/internal/securefile"
	"winsvpn.local/winnprotocol/internal/state"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

const (
	integrationDevice     = "device-android-1"
	integrationPeer       = "nNOe1VBs+qdVjQGHgems9Xd3SO6gsrVl7+DM8y/EZAQ="
	integrationController = "controller-1"
)

func TestAllHybridSuitesRotateMatchingPSKs(t *testing.T) {
	for _, suiteName := range protocol.SupportedSuites() {
		t.Run(suiteName, func(t *testing.T) {
			fixture := newFixture(t, suiteName, awg.FileApplier{Path: filepath.Join(t.TempDir(), "server.psk")})
			defer fixture.server.Close()
			clientPSK := filepath.Join(t.TempDir(), "client.psk")
			clientState := filepath.Join(t.TempDir(), "client.state")
			result := runRotation(t, fixture, clientState, clientPSK)
			if result.Generation != 1 {
				t.Fatalf("generation = %d, want 1", result.Generation)
			}
			if result.Curve != fixture.suite.Curve.String() {
				t.Fatalf("curve = %s, want %s", result.Curve, fixture.suite.Curve)
			}
			serverPSK, err := os.ReadFile(fixture.serverPSKPath)
			if err != nil {
				t.Fatal(err)
			}
			devicePSK, err := os.ReadFile(clientPSK)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(serverPSK, devicePSK) {
				t.Fatal("controller and device applied different PSKs")
			}
		})
	}
}

func TestClassicalOnlyDowngradeHasNoCommonGroup(t *testing.T) {
	fixture := newFixture(t, protocol.DefaultSuite, awg.FileApplier{Path: filepath.Join(t.TempDir(), "server.psk")})
	defer fixture.server.Close()
	classical := fixture.clientTLS.Clone()
	classical.CurvePreferences = []tls.CurveID{tls.X25519}
	client, err := bootstrap.NewClient(
		fixture.server.URL,
		classical,
		fixture.suite,
		integrationController,
		fixture.deviceSigner,
		fixture.controllerVerifier,
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := client.NewRequest(integrationDevice, integrationPeer, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Rekey(context.Background(), request); err == nil {
		t.Fatal("classical-only TLS client unexpectedly completed a rekey")
	}
}

func TestSuiteMismatchHasNoCommonGroup(t *testing.T) {
	fixture := newFixture(t, protocol.SuiteP384MLKEM1024, awg.FileApplier{Path: filepath.Join(t.TempDir(), "server.psk")})
	defer fixture.server.Close()
	otherSuite, err := tlsconfig.ParseSuite(protocol.SuiteP256MLKEM768)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := tlsconfig.Client(
		fixture.paths.DeviceCert,
		fixture.paths.DeviceKey,
		fixture.paths.CACert,
		"localhost",
		otherSuite,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, otherDeviceSigner, otherControllerVerifier := authMaterials(t, fixture.paths, otherSuite.Name)
	client, err := bootstrap.NewClient(
		fixture.server.URL,
		clientTLS,
		otherSuite,
		integrationController,
		otherDeviceSigner,
		otherControllerVerifier,
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := client.NewRequest(integrationDevice, integrationPeer, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Rekey(context.Background(), request); err == nil {
		t.Fatal("mismatched hybrid suites unexpectedly completed a rekey")
	}
}

func TestFailedClientApplyRetriesExactCommittedRequest(t *testing.T) {
	fixture := newFixture(t, protocol.DefaultSuite, awg.FileApplier{Path: filepath.Join(t.TempDir(), "server.psk")})
	defer fixture.server.Close()
	clientState := filepath.Join(t.TempDir(), "client.state")
	client, err := bootstrap.NewClient(
		fixture.server.URL,
		fixture.clientTLS,
		fixture.suite,
		integrationController,
		fixture.deviceSigner,
		fixture.controllerVerifier,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = rotation.Run(
		context.Background(),
		client,
		failingApplier{},
		clientState,
		integrationDevice,
		integrationPeer,
		fixture.suite.Name,
	)
	if err == nil {
		t.Fatal("failing client adapter unexpectedly succeeded")
	}
	snapshot, err := fixture.store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Peers) != 1 || snapshot.Peers[0].Generation != 1 {
		t.Fatalf("controller did not commit generation 1: %+v", snapshot)
	}
	clientPSK := filepath.Join(t.TempDir(), "client.psk")
	result := runRotation(t, fixture, clientState, clientPSK)
	if result.Generation != 1 {
		t.Fatalf("retry advanced generation to %d, want idempotent generation 1", result.Generation)
	}
	serverPSK, _ := os.ReadFile(fixture.serverPSKPath)
	devicePSK, _ := os.ReadFile(clientPSK)
	if !bytes.Equal(serverPSK, devicePSK) {
		t.Fatal("retry did not apply the controller's committed PSK")
	}
}

func TestRevokedDeviceIsRejected(t *testing.T) {
	fixture := newFixture(t, protocol.DefaultSuite, awg.FileApplier{Path: filepath.Join(t.TempDir(), "server.psk")})
	defer fixture.server.Close()
	if err := fixture.store.Revoke(context.Background(), integrationDevice); err != nil {
		t.Fatal(err)
	}
	client, err := bootstrap.NewClient(
		fixture.server.URL,
		fixture.clientTLS,
		fixture.suite,
		integrationController,
		fixture.deviceSigner,
		fixture.controllerVerifier,
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := client.NewRequest(integrationDevice, integrationPeer, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Rekey(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "device_revoked") {
		t.Fatalf("revocation error = %v", err)
	}
}

func TestValidCertificateWithUnregisteredPQKeyIsRejected(t *testing.T) {
	fixture := newFixture(t, protocol.DefaultSuite, awg.FileApplier{Path: filepath.Join(t.TempDir(), "server.psk")})
	defer fixture.server.Close()
	wrongSeed := bytes.Repeat([]byte{0xa5}, 32)
	wrongSigner, err := pqauth.NewSigner(protocol.RequiredAuthAlgorithm(fixture.suite.Name), wrongSeed)
	clear(wrongSeed)
	if err != nil {
		t.Fatal(err)
	}
	client, err := bootstrap.NewClient(
		fixture.server.URL,
		fixture.clientTLS,
		fixture.suite,
		integrationController,
		wrongSigner,
		fixture.controllerVerifier,
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := client.NewRequest(integrationDevice, integrationPeer, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Rekey(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "pq_auth_rejected") {
		t.Fatalf("unregistered PQ key error = %v", err)
	}
}

func TestClientRejectsControllerWithWrongPQKey(t *testing.T) {
	fixture := newFixture(t, protocol.DefaultSuite, awg.FileApplier{Path: filepath.Join(t.TempDir(), "server.psk")})
	defer fixture.server.Close()
	wrongSeed := bytes.Repeat([]byte{0xb6}, 32)
	wrongSigner, err := pqauth.NewSigner(protocol.RequiredAuthAlgorithm(fixture.suite.Name), wrongSeed)
	clear(wrongSeed)
	if err != nil {
		t.Fatal(err)
	}
	wrongVerifier, err := pqauth.NewVerifier(wrongSigner.Algorithm(), wrongSigner.PublicBytes())
	if err != nil {
		t.Fatal(err)
	}
	client, err := bootstrap.NewClient(
		fixture.server.URL,
		fixture.clientTLS,
		fixture.suite,
		integrationController,
		fixture.deviceSigner,
		wrongVerifier,
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := client.NewRequest(integrationDevice, integrationPeer, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Rekey(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "controller PQ authentication key binding mismatch") {
		t.Fatalf("wrong controller PQ pin error = %v", err)
	}
}

func TestRateLimitRejectsBeforeIssuingAnotherKeyAndRecordsMetric(t *testing.T) {
	fixture := newFixture(t, protocol.DefaultSuite, awg.FileApplier{Path: filepath.Join(t.TempDir(), "server.psk")})
	defer fixture.server.Close()
	limiter, err := ratelimit.New(1, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	metrics := observability.New()
	fixture.service.Limiter = limiter
	fixture.service.Metrics = metrics
	client, err := bootstrap.NewClient(
		fixture.server.URL,
		fixture.clientTLS,
		fixture.suite,
		integrationController,
		fixture.deviceSigner,
		fixture.controllerVerifier,
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := client.NewRequest(integrationDevice, integrationPeer, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Rekey(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Rekey(context.Background(), request); err == nil || !strings.Contains(err.Error(), "rate_limited") {
		t.Fatalf("rate-limit error = %v", err)
	}

	recorder := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, err := io.ReadAll(recorder.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `winn_protocol_events_total{event="rate_limited"} 1`) ||
		!strings.Contains(string(body), `winn_protocol_events_total{event="rekey_committed"} 1`) {
		t.Fatalf("unexpected metrics:\n%s", body)
	}
}

func TestOperationalLogOmitsRawAndCanonicalDeviceIdentity(t *testing.T) {
	fixture := newFixture(
		t,
		protocol.DefaultSuite,
		awg.FileApplier{Path: filepath.Join(t.TempDir(), "server.psk")},
	)
	defer fixture.server.Close()
	var output bytes.Buffer
	fixture.service.Logger = log.New(&output, "", 0)
	runRotation(
		t,
		fixture,
		filepath.Join(t.TempDir(), "client.state"),
		filepath.Join(t.TempDir(), "client.psk"),
	)
	logged := output.Bytes()
	for _, forbidden := range [][]byte{
		[]byte(integrationDevice),
		[]byte(base64.StdEncoding.EncodeToString([]byte(integrationDevice))),
		[]byte(base64.RawURLEncoding.EncodeToString([]byte(integrationDevice))),
		[]byte(fmt.Sprintf("%x", []byte(integrationDevice))),
	} {
		if bytes.Contains(logged, forbidden) {
			t.Fatalf("operational log exposed device identity alias %q: %s", forbidden, logged)
		}
	}
}

func TestCommitSuccessReleaseFailureLatchesAndReturns503(t *testing.T) {
	fixture := newFixture(
		t, protocol.DefaultSuite,
		awg.FileApplier{Path: filepath.Join(t.TempDir(), "server.psk")},
	)
	defer fixture.server.Close()
	fixture.service.Store = &releaseFailureController{
		Controller:            fixture.store,
		source:                fixture.store,
		releaseFailsRemaining: 1,
	}
	assertReconciliationRequired(t, fixture)
}

func TestRecoveredCommitReleaseFailureLatchesAndReturns503(t *testing.T) {
	fixture := newFixture(
		t, protocol.DefaultSuite,
		awg.FileApplier{Path: filepath.Join(t.TempDir(), "server.psk")},
	)
	defer fixture.server.Close()
	fixture.service.Store = &releaseFailureController{
		Controller:            fixture.store,
		source:                fixture.store,
		commitAckLoss:         true,
		releaseFailsRemaining: 1,
	}
	assertReconciliationRequired(t, fixture)
}

func TestRollbackSuccessReleaseFailureLatchesAndReturns503(t *testing.T) {
	fixture := newFixture(
		t, protocol.DefaultSuite,
		awg.FileApplier{Path: filepath.Join(t.TempDir(), "server.psk")},
	)
	defer fixture.server.Close()
	fixture.service.Store = &rollbackReleaseFailureController{releaseFailsRemaining: 1}
	assertReconciliationRequired(t, fixture)
}

func assertReconciliationRequired(t *testing.T, fixture fixture) {
	t.Helper()
	client, err := bootstrap.NewClient(
		fixture.server.URL,
		fixture.clientTLS,
		fixture.suite,
		integrationController,
		fixture.deviceSigner,
		fixture.controllerVerifier,
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := client.NewRequest(integrationDevice, integrationPeer, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Rekey(context.Background(), request); err == nil ||
		!strings.Contains(err.Error(), "controller_reconciliation_required") {
		t.Fatalf("release-failure response = %v", err)
	}
	followUp, err := client.NewRequest(integrationDevice, integrationPeer, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Rekey(context.Background(), followUp); err == nil ||
		!strings.Contains(err.Error(), "controller_reconciliation_required") {
		t.Fatalf("latched follow-up response = %v", err)
	}
}

type releaseFailureController struct {
	state.Controller
	source                state.TunnelTransactionSource
	commitAckLoss         bool
	releaseFailsRemaining int
}

func (c *releaseFailureController) BeginTunnelTransaction(
	ctx context.Context,
	deviceID string,
	peerPublicKey string,
) (state.TunnelTransaction, error) {
	transaction, err := c.source.BeginTunnelTransaction(ctx, deviceID, peerPublicKey)
	if err != nil {
		return nil, err
	}
	return &releaseFailureTransaction{
		TunnelTransaction: transaction,
		controller:        c,
	}, nil
}

type releaseFailureTransaction struct {
	state.TunnelTransaction
	controller *releaseFailureController
}

func (t *releaseFailureTransaction) Commit(ctx context.Context, requestID string) error {
	if err := t.TunnelTransaction.Commit(ctx, requestID); err != nil {
		return err
	}
	if t.controller.commitAckLoss {
		return errors.New("injected commit acknowledgement loss")
	}
	return nil
}

func (t *releaseFailureTransaction) Release(ctx context.Context) error {
	if err := t.TunnelTransaction.Release(ctx); err != nil {
		return err
	}
	if t.controller.releaseFailsRemaining > 0 {
		t.controller.releaseFailsRemaining--
		return errors.New("injected release verification failure")
	}
	return nil
}

type rollbackReleaseFailureController struct {
	releaseFailsRemaining int
}

func (*rollbackReleaseFailureController) Prepare(
	context.Context, protocol.RekeyRequest,
) (state.Prepared, error) {
	return state.Prepared{}, errors.New("ordinary Prepare is forbidden")
}

func (*rollbackReleaseFailureController) Commit(context.Context, string) error {
	return errors.New("ordinary Commit is forbidden")
}

func (*rollbackReleaseFailureController) Close() error { return nil }

func (c *rollbackReleaseFailureController) BeginTunnelTransaction(
	context.Context, string, string,
) (state.TunnelTransaction, error) {
	return &rollbackReleaseFailureTransaction{controller: c}, nil
}

type rollbackReleaseFailureTransaction struct {
	controller *rollbackReleaseFailureController
	request    protocol.RekeyRequest
	prepared   state.Prepared
	probes     int
}

func (t *rollbackReleaseFailureTransaction) Lease() state.TunnelLease {
	return alwaysValidLease{}
}

func (t *rollbackReleaseFailureTransaction) Prepare(
	_ context.Context,
	request protocol.RekeyRequest,
) (state.Prepared, error) {
	t.request = request
	psk := bytes.Repeat([]byte{0x71}, 32)
	t.prepared = state.Prepared{
		Response: protocol.RekeyResponse{
			Version:       protocol.Version,
			Suite:         request.Suite,
			ControllerID:  request.ControllerID,
			DeviceID:      request.DeviceID,
			PeerPublicKey: request.PeerPublicKey,
			RequestID:     request.RequestID,
			Nonce:         request.Nonce,
			Generation:    request.CurrentGeneration + 1,
			PresharedKey:  base64.StdEncoding.EncodeToString(psk),
		},
		PSK: psk,
	}
	return t.prepared, nil
}

func (*rollbackReleaseFailureTransaction) Commit(context.Context, string) error {
	return errors.New("injected pre-commit failure")
}

func (t *rollbackReleaseFailureTransaction) ReconcileCommitOutcome(
	context.Context,
	protocol.RekeyRequest,
) (state.CommitSnapshot, error) {
	t.probes++
	digest, _ := protocol.RequestDigest(t.request)
	return state.CommitSnapshot{
		Disposition:   state.CommitUncommitted,
		Response:      t.prepared.Response,
		PSK:           append([]byte(nil), t.prepared.PSK...),
		RequestDigest: digest,
		SnapshotHash:  [32]byte{0x44},
	}, nil
}

func (t *rollbackReleaseFailureTransaction) Release(context.Context) error {
	if t.controller.releaseFailsRemaining > 0 {
		t.controller.releaseFailsRemaining--
		return errors.New("injected rollback-terminal release failure")
	}
	return nil
}

type alwaysValidLease struct{}

func (alwaysValidLease) Validate(context.Context) error { return nil }

type fixture struct {
	server             *httptest.Server
	service            *bootstrap.Server
	store              *state.Store
	suite              tlsconfig.Suite
	clientTLS          *tls.Config
	paths              pki.Paths
	serverPSKPath      string
	deviceSigner       *pqauth.Signer
	controllerVerifier *pqauth.Verifier
}

func newFixture(t *testing.T, suiteName string, applier awg.Applier) fixture {
	t.Helper()
	directory := t.TempDir()
	paths, err := pki.GenerateLab(filepath.Join(directory, "pki"), "localhost", integrationDevice, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	suite, err := tlsconfig.ParseSuite(suiteName)
	if err != nil {
		t.Fatal(err)
	}
	controllerSigner, deviceSigner, controllerVerifier := authMaterials(t, paths, suite.Name)
	if file, ok := applier.(awg.FileApplier); ok {
		if err := securefile.AtomicWrite(
			file.Path,
			[]byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32))+"\n"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
	controllerStore, err := state.Open(
		filepath.Join(directory, "controller.state"),
		paths.StateKey,
		time.Hour,
		integrationController,
		controllerSigner,
	)
	if err != nil {
		t.Fatal(err)
	}
	deviceRegistry, err := pqauth.LoadRegistry(paths.DeviceRegistry)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, err := tlsconfig.Server(paths.ServerCert, paths.ServerKey, paths.CACert, suite)
	if err != nil {
		t.Fatal(err)
	}
	service := &bootstrap.Server{
		Store:          controllerStore,
		Applier:        applier,
		Suite:          suite,
		ControllerID:   integrationController,
		DeviceRegistry: deviceRegistry,
		ApplyTimeout:   time.Second,
	}
	server := httptest.NewUnstartedServer(service)
	server.TLS = serverTLS
	server.StartTLS()
	clientTLS, err := tlsconfig.Client(paths.DeviceCert, paths.DeviceKey, paths.CACert, "localhost", suite)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	serverPSKPath := ""
	if file, ok := applier.(awg.FileApplier); ok {
		serverPSKPath = file.Path
	}
	return fixture{
		server:             server,
		service:            service,
		store:              controllerStore,
		suite:              suite,
		clientTLS:          clientTLS,
		paths:              paths,
		serverPSKPath:      serverPSKPath,
		deviceSigner:       deviceSigner,
		controllerVerifier: controllerVerifier,
	}
}

func runRotation(t *testing.T, fixture fixture, clientState, clientPSK string) rotation.Result {
	t.Helper()
	client, err := bootstrap.NewClient(
		fixture.server.URL,
		fixture.clientTLS,
		fixture.suite,
		integrationController,
		fixture.deviceSigner,
		fixture.controllerVerifier,
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := rotation.Run(
		context.Background(),
		client,
		awg.FileApplier{Path: clientPSK},
		clientState,
		integrationDevice,
		integrationPeer,
		fixture.suite.Name,
	)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func authMaterials(
	t *testing.T,
	paths pki.Paths,
	suite string,
) (*pqauth.Signer, *pqauth.Signer, *pqauth.Verifier) {
	t.Helper()
	algorithm := protocol.RequiredAuthAlgorithm(suite)
	controllerSeed := paths.ControllerPQ65Seed
	controllerPublic := paths.ControllerPQ65Public
	deviceSeed := paths.DevicePQ65Seed
	if algorithm == protocol.AuthMLDSA87 {
		controllerSeed = paths.ControllerPQ87Seed
		controllerPublic = paths.ControllerPQ87Public
		deviceSeed = paths.DevicePQ87Seed
	}
	controllerSigner, err := pqauth.LoadSigner(algorithm, controllerSeed)
	if err != nil {
		t.Fatal(err)
	}
	deviceSigner, err := pqauth.LoadSigner(algorithm, deviceSeed)
	if err != nil {
		t.Fatal(err)
	}
	controllerVerifier, err := pqauth.LoadVerifier(algorithm, controllerPublic)
	if err != nil {
		t.Fatal(err)
	}
	return controllerSigner, deviceSigner, controllerVerifier
}

type failingApplier struct{}

func (failingApplier) Apply(context.Context, string, []byte) error {
	return errors.New("intentional apply failure")
}

func (failingApplier) Description() string {
	return "intentional-failure"
}

func (failingApplier) ReadCurrentPSK(context.Context, string) ([]byte, error) {
	return bytes.Repeat([]byte{0x31}, 32), nil
}
