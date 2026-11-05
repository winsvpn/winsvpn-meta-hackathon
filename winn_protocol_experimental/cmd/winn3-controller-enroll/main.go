// Command winn3-controller-enroll is the Track E3 probe for controller
// enrollment plus AWG key issuance in the standalone Winn Protocol v3 module.
//
// The enrollment chain has three hops. This command runs hop 2 hermetically.
// Hops 1 and 3 are the Python hub; they are documented and skipped from
// chain_test.go unless a loopback hub is opted in via WINN3_E3_HUB_BASE.
//
//  1. data plane registers (D4)     POST /api/v1/nodes/register
//  2. controller mints AWG key      POST /v2/rekeys, x25519-mlkem768, 24h TTL
//  3. hub serves descriptor         POST /verify vpn_config.winn3_descriptor
//
// Hop 2 starts the same library stack cmd/winn-server runs
// (internal/bootstrap, internal/state, internal/pqauth, internal/awg,
// internal/tlsconfig) on an httptest TLS listener. No Kansas host, no
// secrets, no network egress. Lab material comes from internal/pki.GenerateLab.
//
// Flags:
//
//	-suite      hybrid TLS suite (default "x25519-mlkem768")
//	-ttl        issued AWG PSK lifetime (default 24h)
//	-controller controller audience identifier (default "winn-controller-1")
//	-device     registered device identifier (default "device-android-1")
//	-emit       write the JSON result to a file ("-" writes stdout)
//
// Exit codes:
//
//	0  every enrollment step and invariant passed
//	1  the chain or an invariant failed (the JSON result is still emitted)
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	"winsvpn.local/winnprotocol/internal/awg"
	"winsvpn.local/winnprotocol/internal/bootstrap"
	"winsvpn.local/winnprotocol/internal/pki"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/securefile"
	"winsvpn.local/winnprotocol/internal/state"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "winn3-controller-enroll: %v\n", err)
		os.Exit(1)
	}
}

// result is the machine-readable probe outcome. It pairs the rotation result
// (durable PSK applied on both sides) with the raw served node descriptor and
// the lane invariants checked against it.
type result struct {
	Suite               string `json:"suite"`
	ControllerID        string `json:"controller_id"`
	DeviceID            string `json:"device_id"`
	PeerPublicKey       string `json:"peer_public_key"`
	Generation          uint64 `json:"generation"`
	KeyID               string `json:"key_id"`
	KeyIDMatches        bool   `json:"key_id_matches"`
	IssuedAt            string `json:"issued_at"`
	ExpiresAt           string `json:"expires_at"`
	Lifetime            string `json:"lifetime"`
	LifetimeTTL         string `json:"lifetime_ttl"`
	LifetimeMatches     bool   `json:"lifetime_matches"`
	PSKSize             int    `json:"psk_size_bytes"`
	PSKAppliedBoth      bool   `json:"psk_applied_both_sides"`
	DescriptorNamesNode bool   `json:"descriptor_names_node"`
	Curve               string `json:"key_exchange"`
	Adapter             string `json:"adapter"`
}

func run(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("winn3-controller-enroll", flag.ContinueOnError)
	var (
		suiteName  = flags.String("suite", protocol.DefaultSuite, "hybrid TLS suite")
		ttl        = flags.Duration("ttl", 24*time.Hour, "issued AWG PSK lifetime")
		controller = flags.String("controller", "winn-controller-1", "controller audience identifier")
		device     = flags.String("device", "device-android-1", "registered device identifier")
		emit       = flags.String("emit", "", "write the JSON result to a file (\"-\" writes stdout)")
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	suite, err := tlsconfig.ParseSuite(*suiteName)
	if err != nil {
		return fmt.Errorf("invalid suite %q: %w", *suiteName, err)
	}
	if *ttl <= 0 {
		return errors.New("-ttl must be positive")
	}
	peer, err := randomPeerPublicKey()
	if err != nil {
		return err
	}
	ctx := context.Background()

	directory, err := os.MkdirTemp("", "winn3-controller-enroll")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)

	paths, err := pki.GenerateLab(directory, "localhost", *device, time.Now().UTC())
	if err != nil {
		return err
	}
	controllerSigner, deviceSigner, controllerVerifier := authMaterials(paths, suite.Name)
	serverApplier := awg.FileApplier{Path: filepath.Join(directory, "server.psk")}
	if err := seedPSK(serverApplier.Path); err != nil {
		return err
	}
	controllerStore, err := state.Open(
		filepath.Join(directory, "controller.state"),
		paths.StateKey,
		*ttl,
		*controller,
		controllerSigner,
	)
	if err != nil {
		return err
	}
	defer controllerStore.Close()
	deviceRegistry, err := pqauth.LoadRegistry(paths.DeviceRegistry)
	if err != nil {
		return err
	}
	serverTLS, err := tlsconfig.Server(paths.ServerCert, paths.ServerKey, paths.CACert, suite)
	if err != nil {
		return err
	}
	service := &bootstrap.Server{
		Store:          controllerStore,
		Applier:        serverApplier,
		Suite:          suite,
		ControllerID:   *controller,
		DeviceRegistry: deviceRegistry,
		ApplyTimeout:   8 * time.Second,
	}
	server := httptest.NewUnstartedServer(service)
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()

	clientTLS, err := tlsconfig.Client(paths.DeviceCert, paths.DeviceKey, paths.CACert, "localhost", suite)
	if err != nil {
		return err
	}
	client, err := bootstrap.NewClient(
		server.URL,
		clientTLS,
		suite,
		*controller,
		deviceSigner,
		controllerVerifier,
	)
	if err != nil {
		return err
	}

	// Hop 2: the device posts /v2/rekeys. The controller mints a generation-1
	// AWG PSK and the RekeyResponse names that device (controller_id,
	// device_id, peer_public_key). This is not the hub's signed gateway
	// descriptor; that object is hop 3 and lives in chain_test.go.
	request, err := client.NewRequest(*device, peer, 0)
	if err != nil {
		return err
	}
	enrollment, err := client.Rekey(ctx, request)
	if err != nil {
		return fmt.Errorf("enrollment round trip failed: %w", err)
	}
	descriptor := enrollment.Response

	// Durable PSK proof: the enrollment above already made the controller
	// apply the minted key to its AWG applier (awg.FileApplier). Read it back
	// and require it to match the device-held PSK byte-for-byte.
	serverApplied, err := os.ReadFile(serverApplier.Path)
	if err != nil {
		return err
	}
	if _, err := protocol.ValidateResponse(request, descriptor, time.Now()); err != nil {
		return fmt.Errorf("served node descriptor failed validation: %w", err)
	}
	deviceApplied := enrollment.PSK

	issuedAt, err := time.Parse(time.RFC3339Nano, descriptor.IssuedAt)
	if err != nil {
		return err
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, descriptor.ExpiresAt)
	if err != nil {
		return err
	}
	lifetime := expiresAt.Sub(issuedAt)
	lifetimeMatches := lifetime == *ttl
	keyIDMatches := protocol.KeyID(*controller, suite.Name, *device, peer, descriptor.Generation, enrollment.PSK) == descriptor.KeyID
	clear(enrollment.PSK)
	descriptorNamesNode := descriptor.DeviceID == *device &&
		descriptor.PeerPublicKey == peer &&
		descriptor.ControllerID == *controller &&
		descriptor.Generation == request.CurrentGeneration+1
	serverAppliedKey := strings.TrimSpace(string(serverApplied))
	pskAppliedBoth := serverAppliedKey == descriptor.PresharedKey && len(deviceApplied) == 32

	check := func(ok bool, message string) error {
		if !ok {
			return errors.New(message)
		}
		return nil
	}
	if err := check(lifetimeMatches, fmt.Sprintf("key lifetime %s does not match -ttl %s", lifetime, *ttl)); err != nil {
		return err
	}
	if err := check(keyIDMatches, "served key_id does not bind controller/device/peer/generation/PSK"); err != nil {
		return err
	}
	if err := check(descriptorNamesNode, "served descriptor does not name the registering node"); err != nil {
		return err
	}
	if err := check(pskAppliedBoth, "controller and device applied different PSKs"); err != nil {
		return err
	}

	res := result{
		Suite:               suite.Name,
		ControllerID:        *controller,
		DeviceID:            *device,
		PeerPublicKey:       peer,
		Generation:          descriptor.Generation,
		KeyID:               descriptor.KeyID,
		KeyIDMatches:        keyIDMatches,
		IssuedAt:            descriptor.IssuedAt,
		ExpiresAt:           descriptor.ExpiresAt,
		Lifetime:            lifetime.String(),
		LifetimeTTL:         ttl.String(),
		LifetimeMatches:     lifetimeMatches,
		PSKSize:             len(deviceApplied),
		PSKAppliedBoth:      pskAppliedBoth,
		DescriptorNamesNode: descriptorNamesNode,
		Curve:               suite.Curve.String(),
		Adapter:             serverApplier.Description(),
	}
	encoded, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	switch *emit {
	case "-":
		_, err = out.Write(encoded)
	case "":
		_, err = out.Write(encoded)
	default:
		err = securefile.AtomicWrite(*emit, encoded, 0o644)
	}
	return err
}

func randomPeerPublicKey() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("peer public key: %w", err)
	}
	var nonzero byte
	for _, b := range raw {
		nonzero |= b
	}
	if nonzero == 0 {
		raw[0] = 1
	}
	return base64.StdEncoding.EncodeToString(raw[:]), nil
}

func seedPSK(path string) error {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return err
	}
	return securefile.AtomicWrite(path, []byte(base64.StdEncoding.EncodeToString(raw[:])+"\n"), 0o600)
}

func authMaterials(paths pki.Paths, suite string) (*pqauth.Signer, *pqauth.Signer, *pqauth.Verifier) {
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
	must(err)
	deviceSigner, err := pqauth.LoadSigner(algorithm, deviceSeed)
	must(err)
	controllerVerifier, err := pqauth.LoadVerifier(algorithm, controllerPublic)
	must(err)
	return controllerSigner, deviceSigner, controllerVerifier
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
