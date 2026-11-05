//go:build unix

package main

// The carrier half of the subprocess contract.
//
// TestSubprocessCarriesRealDatagramsOverTheMasqueCarrier is the test that
// matters for an audit, and it is not a double at any layer. It runs the REAL
// winn-datapath binary as a subprocess, hands it a socket over SCM_RIGHTS the
// way the Android service does, and points it at the REAL H3 CONNECT-UDP
// (MASQUE) server from internal/carrier over a REAL TLS 1.3 x25519-mlkem768
// handshake with Encrypted Client Hello and ML-DSA request signing. The
// AmneziaWG outer datagrams that cross the duplex Inbound and Outbound frames
// are the same bytes the gateway receives.
//
// It is the answer to the one question the platform plan left open: whether
// anything can reach datapath.OpenWithCarrier from the process the Android host
// actually spawns.
//
// The rest of the file is the refusal matrix. Every case there is a way a
// winn/3 session could have quietly become something weaker, and each one is a
// hard failure instead.

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"winsvpn.local/winnprotocol/datapath"
	"winsvpn.local/winnprotocol/datapath/carrierhost"
	"winsvpn.local/winnprotocol/datapath/duplex"
	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/pki"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

const labSuite = "x25519-mlkem768"

// labCarrier is one running MASQUE carrier plus the material a client needs to
// authenticate to it.
type labCarrier struct {
	paths        pki.Paths
	template     string
	publicTarget string
	gateway      *net.UDPConn
}

// startLabMasqueCarrier stands up the echo "gateway", the H3 CONNECT-UDP server
// in front of it, and a lab PKI. Everything is torn down by t.Cleanup.
func startLabMasqueCarrier(t *testing.T) labCarrier {
	t.Helper()
	return startLabMasqueCarrierWithSuite(t, labSuite)
}

// startLabMasqueCarrierWithSuite is startLabMasqueCarrier for a server that
// offers a different hybrid group than the client profile names. It exists for
// the group-downgrade mutation check.
func startLabMasqueCarrierWithSuite(
	t *testing.T, suiteName string,
) labCarrier {
	t.Helper()

	gateway := newGateway(t)
	go func() {
		buffer := make([]byte, 4096)
		for {
			count, from, err := gateway.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			if _, err := gateway.WriteToUDP(buffer[:count], from); err != nil {
				return
			}
		}
	}()

	paths, err := pki.GenerateLab(
		t.TempDir()+"/pki", "127.0.0.1", "android-lab-1", time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("generate lab PKI: %v", err)
	}
	suite, err := tlsconfig.ParseSuite(suiteName)
	if err != nil {
		t.Fatal(err)
	}
	controllerSigner, err := pqauth.LoadSigner(
		pqauth.MLDSA87, paths.ControllerPQ87Seed,
	)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := pqauth.LoadRegistry(paths.DeviceRegistry)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := carrierauth.NewReplayCache(128)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	template := "https://" + listener.LocalAddr().String() +
		"/.well-known/masque/udp/{target_host}/{target_port}/"
	publicTarget := gateway.LocalAddr().String()
	handler, err := carrier.NewH3Server(
		template, publicTarget, publicTarget, suite,
		&carrierauth.RequestVerifier{
			Registry: registry, Replay: replay,
			Suite: suite.Name, MaxSkew: time.Minute,
		},
		controllerSigner, "lab-controller",
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close() })

	serverTLS, err := tlsconfig.ServerForALPN(
		paths.ServerCert, paths.ServerKey, paths.CACert, suite,
		http3.NextProtoH3,
	)
	if err != nil {
		t.Fatal(err)
	}
	// ECH is required on both sides. The dialer carrierhost builds always
	// demands an accepted Encrypted Client Hello, so a server without keys here
	// would fail the handshake — which is the correct behaviour and is why the
	// server is configured rather than the client relaxed.
	echKeys, err := echconfig.LoadServerKeys(paths.ECHServerKeys)
	if err != nil {
		t.Fatal(err)
	}
	if err := echconfig.ConfigureServer(serverTLS, echKeys, true); err != nil {
		t.Fatal(err)
	}

	server := &http3.Server{
		TLSConfig: serverTLS, Handler: handler, EnableDatagrams: true,
		QUICConfig: &quic.Config{
			EnableDatagrams: true, Allow0RTT: false,
			InitialPacketSize: carrier.H3InitialPacketSize(
				handler.MaxOuterDatagram,
			),
			HandshakeIdleTimeout: 10 * time.Second,
			MaxIdleTimeout:       30 * time.Second,
		},
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case err := <-serverDone:
			if err != nil && !errors.Is(err, http.ErrServerClosed) &&
				!errors.Is(err, net.ErrClosed) {
				t.Errorf("H3 server: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("H3 server did not stop")
		}
	})

	return labCarrier{
		paths:        paths,
		template:     template,
		publicTarget: publicTarget,
		gateway:      gateway,
	}
}

// writeCarrierProfile writes an owner-only profile document and returns its
// path. The mutate hook lets a refusal case change one field.
func writeCarrierProfile(
	t *testing.T,
	lab labCarrier,
	mutate func(*carrierhost.Profile),
) string {
	t.Helper()
	profile := carrierhost.Profile{
		Profile:            carrierhost.ProfileVersion,
		Carrier:            carrierhost.CarrierHTTP3,
		MASQUETemplate:     lab.template,
		PublicTarget:       lab.publicTarget,
		ServerName:         "127.0.0.1",
		Suite:              labSuite,
		ControllerID:       "lab-controller",
		ControllerPinsPath: lab.paths.ControllerPQPins,
		RootCAPath:         lab.paths.CACert,
		ECHConfigListPath:  lab.paths.ECHConfigList,
		AuthorizationMode:  carrierauth.AuthModeIdentity,
		DeviceID:           lab.paths.DeviceID,
		DeviceAlgorithm:    pqauth.MLDSA65,
		DeviceSeedPath:     lab.paths.DevicePQ65Seed,
		ClientCertPath:     lab.paths.DeviceCert,
		ClientKeyPath:      lab.paths.DeviceKey,
		SessionID:          "0123456789abcdef0123456789abcdef",
		ManifestDigest:     carrierauth.LabManifestDigest,
	}
	if mutate != nil {
		mutate(&profile)
	}
	blob, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp("", "winn-profile")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "carrier-profile.json")
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// carrierSession is one live conversation with a spawned engine.
type carrierSession struct {
	control     *net.UnixConn
	reader      *duplex.Reader
	writer      *duplex.Writer
	stderr      *bytes.Buffer
	socketLocal *net.UDPAddr
}

func (session *carrierSession) expect(
	t *testing.T, want duplex.Opcode,
) []byte {
	t.Helper()
	_ = session.control.SetReadDeadline(time.Now().Add(60 * time.Second))
	opcode, payload, err := session.reader.Read()
	if err != nil {
		t.Fatalf("expecting %s: %v (stderr: %s)",
			want, err, session.stderr.String())
	}
	if opcode != want {
		t.Fatalf("got %s (%q), want %s (stderr: %s)",
			opcode, payload, want, session.stderr.String())
	}
	return append([]byte(nil), payload...)
}

// spawnCarrierEngine runs the real binary with the Android argv shape, hands it
// a UDP socket over SCM_RIGHTS, and returns the live channel.
//
// profilePath == "" spawns the engine with no -carrier-profile, which is how the
// shipping host spawns it today.
func spawnCarrierEngine(t *testing.T, profilePath string) *carrierSession {
	t.Helper()
	binary := buildBinary(t)

	controlPath := shortSocketPath(t)
	listener, err := net.Listen("unix", controlPath)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	// The socket the host opens. On Android VpnService.protect(fd) has marked
	// this kernel socket by now, and the mark travels with the descriptor
	// because SCM_RIGHTS creates a second descriptor onto the same struct sock.
	// It is UNCONNECTED, which is what the HTTP/3 carrier requires.
	outer, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1), Port: 0,
	})
	if err != nil {
		t.Fatalf("open outer socket: %v", err)
	}
	outerAddr, ok := outer.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatal("outer socket has no UDP address")
	}
	handOver, err := outer.File()
	if err != nil {
		t.Fatalf("duplicate outer socket: %v", err)
	}
	t.Cleanup(func() { _ = handOver.Close() })

	arguments := []string{
		"-transport", "unix", "-control", controlPath, "-receive-fd",
	}
	if profilePath != "" {
		arguments = append(arguments, "-carrier-profile", profilePath)
	}
	command := exec.Command(binary, arguments...)
	stderr := &bytes.Buffer{}
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	t.Cleanup(func() { _ = command.Wait() })

	accepted, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept control connection: %v (stderr: %s)",
			err, stderr.String())
	}
	t.Cleanup(func() { _ = accepted.Close() })
	control, ok := accepted.(*net.UnixConn)
	if !ok {
		t.Fatal("accepted connection is not a unix socket")
	}
	rights := syscall.UnixRights(int(handOver.Fd()))
	if _, _, err := control.WriteMsgUnix([]byte{0}, rights, nil); err != nil {
		t.Fatalf("send descriptor: %v", err)
	}
	// The child holds its own descriptor onto the same socket now. Ours would
	// otherwise steal datagrams from it.
	_ = outer.Close()

	return &carrierSession{
		control:     control,
		reader:      duplex.NewReader(control, true),
		writer:      duplex.NewWriter(control),
		stderr:      stderr,
		socketLocal: outerAddr,
	}
}

// carrierCreateFrame is the Create payload for a carrier session. It is exactly
// datapath.Config and nothing more: the carrier's own configuration reached the
// engine on argv, not here.
func carrierCreateFrame(carrierName, gatewayEndpoint string) []byte {
	return []byte(`{"contract":"` + datapath.ContractVersion +
		`","payload":"` + datapath.PayloadAWGDatagram +
		`","carrier":"` + carrierName +
		`","gateway_endpoint":"` + gatewayEndpoint +
		`","session_id":"carrier-e2e"}`)
}

func TestSubprocessCarriesRealDatagramsOverTheMasqueCarrier(t *testing.T) {
	lab := startLabMasqueCarrier(t)
	profilePath := writeCarrierProfile(t, lab, nil)
	session := spawnCarrierEngine(t, profilePath)

	if err := session.writer.Write(
		duplex.OpCreate,
		carrierCreateFrame(datapath.CarrierHTTP3, lab.publicTarget),
	); err != nil {
		t.Fatalf("write create: %v", err)
	}
	var ready datapath.Status
	if err := json.Unmarshal(
		session.expect(t, duplex.OpCreateAck), &ready,
	); err != nil {
		t.Fatalf("decode create ack: %v", err)
	}

	if ready.Carrier != datapath.CarrierHTTP3 {
		t.Fatalf("status carrier = %q, want %q",
			ready.Carrier, datapath.CarrierHTTP3)
	}
	if ready.SocketOwnedByEngine {
		t.Fatal("the engine claims to own a socket the host handed it")
	}
	// The cross-layer proof. The carrier's local address is the QUIC
	// connection's local address, so this says the post-quantum handshake left
	// over the descriptor the host opened, protected and passed — not over one
	// the engine opened for itself.
	if ready.LocalEndpoint != session.socketLocal.String() {
		t.Fatalf(
			"carrier is bound to %s, want the host's protected socket %s",
			ready.LocalEndpoint, session.socketLocal,
		)
	}
	if ready.GatewaySenderFilter {
		t.Fatal("gateway_sender_filter is on for a carrier transport")
	}

	payloads := [][]byte{
		[]byte("awg-outer-datagram-one-through-the-subprocess"),
		[]byte("awg-outer-datagram-two-through-the-subprocess"),
	}
	for _, payload := range payloads {
		if err := session.writer.Write(duplex.OpInbound, payload); err != nil {
			t.Fatalf("write inbound: %v", err)
		}
		if got := session.expect(t, duplex.OpOutbound); !bytes.Equal(
			got, payload,
		) {
			t.Fatalf("outbound frame = %q, want %q", got, payload)
		}
	}

	if err := session.writer.Write(duplex.OpStatusRequest, nil); err != nil {
		t.Fatalf("write status request: %v", err)
	}
	var final datapath.Status
	if err := json.Unmarshal(
		session.expect(t, duplex.OpStatusResponse), &final,
	); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if final.TxDatagrams != uint64(len(payloads)) ||
		final.RxDatagrams != uint64(len(payloads)) {
		t.Fatalf("tx=%d rx=%d, want %d each",
			final.TxDatagrams, final.RxDatagrams, len(payloads))
	}
	if final.CarrierErr != "" {
		t.Fatalf("carrier reported %q", final.CarrierErr)
	}
	if !final.Up {
		t.Fatal("the carrier session is not up after a successful round trip")
	}

	if err := session.writer.Write(duplex.OpClose, nil); err != nil {
		t.Fatalf("write close: %v", err)
	}
	if payload := session.expect(t, duplex.OpCloseAck); len(payload) != 0 {
		t.Fatalf("close-ack carried %d bytes, must be empty", len(payload))
	}
}

// TestTheProfileSuiteIsLoadBearing is the mutation check behind the headline
// claim. The passing test above only shows that A post-quantum handshake
// happened; this one shows the session is bound to the group the PROFILE names
// and cannot be moved onto a different one by the server.
//
// The mechanism is tlsconfig.validateState, which internal/carrier installs as
// VerifyConnection: it compares tls.ConnectionState.CurveID against the
// profile's suite and tears the connection down on any other value. So a server
// offering p384-mlkem1024 to a client whose profile says x25519-mlkem768 must
// fail to produce a tunnel, and the CreateAck must never arrive.
func TestTheProfileSuiteIsLoadBearing(t *testing.T) {
	lab := startLabMasqueCarrierWithSuite(t, "p384-mlkem1024")
	profilePath := writeCarrierProfile(t, lab, func(profile *carrierhost.Profile) {
		profile.Suite = labSuite
	})
	session := spawnCarrierEngine(t, profilePath)

	if err := session.writer.Write(
		duplex.OpCreate,
		carrierCreateFrame(datapath.CarrierHTTP3, lab.publicTarget),
	); err != nil {
		t.Fatalf("write create: %v", err)
	}
	failure := string(session.expect(t, duplex.OpError))
	if failure == "" {
		t.Fatal("a group mismatch produced an empty refusal")
	}
	if strings.Contains(failure, "\"up\":true") {
		t.Fatalf("a group mismatch produced a live tunnel: %s", failure)
	}
}

// TestSubprocessRefusesACarrierConfigurationWithNoProfile is the anti-downgrade
// property restated at the engine boundary: a configuration that asks for a
// carrier must not silently become direct-awg because nothing was there to
// build the carrier with.
func TestSubprocessRefusesACarrierConfigurationWithNoProfile(t *testing.T) {
	lab := startLabMasqueCarrier(t)
	session := spawnCarrierEngine(t, "")

	if err := session.writer.Write(
		duplex.OpCreate,
		carrierCreateFrame(datapath.CarrierHTTP3, lab.publicTarget),
	); err != nil {
		t.Fatalf("write create: %v", err)
	}
	failure := string(session.expect(t, duplex.OpError))
	if !strings.Contains(failure, "OpenWithCarrier") {
		t.Fatalf("refusal did not name the missing dialer: %s", failure)
	}
}

// TestSubprocessRefusesDirectAWGWhenGivenACarrierProfile is the same property
// from the other direction. An engine started for an authenticated carrier must
// not be talked back down to the unauthenticated one by the Create frame, which
// is the document a peer controls.
func TestSubprocessRefusesDirectAWGWhenGivenACarrierProfile(t *testing.T) {
	lab := startLabMasqueCarrier(t)
	profilePath := writeCarrierProfile(t, lab, nil)
	session := spawnCarrierEngine(t, profilePath)

	if err := session.writer.Write(
		duplex.OpCreate,
		carrierCreateFrame(datapath.CarrierDirectAWG, lab.publicTarget),
	); err != nil {
		t.Fatalf("write create: %v", err)
	}
	failure := string(session.expect(t, duplex.OpError))
	if !strings.Contains(failure, datapath.CarrierDirectAWG) ||
		!strings.Contains(failure, "refusing") {
		t.Fatalf("refusal text = %s", failure)
	}
}

// TestSubprocessRefusesACarrierDisagreement covers the third combination: both
// documents name a carrier, and they are different ones.
func TestSubprocessRefusesACarrierDisagreement(t *testing.T) {
	lab := startLabMasqueCarrier(t)
	profilePath := writeCarrierProfile(t, lab, nil)
	session := spawnCarrierEngine(t, profilePath)

	if err := session.writer.Write(
		duplex.OpCreate,
		carrierCreateFrame(datapath.CarrierHTTP2, lab.publicTarget),
	); err != nil {
		t.Fatalf("write create: %v", err)
	}
	failure := string(session.expect(t, duplex.OpError))
	if !strings.Contains(failure, "disagreement") {
		t.Fatalf("refusal text = %s", failure)
	}
}

// TestACarrierMayNotOpenItsOwnSocket is the Android socket rule, restated for
// the carrier path.
//
// Without a protected descriptor the carrier must fail rather than dial one of
// its own: an unmarked socket's packets match the routes VpnService just
// installed, are written back into the tunnel, and loop with nothing leaving the
// device. allow_own_socket is false in every configuration the Android host
// builds, so this is the branch that has to hold.
func TestACarrierMayNotOpenItsOwnSocket(t *testing.T) {
	lab := startLabMasqueCarrier(t)
	binary := buildBinary(t)
	profilePath := writeCarrierProfile(t, lab, nil)

	command := exec.Command(binary,
		"-transport", "stdio", "-carrier-profile", profilePath)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := &bytes.Buffer{}
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = command.Wait()
	})

	// No -udp-fd and no -receive-fd, so the engine holds descriptor -1.
	if err := duplex.NewWriter(stdin).Write(
		duplex.OpCreate,
		carrierCreateFrame(datapath.CarrierHTTP3, lab.publicTarget),
	); err != nil {
		t.Fatalf("write create: %v", err)
	}
	opcode, payload, err := duplex.NewReader(stdout, true).Read()
	if err != nil {
		t.Fatalf("read reply: %v (stderr: %s)", err, stderr.String())
	}
	if opcode != duplex.OpError {
		t.Fatalf("got %s (%q), want %s", opcode, payload, duplex.OpError)
	}
	if !strings.Contains(string(payload), "allow_own_socket") {
		t.Fatalf("refusal did not name the socket rule: %s", payload)
	}
}

// TestEngineRefusesToStartOnAnUnusableProfile proves the profile is validated
// before a transport exists. A bad profile has to kill the process on stderr,
// because by the time a Create frame arrives the host has already protected a
// socket and let go of the descriptor.
func TestEngineRefusesToStartOnAnUnusableProfile(t *testing.T) {
	lab := startLabMasqueCarrier(t)
	binary := buildBinary(t)

	cases := map[string]func(*carrierhost.Profile){
		"manifest route": func(profile *carrierhost.Profile) {
			profile.ManifestPath = lab.paths.CACert
		},
		"anonymous route": func(profile *carrierhost.Profile) {
			profile.AuthorizationMode = carrierauth.AuthModeAnonymousToken
		},
		"missing controller pins": func(profile *carrierhost.Profile) {
			profile.ControllerPinsPath = ""
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			profilePath := writeCarrierProfile(t, lab, mutate)
			output, err := exec.Command(binary,
				"-transport", "unix",
				"-control", shortSocketPath(t),
				"-receive-fd",
				"-carrier-profile", profilePath,
			).CombinedOutput()
			if err == nil {
				t.Fatalf("the engine started on an unusable profile: %s", output)
			}
			if len(bytes.TrimSpace(output)) == 0 {
				t.Fatal("the engine failed without saying why")
			}
		})
	}
}

// TestPrintContractAdvertisesTheCarrierSeam lets a host discover, without
// spawning a tunnel, whether the binary it packaged can be given a profile.
func TestPrintContractAdvertisesTheCarrierSeam(t *testing.T) {
	binary := buildBinary(t)
	output, err := exec.Command(binary, "-print-contract").Output()
	if err != nil {
		t.Fatalf("-print-contract: %v", err)
	}
	var banner Contract
	if err := json.Unmarshal(bytes.TrimSpace(output), &banner); err != nil {
		t.Fatalf("decode contract banner %q: %v", output, err)
	}
	if banner.CarrierProfileVersion != carrierhost.ProfileVersion {
		t.Fatalf("banner carrier profile version = %q, want %q",
			banner.CarrierProfileVersion, carrierhost.ProfileVersion)
	}
	for _, want := range []string{
		datapath.CarrierDirectAWG,
		carrierhost.CarrierHTTP3,
		carrierhost.CarrierHTTP2,
	} {
		if !contains(banner.Carriers, want) {
			t.Fatalf("banner carriers %v omit %q", banner.Carriers, want)
		}
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
