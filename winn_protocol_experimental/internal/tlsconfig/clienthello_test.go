package tlsconfig_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"

	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/pki"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

// These tests measure the ClientHello this package actually puts on the wire.
//
// Everything a censor's DPI sees on a client's first flight is in those bytes,
// so the assertions are written against the parsed wire image rather than
// against the tls.Config that produced it. A configuration field can be right
// while the bytes are wrong - crypto/tls treats CurvePreferences as a filter
// over its own fixed order, not as the order to send - and it is the bytes that
// get a user identified.
//
// When ECH is in use the captured bytes are the *outer* hello, the one a censor
// reads. crypto/tls derives it from the inner hello by replacing only the
// server name, the random and the ECH extension, so every other field below is
// visible in clear text on the wire.

const captureTimeout = 10 * time.Second

type parsedClientHello struct {
	legacyVersion     uint16
	sessionIDLen      int
	cipherSuites      []uint16
	extensions        []uint16 // in wire order
	serverName        string
	supportedGroups   []uint16
	keyShareGroups    []uint16
	supportedVersions []uint16
	signatureSchemes  []uint16
	alpn              []string
}

// isGREASE reports whether a value is one of the reserved codepoints of RFC
// 8701. Browsers emit them in several fields; crypto/tls never does, so their
// absence is one of the strongest single discriminators against this client.
func isGREASE(value uint16) bool {
	return value&0x0f0f == 0x0a0a && byte(value>>8) == byte(value)
}

func anyGREASE(values []uint16) bool {
	return slices.ContainsFunc(values, isGREASE)
}

// TestClientCurvePreferencesKeepsTheRequiredGroupFirst is the guard on the one
// invariant the widened offer depends on.
//
// crypto/tls sends a key share for the first surviving group only. If a group
// Winn does not use ever sorts ahead of the required one, every connection
// draws a HelloRetryRequest - a second round trip that is rarer on the modern
// web, and so a louder signature, than the narrow group list it replaced. Go's
// default order is not API, so this has to be checked rather than assumed.
func TestClientCurvePreferencesKeepsTheRequiredGroupFirst(t *testing.T) {
	for _, suiteName := range protocol.SupportedSuites() {
		t.Run(suiteName, func(t *testing.T) {
			suite, err := tlsconfig.ParseSuite(suiteName)
			if err != nil {
				t.Fatal(err)
			}
			offered := tlsconfig.ClientCurvePreferences(suite)
			if len(offered) == 0 {
				t.Fatal("no groups offered")
			}
			if offered[0] != suite.Curve {
				t.Fatalf(
					"offered[0] = %v, want the required group %v; any other first "+
						"entry makes crypto/tls key-share the wrong group and draws a "+
						"HelloRetryRequest on every connection",
					offered[0], suite.Curve,
				)
			}
			if len(offered) < 2 {
				t.Fatalf(
					"only %d group offered; a single-group supported_groups is the "+
						"first-flight identifier this list exists to remove",
					len(offered),
				)
			}
		})
	}
}

// TestClientHelloOffersASpreadOfKeyAgreementGroups is the wire-level regression
// test for finding 4's supported_groups half: the shipped client configuration
// must not name exactly one group.
func TestClientHelloOffersASpreadOfKeyAgreementGroups(t *testing.T) {
	lab := newLab(t)
	for _, suiteName := range protocol.SupportedSuites() {
		t.Run(suiteName, func(t *testing.T) {
			suite, err := tlsconfig.ParseSuite(suiteName)
			if err != nil {
				t.Fatal(err)
			}
			hello := captureClientHello(t, lab.clientConfig(t, suite, true, "h2"))

			if len(hello.supportedGroups) < 2 {
				t.Fatalf(
					"supported_groups on the wire = %v; one group is a first-flight "+
						"identifier for this tool", hexes(hello.supportedGroups),
				)
			}
			if hello.supportedGroups[0] != uint16(suite.Curve) {
				t.Fatalf("supported_groups[0] = 0x%04x, want 0x%04x",
					hello.supportedGroups[0], uint16(suite.Curve))
			}
			// One key share, for the required group, plus crypto/tls's classical
			// fallback share. Anything else means a HelloRetryRequest is coming.
			if len(hello.keyShareGroups) == 0 ||
				hello.keyShareGroups[0] != uint16(suite.Curve) {
				t.Fatalf("key_share = %v, want the required group first",
					hexes(hello.keyShareGroups))
			}
			if hello.serverName == lab.serverName {
				t.Fatal("outer SNI leaked the private server name; ECH was not applied")
			}
		})
	}
}

// TestClientHelloMatchesAStockGoClientWithECH states the achievable claim
// precisely, and holds it.
//
// The client cannot be made to look like a browser - see
// docs/CLIENT_TLS_FINGERPRINT.md for why that is structural, not a matter of
// effort. What it can do is stop being separable from the population of
// ordinary Go TLS clients that use ECH, which is what this asserts, field by
// field, for the one suite that can reach it.
func TestClientHelloMatchesAStockGoClientWithECH(t *testing.T) {
	lab := newLab(t)
	suite, err := tlsconfig.ParseSuite(protocol.SuiteX25519MLKEM768)
	if err != nil {
		t.Fatal(err)
	}
	winn := captureClientHello(t, lab.clientConfig(t, suite, true, "h2"))

	// A default-configured Go client: no CurvePreferences, no version pinning,
	// only the ECH list and the ALPN the caller would have chosen anyway.
	stock := captureClientHello(t, &tls.Config{
		ServerName:                     lab.serverName,
		RootCAs:                        lab.rootCAs(t),
		NextProtos:                     []string{"h2"},
		EncryptedClientHelloConfigList: lab.echList(t),
	})

	if !slices.Equal(winn.supportedGroups, stock.supportedGroups) {
		t.Fatalf("supported_groups %v, stock Go sends %v",
			hexes(winn.supportedGroups), hexes(stock.supportedGroups))
	}
	if !slices.Equal(winn.keyShareGroups, stock.keyShareGroups) {
		t.Fatalf("key_share %v, stock Go sends %v",
			hexes(winn.keyShareGroups), hexes(stock.keyShareGroups))
	}
	if !slices.Equal(winn.extensions, stock.extensions) {
		t.Fatalf("extensions %v, stock Go sends %v",
			hexes(winn.extensions), hexes(stock.extensions))
	}
	if !slices.Equal(winn.cipherSuites, stock.cipherSuites) {
		t.Fatalf("cipher_suites %v, stock Go sends %v",
			hexes(winn.cipherSuites), hexes(stock.cipherSuites))
	}
	if !slices.Equal(winn.supportedVersions, stock.supportedVersions) {
		t.Fatalf("supported_versions %v, stock Go sends %v",
			hexes(winn.supportedVersions), hexes(stock.supportedVersions))
	}
	if !slices.Equal(winn.signatureSchemes, stock.signatureSchemes) {
		t.Fatalf("signature_algorithms %v, stock Go sends %v",
			hexes(winn.signatureSchemes), hexes(stock.signatureSchemes))
	}
	if winn.sessionIDLen != stock.sessionIDLen ||
		winn.legacyVersion != stock.legacyVersion {
		t.Fatalf("record prefix differs: %+v vs %+v", winn, stock)
	}
}

// TestWidenedOfferStillRefusesAnUnwantedKeyAgreement is the load-bearing test.
//
// Before the offer was widened, crypto/tls itself refused any group but the
// required one, because none other was ever advertised. Several are advertised
// now, so the refusal has to be explicit - and it has to still happen before
// the client authenticates. This drives a real handshake against a server that
// will only do classical X25519, a group the client now offers, and requires
// that the client tears the connection down without ever sending its
// certificate.
//
// If this test fails, the widened offer has become a downgrade.
func TestWidenedOfferStillRefusesAnUnwantedKeyAgreement(t *testing.T) {
	lab := newLab(t)
	suite, err := tlsconfig.ParseSuite(protocol.SuiteX25519MLKEM768)
	if err != nil {
		t.Fatal(err)
	}

	certificate, err := tls.LoadX509KeyPair(lab.paths.ServerCert, lab.paths.ServerKey)
	if err != nil {
		t.Fatal(err)
	}
	sawClientCertificate := false
	downgradingServer := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		// Classical only. A censor-operated or compromised endpoint that wants
		// the connection without post-quantum protection looks exactly like
		// this.
		CurvePreferences: []tls.CurveID{tls.X25519},
		NextProtos:       []string{"h2"},
		ClientAuth:       tls.RequireAnyClientCert,
		VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error {
			sawClientCertificate = true
			return nil
		},
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		server := tls.Server(connection, downgradingServer)
		_ = connection.SetDeadline(time.Now().Add(captureTimeout))
		_ = server.Handshake()
	}()

	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(captureTimeout))
	client := tls.Client(connection, lab.clientConfig(t, suite, false, "h2"))
	handshakeErr := client.Handshake()
	<-done

	if handshakeErr == nil {
		t.Fatal(
			"handshake completed on classical X25519; the widened group offer " +
				"has become a downgrade and the post-handshake key-agreement " +
				"re-verification is no longer load-bearing",
		)
	}
	if sawClientCertificate {
		t.Fatal(
			"client sent its certificate before refusing the downgraded key " +
				"agreement; the refusal must stay ahead of client authentication",
		)
	}
	if state := client.ConnectionState(); state.HandshakeComplete {
		t.Fatal("client reports a complete handshake after refusing the peer")
	}
}

// TestValidateKeyAgreementRefusesEveryGroupButTheSuite covers the enforcement
// helper directly, including the classical groups the widened offer added.
func TestValidateKeyAgreementRefusesEveryGroupButTheSuite(t *testing.T) {
	suite, err := tlsconfig.ParseSuite(protocol.SuiteX25519MLKEM768)
	if err != nil {
		t.Fatal(err)
	}
	if err := tlsconfig.ValidateKeyAgreement(&tls.ConnectionState{
		Version: tls.VersionTLS13, CurveID: suite.Curve,
	}, suite); err != nil {
		t.Fatalf("required group refused: %v", err)
	}
	for _, offered := range tlsconfig.ClientCurvePreferences(suite) {
		if offered == suite.Curve {
			continue
		}
		if err := tlsconfig.ValidateKeyAgreement(&tls.ConnectionState{
			Version: tls.VersionTLS13, CurveID: offered,
		}, suite); err == nil {
			t.Fatalf("group %v is advertised and was accepted; offering a group "+
				"must never mean accepting it", offered)
		}
	}
	if err := tlsconfig.ValidateKeyAgreement(&tls.ConnectionState{
		Version: tls.VersionTLS12, CurveID: suite.Curve,
	}, suite); err == nil {
		t.Fatal("TLS 1.2 accepted")
	}
	if err := tlsconfig.ValidateKeyAgreement(nil, suite); err == nil {
		t.Fatal("nil connection state accepted")
	}
}

// TestClientHelloDistinguishersThatRemain records, as executable fact, the
// discriminators that are still on the wire after this work.
//
// It is not a test of a defence. It exists so that the claims in
// docs/CLIENT_TLS_FINGERPRINT.md cannot quietly go stale, and so that anyone
// who does close one of these has to come here and say so. Every assertion
// below is a property a censor can key on today.
func TestClientHelloDistinguishersThatRemain(t *testing.T) {
	lab := newLab(t)
	suite, err := tlsconfig.ParseSuite(protocol.SuiteX25519MLKEM768)
	if err != nil {
		t.Fatal(err)
	}
	hello := captureClientHello(t, lab.clientConfig(t, suite, true, "h2"))

	if len(hello.cipherSuites) != 3 {
		t.Fatalf("cipher_suites has %d entries, documented as 3 (TLS 1.3 suites "+
			"are not configurable in crypto/tls); update the fingerprint doc",
			len(hello.cipherSuites))
	}
	if len(hello.supportedVersions) != 1 ||
		hello.supportedVersions[0] != tls.VersionTLS13 {
		t.Fatalf("supported_versions = %v, documented as TLS 1.3 alone because "+
			"crypto/tls forbids MinVersion below TLS 1.3 when ECH is configured; "+
			"update the fingerprint doc", hexes(hello.supportedVersions))
	}
	if anyGREASE(hello.cipherSuites) || anyGREASE(hello.extensions) ||
		anyGREASE(hello.supportedGroups) || anyGREASE(hello.supportedVersions) {
		t.Fatal("GREASE appeared on the wire; crypto/tls does not emit it, so " +
			"either the TLS stack changed or a mimicry layer landed - update the " +
			"fingerprint doc either way")
	}
	// crypto/tls marshals extensions in a fixed order and offers no way to
	// permute them. Chrome permutes per connection, so a stable order is itself
	// a discriminator; the order is recorded in the fingerprint doc.
	if len(hello.extensions) == 0 {
		t.Fatal("no extensions parsed")
	}
}

// TestOuterALPNMatchesABrowserOverTCP pins the wire encoding of the H2 carrier's
// ALPN offer.
//
// ALPN travels in the clear in the outer ClientHello even under ECH, so the
// offer is visible to a passive observer. A browser dialing TCP offers h2 and
// http/1.1 together; the Winn H2 client offered h2 alone, which no ordinary
// client sends. This asserts both protocols reach the wire, in order.
//
// The companion test is TestNewH2DialerOffersBrowserShapedALPN in
// internal/carrier, which pins that the shipped constructor actually builds this
// list. Two tests are needed because internal/carrier imports internal/tlsconfig,
// so this package cannot reach NewH2Dialer without an import cycle: this one
// proves the bytes, that one proves the product path produces them.
func TestOuterALPNMatchesABrowserOverTCP(t *testing.T) {
	lab := newLab(t)
	suite, err := tlsconfig.ParseSuite(protocol.SuiteX25519MLKEM768)
	if err != nil {
		t.Fatal(err)
	}
	hello := captureClientHello(
		t, lab.clientConfig(t, suite, true, "h2", "http/1.1"),
	)

	want := []string{"h2", "http/1.1"}
	if !slices.Equal(hello.alpn, want) {
		t.Fatalf("outer ALPN = %v, want %v; a single-protocol ALPN is a "+
			"discriminator no browser produces", hello.alpn, want)
	}
}

// TestSecPSuitesCannotMatchTheStockOffer records the finding that the two
// SecP hybrid suites are fingerprintable by construction.
//
// crypto/tls will only key-share the first surviving group, so keeping a SecP
// hybrid as the key share means dropping X25519MLKEM768 - and a post-quantum
// client that omits the only post-quantum group every browser offers is, by
// that omission, unique. No mimicry layer can fix this: uTLS does not implement
// these groups at all, and neither BoringSSL nor Firefox can construct them, so
// there is no traffic for such a hello to hide in.
func TestSecPSuitesCannotMatchTheStockOffer(t *testing.T) {
	reference, err := tlsconfig.ParseSuite(protocol.SuiteX25519MLKEM768)
	if err != nil {
		t.Fatal(err)
	}
	stock := tlsconfig.ClientCurvePreferences(reference)
	for _, suiteName := range []string{
		protocol.SuiteP256MLKEM768, protocol.SuiteP384MLKEM1024,
	} {
		suite, err := tlsconfig.ParseSuite(suiteName)
		if err != nil {
			t.Fatal(err)
		}
		offered := tlsconfig.ClientCurvePreferences(suite)
		if slices.Equal(offered, stock) {
			t.Fatalf("%s now offers the stock group set (%v); if that became "+
				"reachable the fingerprint doc's suite guidance is wrong",
				suiteName, offered)
		}
		if slices.Contains(offered, reference.Curve) {
			t.Fatalf("%s offers X25519MLKEM768, which sorts ahead of its required "+
				"group and would draw a HelloRetryRequest on every connection",
				suiteName)
		}
	}
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

type labFixture struct {
	paths      pki.Paths
	serverName string
}

func newLab(t *testing.T) *labFixture {
	t.Helper()
	paths, err := pki.GenerateLab(
		filepath.Join(t.TempDir(), "pki"), "localhost", "fingerprint-device-1",
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return &labFixture{paths: paths, serverName: "localhost"}
}

func (l *labFixture) echList(t *testing.T) []byte {
	t.Helper()
	list, err := echconfig.LoadClientConfigList(l.paths.ECHConfigList)
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func (l *labFixture) rootCAs(t *testing.T) *x509.CertPool {
	t.Helper()
	config, err := tlsconfig.ClientAnonymousForALPN(
		l.paths.CACert, l.serverName, mustSuite(t, protocol.SuiteX25519MLKEM768),
		"h2",
	)
	if err != nil {
		t.Fatal(err)
	}
	return config.RootCAs
}

// clientConfig builds the configuration the shipped client builds, through the
// exported constructors, so these tests break if the product path stops using
// them.
func (l *labFixture) clientConfig(
	t *testing.T, suite tlsconfig.Suite, withECH bool, alpn ...string,
) *tls.Config {
	t.Helper()
	config, err := tlsconfig.ClientForALPN(
		l.paths.DeviceCert, l.paths.DeviceKey, l.paths.CACert,
		l.serverName, suite, alpn...,
	)
	if err != nil {
		t.Fatal(err)
	}
	if withECH {
		if err := echconfig.ConfigureClient(config, l.echList(t), true); err != nil {
			t.Fatal(err)
		}
	}
	return config
}

func mustSuite(t *testing.T, name string) tlsconfig.Suite {
	t.Helper()
	suite, err := tlsconfig.ParseSuite(name)
	if err != nil {
		t.Fatal(err)
	}
	return suite
}

// captureClientHello runs one client handshake against a listener that reads
// the first flight and hangs up, then parses the raw bytes. The handshake
// cannot complete; the bytes are the point.
func captureClientHello(t *testing.T, config *tls.Config) parsedClientHello {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	type capture struct {
		record []byte
		err    error
	}
	captured := make(chan capture, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			captured <- capture{err: err}
			return
		}
		defer connection.Close()
		_ = connection.SetReadDeadline(time.Now().Add(captureTimeout))
		header := make([]byte, 5)
		if _, err := io.ReadFull(connection, header); err != nil {
			captured <- capture{err: fmt.Errorf("read record header: %w", err)}
			return
		}
		if header[0] != 22 {
			captured <- capture{err: fmt.Errorf(
				"first record type %d, want handshake", header[0])}
			return
		}
		body := make([]byte, binary.BigEndian.Uint16(header[3:5]))
		if _, err := io.ReadFull(connection, body); err != nil {
			captured <- capture{err: fmt.Errorf("read record body: %w", err)}
			return
		}
		captured <- capture{record: body}
	}()

	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(captureTimeout))
	client := tls.Client(connection, config)
	_ = client.Handshake() // expected to fail; the listener never answers

	result := <-captured
	if result.err != nil {
		t.Fatalf("capture ClientHello: %v", result.err)
	}
	hello, err := parseClientHello(result.record)
	if err != nil {
		t.Fatalf("parse ClientHello: %v", err)
	}
	return hello
}

func parseClientHello(record []byte) (parsedClientHello, error) {
	var hello parsedClientHello
	input := cryptobyte.String(record)

	var messageType uint8
	var body cryptobyte.String
	if !input.ReadUint8(&messageType) || messageType != 1 ||
		!input.ReadUint24LengthPrefixed(&body) {
		return hello, errors.New("not a ClientHello handshake message")
	}
	var sessionID, compression, cipherSuites cryptobyte.String
	if !body.ReadUint16(&hello.legacyVersion) ||
		!body.Skip(32) ||
		!body.ReadUint8LengthPrefixed(&sessionID) ||
		!body.ReadUint16LengthPrefixed(&cipherSuites) ||
		!body.ReadUint8LengthPrefixed(&compression) {
		return hello, errors.New("malformed ClientHello prefix")
	}
	hello.sessionIDLen = len(sessionID)
	for !cipherSuites.Empty() {
		var suite uint16
		if !cipherSuites.ReadUint16(&suite) {
			return hello, errors.New("malformed cipher suites")
		}
		hello.cipherSuites = append(hello.cipherSuites, suite)
	}

	var extensions cryptobyte.String
	if !body.ReadUint16LengthPrefixed(&extensions) {
		return hello, errors.New("malformed extension block")
	}
	for !extensions.Empty() {
		var extensionType uint16
		var data cryptobyte.String
		if !extensions.ReadUint16(&extensionType) ||
			!extensions.ReadUint16LengthPrefixed(&data) {
			return hello, errors.New("malformed extension")
		}
		hello.extensions = append(hello.extensions, extensionType)
		if err := parseExtensionBody(&hello, extensionType, data); err != nil {
			return hello, err
		}
	}
	return hello, nil
}

const (
	extServerName          uint16 = 0
	extSupportedGroups     uint16 = 10
	extSignatureAlgorithms uint16 = 13
	extALPN                uint16 = 16
	extSupportedVersions   uint16 = 43
	extKeyShare            uint16 = 51
)

func parseExtensionBody(
	hello *parsedClientHello, extensionType uint16, data cryptobyte.String,
) error {
	switch extensionType {
	case extServerName:
		var nameList cryptobyte.String
		if !data.ReadUint16LengthPrefixed(&nameList) {
			return errors.New("malformed server_name")
		}
		var nameType uint8
		var name cryptobyte.String
		if !nameList.ReadUint8(&nameType) || nameType != 0 ||
			!nameList.ReadUint16LengthPrefixed(&name) {
			return errors.New("malformed server_name entry")
		}
		hello.serverName = string(name)
	case extSupportedGroups:
		groups, err := readUint16Vector16(data)
		if err != nil {
			return fmt.Errorf("supported_groups: %w", err)
		}
		hello.supportedGroups = groups
	case extKeyShare:
		var shares cryptobyte.String
		if !data.ReadUint16LengthPrefixed(&shares) {
			return errors.New("malformed key_share")
		}
		for !shares.Empty() {
			var group uint16
			var share cryptobyte.String
			if !shares.ReadUint16(&group) ||
				!shares.ReadUint16LengthPrefixed(&share) {
				return errors.New("malformed key_share entry")
			}
			hello.keyShareGroups = append(hello.keyShareGroups, group)
		}
	case extSupportedVersions:
		var versions cryptobyte.String
		if !data.ReadUint8LengthPrefixed(&versions) {
			return errors.New("malformed supported_versions")
		}
		for !versions.Empty() {
			var version uint16
			if !versions.ReadUint16(&version) {
				return errors.New("malformed version")
			}
			hello.supportedVersions = append(hello.supportedVersions, version)
		}
	case extSignatureAlgorithms:
		schemes, err := readUint16Vector16(data)
		if err != nil {
			return fmt.Errorf("signature_algorithms: %w", err)
		}
		hello.signatureSchemes = schemes
	case extALPN:
		var protocols cryptobyte.String
		if !data.ReadUint16LengthPrefixed(&protocols) {
			return errors.New("malformed ALPN")
		}
		for !protocols.Empty() {
			var name cryptobyte.String
			if !protocols.ReadUint8LengthPrefixed(&name) {
				return errors.New("malformed ALPN entry")
			}
			hello.alpn = append(hello.alpn, string(name))
		}
	}
	return nil
}

func readUint16Vector16(data cryptobyte.String) ([]uint16, error) {
	var body cryptobyte.String
	if !data.ReadUint16LengthPrefixed(&body) {
		return nil, errors.New("malformed vector")
	}
	var values []uint16
	for !body.Empty() {
		var value uint16
		if !body.ReadUint16(&value) {
			return nil, errors.New("malformed element")
		}
		values = append(values, value)
	}
	return values, nil
}

func hexes(values []uint16) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, fmt.Sprintf("0x%04x", value))
	}
	return out
}
