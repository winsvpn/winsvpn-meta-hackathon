package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/gatewaymanifest"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/privacytoken"
	"winsvpn.local/winnprotocol/internal/securefile"
	"winsvpn.local/winnprotocol/internal/transparency"
)

func main() {
	var action string
	var manifestPath string
	var outputPath string
	var pinsPath string
	var signerSeed string
	var signerAlgorithm string
	var logPath string
	var checkpointPath string
	var controllerID string
	var suiteName string
	var sequence uint64
	var lifetime time.Duration
	var nodeID string
	var masqueTemplate string
	var h2URL string
	var serverName string
	var echConfigPath string
	var maxDatagram int
	var authorizationModes string
	var tokenPublicPath string
	var tokenScope string
	var previousDigest string
	flag.StringVar(&action, "action", "", "create, sign, verify, append, or verify-log")
	flag.StringVar(&manifestPath, "manifest", "", "gateway manifest JSON")
	flag.StringVar(&outputPath, "out", "", "signed manifest output (create/sign)")
	flag.StringVar(&pinsPath, "controller-pq-pins", "", "controller ML-DSA verifier set")
	flag.StringVar(&signerSeed, "controller-pq-seed", "", "controller ML-DSA seed")
	flag.StringVar(&signerAlgorithm, "controller-pq-algorithm", pqauth.MLDSA87, "controller ML-DSA algorithm")
	flag.StringVar(&logPath, "transparency-log", "", "append-only transparency receipt log")
	flag.StringVar(&checkpointPath, "checkpoint", "", "checkpoint JSON to write or require")
	flag.StringVar(&controllerID, "controller-id", "", "manifest controller identity (create)")
	flag.StringVar(&suiteName, "suite", "x25519-mlkem768", "manifest hybrid TLS suite (create)")
	flag.Uint64Var(&sequence, "sequence", 1, "monotonic manifest sequence (create)")
	flag.DurationVar(&lifetime, "lifetime", 24*time.Hour, "manifest lifetime, maximum seven days (create)")
	flag.StringVar(&nodeID, "node-id", "", "gateway node identity (create)")
	flag.StringVar(&masqueTemplate, "masque-template", "", "gateway HTTPS MASQUE template (create)")
	flag.StringVar(&h2URL, "h2-url", "", "gateway HTTPS H2 URL (create)")
	flag.StringVar(&serverName, "server-name", "", "gateway TLS server name (create)")
	flag.StringVar(&echConfigPath, "ech-config-list", "", "gateway RFC 9849 ECHConfigList (create)")
	flag.IntVar(&maxDatagram, "max-datagram", 1350, "gateway maximum inner datagram (create)")
	flag.StringVar(&authorizationModes, "authorization-modes", "identity", "comma-separated identity and/or anonymous-token (create)")
	flag.StringVar(&tokenPublicPath, "privacy-token-public-key", "", "optional RSA blind-token public key PEM (create)")
	flag.StringVar(&tokenScope, "privacy-token-scope", "", "token scope, normally carrier:HOST:PORT (create)")
	flag.StringVar(&previousDigest, "previous-digest", "", "previous signed manifest digest (create)")
	flag.Parse()

	switch action {
	case "create":
		require(outputPath, "-out")
		require(signerSeed, "-controller-pq-seed")
		require(controllerID, "-controller-id")
		require(nodeID, "-node-id")
		require(masqueTemplate, "-masque-template")
		require(h2URL, "-h2-url")
		require(serverName, "-server-name")
		require(echConfigPath, "-ech-config-list")
		if sequence == 0 || lifetime <= 0 ||
			lifetime > gatewaymanifest.MaxLifetime {
			exitError(errors.New("sequence and lifetime are invalid"))
		}
		echList, err := echconfig.LoadClientConfigList(echConfigPath)
		if err != nil {
			exitError(err)
		}
		now := time.Now().UTC()
		expires := now.Add(lifetime)
		modes := splitModes(authorizationModes)
		capabilities := gatewaymanifest.RequiredCapabilities()
		manifest := gatewaymanifest.Manifest{
			Format: gatewaymanifest.Format, Sequence: sequence,
			IssuedAt:     now.Format(time.RFC3339Nano),
			ExpiresAt:    expires.Format(time.RFC3339Nano),
			ControllerID: controllerID, Suite: suiteName,
			MinimumClient: "winn/2.2", PreviousDigest: previousDigest,
			Capabilities: capabilities,
			Nodes: []gatewaymanifest.Node{{
				ID: nodeID, MASQUETemplate: masqueTemplate, H2URL: h2URL,
				ServerName:          serverName,
				ECHConfigList:       base64.StdEncoding.EncodeToString(echList),
				MaxInnerDatagram:    maxDatagram,
				AuthenticationModes: modes, Capabilities: capabilities,
			}},
		}
		clear(echList)
		if tokenPublicPath != "" {
			if tokenScope == "" ||
				!contains(modes, gatewaymanifest.AuthAnonymousToken) {
				exitError(errors.New("privacy-token-scope and anonymous-token mode are required with a token key"))
			}
			publicKey, err := privacytoken.LoadIssuerPublicKey(tokenPublicPath)
			if err != nil {
				exitError(err)
			}
			der, err := x509.MarshalPKIXPublicKey(publicKey)
			if err != nil {
				exitError(err)
			}
			keyID, err := privacytoken.IssuerKeyID(publicKey)
			if err != nil {
				clear(der)
				exitError(err)
			}
			manifest.PrivacyTokenKey = []gatewaymanifest.PrivacyTokenKey{{
				ID: keyID, Scope: tokenScope, Algorithm: privacytoken.Algorithm,
				PublicKey: base64.StdEncoding.EncodeToString(der),
				NotBefore: now.Format(time.RFC3339Nano),
				NotAfter:  expires.Format(time.RFC3339Nano),
			}}
			clear(der)
		}
		signer := mustSigner(signerAlgorithm, signerSeed)
		if err := gatewaymanifest.Sign(&manifest, signer); err != nil {
			exitError(err)
		}
		encoded, err := gatewaymanifest.Encode(manifest)
		if err != nil {
			exitError(err)
		}
		if err := securefile.AtomicWrite(outputPath, encoded, 0o644); err != nil {
			exitError(err)
		}
		digest, err := gatewaymanifest.Digest(manifest)
		if err != nil {
			exitError(err)
		}
		fmt.Println(digest)

	case "sign":
		require(manifestPath, "-manifest")
		require(outputPath, "-out")
		require(signerSeed, "-controller-pq-seed")
		manifest := mustManifest(manifestPath)
		signer := mustSigner(signerAlgorithm, signerSeed)
		if err := gatewaymanifest.Sign(&manifest, signer); err != nil {
			exitError(err)
		}
		encoded, err := gatewaymanifest.Encode(manifest)
		if err != nil {
			exitError(err)
		}
		if err := securefile.AtomicWrite(outputPath, encoded, 0o644); err != nil {
			exitError(err)
		}
		digest, err := gatewaymanifest.Digest(manifest)
		if err != nil {
			exitError(err)
		}
		fmt.Println(digest)

	case "verify":
		require(manifestPath, "-manifest")
		require(pinsPath, "-controller-pq-pins")
		manifest := mustManifest(manifestPath)
		pins := mustPins(pinsPath)
		if err := gatewaymanifest.Verify(
			manifest, pins, time.Now().UTC(), gatewaymanifest.DefaultClockSkew,
		); err != nil {
			exitError(err)
		}
		digest, err := gatewaymanifest.Digest(manifest)
		if err != nil {
			exitError(err)
		}
		fmt.Println(digest)

	case "append":
		require(manifestPath, "-manifest")
		require(pinsPath, "-controller-pq-pins")
		require(signerSeed, "-controller-pq-seed")
		require(logPath, "-transparency-log")
		manifest := mustManifest(manifestPath)
		pins := mustPins(pinsPath)
		if err := gatewaymanifest.Verify(
			manifest, pins, time.Now().UTC(), gatewaymanifest.DefaultClockSkew,
		); err != nil {
			exitError(err)
		}
		digest, err := gatewaymanifest.Digest(manifest)
		if err != nil {
			exitError(err)
		}
		_, checkpoint, err := transparency.Append(
			logPath, digest, mustSigner(signerAlgorithm, signerSeed),
			pins, time.Now().UTC(),
		)
		if err != nil {
			exitError(err)
		}
		if checkpointPath != "" {
			writeJSON(checkpointPath, checkpoint, 0o644)
		}
		printJSON(checkpoint)

	case "verify-log":
		require(logPath, "-transparency-log")
		require(pinsPath, "-controller-pq-pins")
		pins := mustPins(pinsPath)
		var expected *transparency.Checkpoint
		if checkpointPath != "" {
			var checkpoint transparency.Checkpoint
			readStrictJSON(checkpointPath, 64<<10, false, &checkpoint)
			expected = &checkpoint
		}
		if manifestPath == "" {
			_, checkpoint, err := transparency.ReadAndVerify(logPath, pins)
			if err != nil {
				exitError(err)
			}
			if expected != nil &&
				(expected.Size != checkpoint.Size ||
					expected.ReceiptDigest != checkpoint.ReceiptDigest) {
				exitError(errors.New("transparency checkpoint mismatch"))
			}
			printJSON(checkpoint)
			return
		}
		manifest := mustManifest(manifestPath)
		if err := gatewaymanifest.Verify(
			manifest, pins, time.Now().UTC(), gatewaymanifest.DefaultClockSkew,
		); err != nil {
			exitError(err)
		}
		digest, err := gatewaymanifest.Digest(manifest)
		if err != nil {
			exitError(err)
		}
		checkpoint, err := transparency.VerifyInclusion(
			logPath, digest, pins, expected,
		)
		if err != nil {
			exitError(err)
		}
		printJSON(checkpoint)

	default:
		exitError(errors.New("-action must be create, sign, verify, append, or verify-log"))
	}
}

func splitModes(encoded string) []string {
	parts := strings.Split(encoded, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		mode := strings.TrimSpace(part)
		if mode != "" && !contains(result, mode) {
			result = append(result, mode)
		}
	}
	return result
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func mustManifest(path string) gatewaymanifest.Manifest {
	manifest, err := gatewaymanifest.Load(path)
	if err != nil {
		exitError(err)
	}
	return manifest
}

func mustPins(path string) *pqauth.VerifierSet {
	pins, err := pqauth.LoadVerifierSet(path)
	if err != nil {
		exitError(err)
	}
	return pins
}

func mustSigner(algorithm, path string) *pqauth.Signer {
	signer, err := pqauth.LoadSigner(algorithm, path)
	if err != nil {
		exitError(err)
	}
	return signer
}

func readStrictJSON(path string, limit int64, private bool, target any) {
	var data []byte
	var err error
	if private {
		data, err = securefile.ReadPrivateLimited(path, limit)
	} else {
		data, err = securefile.ReadPublicIntegrity(path, limit)
	}
	if err != nil {
		exitError(err)
	}
	defer clear(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		exitError(err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		exitError(errors.New("JSON input contains trailing data"))
	}
}

func writeJSON(path string, value any, mode os.FileMode) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		exitError(err)
	}
	encoded = append(encoded, '\n')
	if err := securefile.AtomicWrite(path, encoded, mode); err != nil {
		exitError(err)
	}
}

func printJSON(value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		exitError(err)
	}
	fmt.Println(string(encoded))
}

func require(value, name string) {
	if value == "" {
		exitError(fmt.Errorf("%s is required", name))
	}
}

func exitError(err error) {
	fmt.Fprintln(os.Stderr, "winn-manifest:", err)
	os.Exit(1)
}
