// Command winn-carrier-provision installs the six device-local credential
// files a Winn carrier profile names into a platform credential directory.
//
// # The gap this closes
//
// datapath/carrierhost/servedkeys.go divides Profile's fields in two. SERVED
// fields are public transport parameters the control plane chooses and hands
// to the client in protocol_params. DEVICE-LOCAL fields are PATHS, and a
// control plane must never choose one, because naming a path is naming which
// file the engine opens.
//
// Every platform host already resolves those paths, by the same six fixed file
// names, against its own private credential directory:
//
//	android/.../WinnCarrierProfile.kt        CredentialSet.REQUIRED_FILES
//	apple/WinsTunnelCore/WinsWinnCarrierProfile.swift  CredentialSet.requiredFiles
//	linux/runner/linux_winn_host.cc          ResolveLinuxWinnCarrierCredentials
//
// and all three FAIL CLOSED when a file is absent, which is the honest state of
// every device today: the hosts, the argv and the engine are wired, and nothing
// puts the files there. servedkeys.go says so in as many words -- "one file
// name across every platform so provisioning tooling needs one name" -- and
// this is that tooling.
//
// So `http3-connect-udp` is not blocked on protocol design. It is blocked on
// six files with fixed names not existing. This command is the step between
// "the deployment has issued a device its credentials" and "the engine can open
// an authenticated carrier".
//
// # What it will not do
//
// It does not ISSUE anything. It has no CA, it mints no certificate, it
// generates no ML-DSA seed and it never invents a trust anchor. Issuance is a
// deployment programme: the device ML-DSA identity has to be generated on the
// device and registered with the controller, the client certificate has to be
// issued by the Winn CA, and the pinned controller verifier set and the ECH
// config list have to be distributed and rotated. `cmd/winn-pki` produces all
// six for a LAB deployment, and this command's default source layout is that
// tool's output, so a lab can be provisioned end to end without a second set of
// file names to keep in step.
//
// Substituting a generated key, a default, or the system trust store for any of
// these would turn a missing-credential refusal into a session that looks
// post-quantum and is not. That is the one failure the whole fail-closed chain
// exists to prevent, so this command has no flag that does it.
//
// # Why it validates rather than copies
//
// A copy would satisfy every host's check -- all three only stat the file and
// test read access, deliberately, because a host must never open a credential.
// But the file is not OPENED until carrierhost.BuildDialer, at Create time,
// long after the host has protected a socket and started the engine. A
// truncated ECH list or a client key that does not match its certificate would
// therefore surface as "the tunnel just does not connect", with the host having
// reported everything present.
//
// This command is not a host. It is an operator tool run once, so it can afford
// to open each file, and it hands every one to the SAME loader that will open
// it at dial time (pqauth.LoadVerifierSet, pqauth.LoadSigner,
// echconfig.LoadClientConfigList, knock.LoadKeysFromFile, tls.LoadX509KeyPair).
// A credential that will fail at dial time fails here instead, on the
// operator's terminal, with the file named.
//
// # Usage
//
//	winn-carrier-provision -from DIR -to DIR [-device-algorithm ALG]
//	                       [-spa-key PATH] [-force] [-verify-only]
//	winn-carrier-provision -print-served-template [-carrier NAME]
//
// -from defaults to the cmd/winn-pki output layout. Any of the six sources may
// be named explicitly instead, for a deployment whose enrolment bundle has its
// own layout.
//
// # Output discipline
//
// No byte of any credential is printed, and no path outside the two directories
// the operator named is printed. The device ML-DSA KEY ID is printed, because
// it is derived from the PUBLIC key and it is exactly what the operator must
// register with the carrier server's -device-registry for this device to be
// admitted; withholding it would send them back to the seed file.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"winsvpn.local/winnprotocol/datapath/carrierhost"
	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/knock"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/securefile"
)

// credential describes one device-local file: the fixed name every platform
// host looks for, the default source name in a cmd/winn-pki bundle, the mode it
// is installed with, and what it is.
//
// The order is carrierhost.DeviceLocalProfileKeys' order, which is also
// CredentialSet.REQUIRED_FILES' order on every host, so a refusal here names
// the same file first that a device would name.
type credential struct {
	// name is the fixed file name inside the credential directory. Changing
	// one of these silently unprovisions every device.
	name string

	// pkiSource is the file cmd/winn-pki writes it as. Empty means the source
	// depends on a flag (the device seed depends on the ML-DSA parameter set).
	pkiSource string

	// mode is the installed permission. It mirrors what cmd/winn-pki already
	// writes, so a file that loads from a PKI bundle loads from a credential
	// directory.
	mode os.FileMode

	// purpose is the operator-facing description, kept identical to the one
	// each host prints when the file is missing.
	purpose string

	// override is the explicit source path flag, when the operator's enrolment
	// bundle is not a winn-pki layout.
	override *string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "winn-carrier-provision:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	var (
		fromDir         string
		toDir           string
		deviceAlgorithm string
		spaKey          string
		force           bool
		verifyOnly      bool
		printTemplate   bool
		templateCarrier string
	)
	overrides := map[string]*string{}
	flags := flag.NewFlagSet("winn-carrier-provision", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.StringVar(&fromDir, "from", "",
		"enrolment bundle directory, in cmd/winn-pki's layout")
	flags.StringVar(&toDir, "to", "",
		"the platform credential directory to install into")
	flags.StringVar(&deviceAlgorithm, "device-algorithm", pqauth.MLDSA65,
		"the device ML-DSA parameter set; MUST equal the served "+
			"device_pq_algorithm")
	flags.StringVar(&spaKey, "spa-key", "",
		"optional single-packet-authorization knock key source; installed as "+
			carrierhost.SPAKeyCredentialFileName)
	flags.BoolVar(&force, "force", false,
		"replace credentials that are already installed")
	flags.BoolVar(&verifyOnly, "verify-only", false,
		"load and check the sources, install nothing")
	flags.BoolVar(&printTemplate, "print-served-template", false,
		"print the protocol_params a control plane must serve, and exit")
	flags.StringVar(&templateCarrier, "carrier", carrierhost.CarrierHTTP3,
		"carrier the served template describes")

	set := credentialSet()
	for index := range set {
		name := strings.TrimSuffix(set[index].name, filepath.Ext(set[index].name))
		value := new(string)
		flags.StringVar(value, "src-"+strings.ReplaceAll(name, "_", "-"), "",
			"explicit source for "+set[index].name)
		set[index].override = value
		overrides[set[index].name] = value
	}
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if printTemplate {
		return printServedTemplate(templateCarrier)
	}
	switch deviceAlgorithm {
	case pqauth.MLDSA65, pqauth.MLDSA87:
	default:
		return fmt.Errorf(
			"-device-algorithm %q is not an ML-DSA parameter set this build "+
				"knows; it is %q or %q", deviceAlgorithm,
			pqauth.MLDSA65, pqauth.MLDSA87,
		)
	}
	if toDir == "" {
		return errors.New("-to is required: the platform credential directory")
	}

	// Resolve every source before touching the destination, so a bundle that
	// is missing a file leaves the device exactly as it was rather than
	// half-provisioned. A device holding five of six credentials fails at the
	// sixth with the same message as a device holding none, which makes a
	// partial install invisible; refusing up front is what keeps it impossible.
	sources := make([]string, len(set))
	for index, entry := range set {
		source, err := resolveSource(entry, fromDir, deviceAlgorithm)
		if err != nil {
			return err
		}
		sources[index] = source
	}

	report, err := verify(set, sources, deviceAlgorithm)
	if err != nil {
		return err
	}
	for _, line := range report {
		fmt.Println(line)
	}

	var spaSource string
	if spaKey != "" {
		if err := verifySPAKey(spaKey); err != nil {
			return err
		}
		spaSource = spaKey
		fmt.Printf("  ok  %-24s  single-packet-authorization knock key, "+
			"exactly one\n", carrierhost.SPAKeyCredentialFileName)
	}

	if verifyOnly {
		fmt.Println("verify-only: every source loads; nothing was installed")
		return nil
	}
	if err := securefile.EnsurePrivateDirectory(toDir); err != nil {
		return fmt.Errorf("credential directory %s: %w", toDir, err)
	}
	installed := 0
	for index, entry := range set {
		written, err := install(sources[index],
			filepath.Join(toDir, entry.name), entry.mode, force)
		if err != nil {
			return err
		}
		if written {
			installed++
		}
	}
	if spaSource != "" {
		written, err := install(spaSource,
			filepath.Join(toDir, carrierhost.SPAKeyCredentialFileName),
			0o600, force)
		if err != nil {
			return err
		}
		if written {
			installed++
		}
	}
	fmt.Printf("installed %d credential file(s) into %s\n", installed, toDir)
	if installed == 0 {
		fmt.Println(
			"nothing was written: every credential was already present. " +
				"Pass -force to replace them.")
	}
	return nil
}

// credentialSet is the ordered list, restated from each host's own table. The
// file names are the contract; they are written out here rather than derived so
// that a change to one is a visible change to this list.
func credentialSet() []credential {
	return []credential{
		{
			name:      "controller_pins.json",
			pkiSource: "controller-pq-pins.json",
			mode:      0o644,
			purpose: "the PINNED controller ML-DSA verifier set, the " +
				"profile's trust anchor",
		},
		{
			name:      "winn_root_ca.pem",
			pkiSource: "ca.pem",
			mode:      0o644,
			purpose: "the Winn CA the carrier certificate must chain to; " +
				"the system trust store is not it",
		},
		{
			name:      "ech_config_list.bin",
			pkiSource: "ech-config-list.bin",
			mode:      0o644,
			purpose: "the Encrypted Client Hello config list, without which " +
				"the TLS profile is a single-probe fingerprint",
		},
		{
			// pkiSource is empty: it depends on -device-algorithm, and picking
			// the wrong parameter set installs a seed the carrier server will
			// reject with a signature failure rather than a missing-file one.
			name:    "device_mldsa_seed.bin",
			mode:    0o600,
			purpose: "the device's ML-DSA private seed",
		},
		{
			name:      "client_cert.pem",
			pkiSource: "device.pem",
			mode:      0o644,
			purpose:   "the mTLS client certificate identity mode requires",
		},
		{
			name:      "client_key.pem",
			pkiSource: "device-key.pem",
			mode:      0o600,
			purpose:   "the mTLS client private key",
		},
	}
}

func resolveSource(
	entry credential, fromDir, deviceAlgorithm string,
) (string, error) {
	if entry.override != nil && strings.TrimSpace(*entry.override) != "" {
		return *entry.override, nil
	}
	if fromDir == "" {
		return "", fmt.Errorf(
			"no source for %s (%s): pass -from with an enrolment bundle or "+
				"name the file explicitly", entry.name, entry.purpose,
		)
	}
	source := entry.pkiSource
	if source == "" {
		// The seed file cmd/winn-pki writes for the requested parameter set.
		switch deviceAlgorithm {
		case pqauth.MLDSA87:
			source = "device-mldsa87.seed"
		default:
			source = "device-mldsa65.seed"
		}
	}
	return filepath.Join(fromDir, source), nil
}

// verify hands every source to the loader that will open it at dial time.
func verify(
	set []credential, sources []string, deviceAlgorithm string,
) ([]string, error) {
	report := make([]string, 0, len(set)+1)
	report = append(report, "checking sources with the loaders that open them "+
		"at dial time:")

	for index, entry := range set {
		source := sources[index]
		info, err := os.Lstat(source)
		if err != nil {
			return nil, fmt.Errorf("%s (%s): %w", entry.name, entry.purpose, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			// Refused rather than followed, matching every host's own rule: a
			// link would let something outside the bundle answer for a name
			// inside it.
			return nil, fmt.Errorf(
				"%s source is a symbolic link, which is refused rather than "+
					"followed: %s", entry.name, source,
			)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s source is not a regular file: %s",
				entry.name, source)
		}
		if info.Size() == 0 {
			return nil, fmt.Errorf("%s source is empty: %s", entry.name, source)
		}
		report = append(report,
			fmt.Sprintf("  ok  %-24s  %d bytes", entry.name, info.Size()))
	}

	// controller_pins.json -- pqauth.LoadVerifierSet, the same call
	// carrierhost.BuildDialer makes first, because the pinned controller keys
	// are the profile's only trust anchor.
	if _, err := pqauth.LoadVerifierSet(sources[0]); err != nil {
		return nil, fmt.Errorf("controller_pins.json does not load as a "+
			"pqauth verifier set: %w", err)
	}

	// winn_root_ca.pem -- the pool the carrier certificate must chain to.
	rootPEM, err := os.ReadFile(sources[1])
	if err != nil {
		return nil, fmt.Errorf("winn_root_ca.pem: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return nil, errors.New(
			"winn_root_ca.pem contains no PEM certificate the TLS stack " +
				"would accept as a root")
	}

	// ech_config_list.bin -- echconfig.LoadClientConfigList, which BuildDialer
	// calls and then requires (ECH is required, not preferred, so a list that
	// does not parse is a session that cannot start rather than one that
	// silently sends its SNI in the clear).
	if _, err := echconfig.LoadClientConfigList(sources[2]); err != nil {
		return nil, fmt.Errorf("ech_config_list.bin does not load as an ECH "+
			"config list: %w", err)
	}

	// device_mldsa_seed.bin -- pqauth.LoadSigner for the requested parameter
	// set. The key id is public and is what the controller registers.
	signer, err := pqauth.LoadSigner(deviceAlgorithm, sources[3])
	if err != nil {
		return nil, fmt.Errorf("device_mldsa_seed.bin does not load as a %s "+
			"signer: %w", deviceAlgorithm, err)
	}
	keyID := signer.KeyID()
	signer.Destroy()

	// client_cert.pem + client_key.pem -- one keypair, and it must chain to the
	// root CA above. A cert that does not chain is the failure a host cannot
	// see: both files exist, both are readable, and the carrier server closes
	// the connection at the TLS handshake.
	pair, err := tls.LoadX509KeyPair(sources[4], sources[5])
	if err != nil {
		return nil, fmt.Errorf("client_cert.pem and client_key.pem are not a "+
			"usable keypair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("client_cert.pem leaf: %w", err)
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		if certificate, err := x509.ParseCertificate(der); err == nil {
			intermediates.AddCert(certificate)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, fmt.Errorf(
			"client_cert.pem does not chain to winn_root_ca.pem for client "+
				"authentication, so the carrier server would close the TLS "+
				"handshake: %w", err)
	}

	report = append(report, fmt.Sprintf(
		"  device %s key id: %s\n"+
			"  register that key id with the carrier server's -device-registry "+
			"for this device_id,\n"+
			"  or the carrier admits the TLS connection and then refuses every "+
			"signed request.",
		deviceAlgorithm, keyID))
	return report, nil
}

func verifySPAKey(path string) error {
	keys, err := knock.LoadKeysFromFile(path)
	if err != nil {
		return fmt.Errorf("SPA knock key: %w", err)
	}
	defer func() {
		for _, key := range keys {
			clear(key)
		}
	}()
	if len(keys) != 1 {
		// carrierhost.wrapSPA's rule, checked here so a rotation overlap file
		// is caught by the operator rather than at dial time on a device.
		return fmt.Errorf(
			"SPA knock key file must contain exactly one key for a client, "+
				"found %d; a server file with a rotation overlap is not a "+
				"client credential", len(keys),
		)
	}
	return nil
}

// install copies one credential. It refuses an incumbent unless -force, because
// silently replacing a device identity would revoke nothing and would leave the
// controller registry describing a key the device no longer has.
func install(source, destination string, mode os.FileMode, force bool) (bool, error) {
	if info, err := os.Lstat(destination); err == nil {
		if !force {
			if info.Mode().IsRegular() {
				return false, nil
			}
			return false, fmt.Errorf(
				"%s already exists and is not a regular file", destination)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return false, err
	}
	defer clear(data)
	if err := securefile.AtomicWrite(destination, data, mode); err != nil {
		return false, fmt.Errorf("installing %s: %w", destination, err)
	}
	return true, nil
}

// printServedTemplate prints the protocol_params a control plane must serve for
// this carrier, with every value a placeholder.
//
// It is generated from carrierhost's own key lists rather than typed out, so a
// key added to the schema appears here without anyone remembering to add it --
// which is the failure servedkeys.go was written to prevent for the four
// platform hosts and which applies just as much to whoever configures the hub.
//
// No device-local key can appear here: they are not in ServedProfileKeys, and
// serving one would let whoever answered the config request choose which file
// the engine opens.
func printServedTemplate(carrier string) error {
	switch carrier {
	case carrierhost.CarrierHTTP3, carrierhost.CarrierHTTP2:
	default:
		return fmt.Errorf("%w (requested %q)",
			carrierhost.ErrCarrierUnsupported, carrier)
	}
	required := map[string]bool{}
	for _, key := range carrierhost.RequiredServedProfileKeys {
		required[key] = true
	}
	spa := map[string]bool{}
	for _, key := range carrierhost.SPAServedProfileKeys {
		spa[key] = true
	}

	document := map[string]any{}
	notes := make([]string, 0, len(carrierhost.ServedProfileKeys))
	for _, key := range carrierhost.ServedProfileKeys {
		if spa[key] {
			// Omitted, not emitted empty: normalizeSPA refuses any non-empty
			// spa_ field without spa_mode=required, and a template that
			// invited a "sensible default" would refuse every non-SPA session.
			notes = append(notes, fmt.Sprintf(
				"  %-26s OMIT unless single packet authorization is on", key))
			continue
		}
		document[key] = servedPlaceholder(key, carrier)
		state := "optional"
		if required[key] {
			state = "REQUIRED"
		}
		notes = append(notes, fmt.Sprintf("  %-26s %s", key, state))
	}
	// SetEscapeHTML(false): the placeholders use angle brackets, and < in
	// an operator-facing template is a value someone will paste verbatim.
	var buffer strings.Builder
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(document); err != nil {
		return err
	}
	encoded := strings.TrimRight(buffer.String(), "\n")
	fmt.Println("# protocol_params a control plane must serve for carrier " +
		carrier + ".")
	fmt.Println("# Generated from carrierhost.ServedProfileKeys. Placeholders " +
		"are not defaults.")
	fmt.Println("#")
	for _, note := range notes {
		fmt.Println("#" + note)
	}
	fmt.Println("#")
	fmt.Println("# NONE of the seven device-local keys may ever be served:")
	for _, key := range carrierhost.DeviceLocalProfileKeys {
		fmt.Println("#   " + key)
	}
	fmt.Println(encoded)
	return nil
}

func servedPlaceholder(key, carrier string) any {
	switch key {
	case "masque_template":
		if carrier != carrierhost.CarrierHTTP3 {
			return ""
		}
		return "https://<carrier-host>/.well-known/masque/udp/" +
			"{target_host}/{target_port}/"
	case "public_target":
		return "<gateway-ip>:<gateway-udp-port>"
	case "server_name":
		return "<inner-clienthello-name-the-carrier-cert-matches>"
	case "suite":
		return "x25519-mlkem768"
	case "controller_id":
		return "<controller-identity-signed-into-responses>"
	case "device_id":
		return "<per-device-identifier-registered-with-the-controller>"
	case "device_pq_algorithm":
		return pqauth.MLDSA65
	case "manifest_digest":
		return strings.Repeat("0", 64)
	case "sequence_epoch":
		return ""
	case "max_inner_datagram":
		return 0
	case "privacy_profile":
		return "high-risk"
	default:
		return ""
	}
}
