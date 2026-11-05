// Command winn-datapath is the subprocess transport of the Winn Protocol v3
// in-process datapath contract.
//
// It speaks the framed duplex protocol in ../../datapath/duplex over stdin and
// stdout, or over a unix stream socket. This is the Android and Windows shape
// of the contract, and it is a second consumer of a pattern this repository
// already ships rather than a new one: on Android a Go binary named libxray.so
// is executed from nativeLibraryDir, and on Windows winsvpn_awg_engine.exe is a
// standalone Go binary. iOS forbids subprocesses and uses ../../cdatapath.
//
// Nothing in this binary or its dependency closure imports os/exec: it is the
// child, and it starts nothing.
//
// # Usage
//
//	winn-datapath [-transport stdio|unix] [-control PATH] [-udp-fd N]
//	              [-receive-fd] [-carrier-profile PATH] [-print-contract]
//
//	-transport stdio   frames on stdin/stdout. The default, and the only
//	                   transport available on Windows.
//	-transport unix    frames on a connected unix stream socket at -control.
//	                   Required if the host needs to hand over a descriptor,
//	                   because SCM_RIGHTS needs a unix socket.
//	-udp-fd N          adopt an already-inherited UDP descriptor. The engine
//	                   takes ownership of it.
//	-receive-fd        with -transport unix, read one descriptor from the
//	                   control socket's ancillary data before serving frames.
//	                   This is the Android path: the service opens the socket,
//	                   calls VpnService.protect(fd), and passes it here.
//	-carrier-profile   path to a carrier profile document. See below.
//	-print-contract    write the contract banner to stdout and exit. Intended
//	                   for build verification, not for runtime use.
//
// # The carrier profile, and why it is a path rather than a frame
//
// Without -carrier-profile this binary behaves exactly as it did before the
// flag existed: it calls datapath.Open, which builds direct-awg and refuses
// every other carrier. That path is byte-identical and is what the shipping
// Android host uses today.
//
// With -carrier-profile the engine loads a carrier profile (see
// ../../datapath/carrierhost), builds an internal/carrier dialer from it, and
// calls datapath.OpenWithCarrier instead, so the AmneziaWG datagrams travel
// inside authenticated Winn envelopes over HTTP/3 CONNECT-UDP or HTTP/2 with a
// post-quantum TLS 1.3 handshake.
//
// The configuration arrives as a PATH and not inside the Create frame on
// purpose. datapath/carrier.go records the rule that an authenticated carrier
// configuration has no business crossing the C ABI as a JSON blob; the same
// objection applies to the duplex frame channel, whose payload is peer-supplied
// by construction. A path is different in kind: this process opens the file
// itself, under its own uid, and every trust decision — the pinned controller
// keys, the root CA, the ECH list, the device key — is made here rather than
// asserted by whoever wrote the frame. The Create frame therefore still carries
// exactly datapath.Config, and cdatapath is untouched.
//
// The two documents must agree about the carrier, and disagreement is fatal in
// both directions. A configuration that names a carrier with no profile is
// already refused by datapath.Open; a profile supplied alongside a direct-awg
// configuration is refused here. Neither may silently become the other.
//
// # Diagnostics
//
// Under -transport stdio, stdout carries frames. Every diagnostic goes to
// stderr, and a stray print to stdout would corrupt the stream, so this file
// writes to stdout in exactly one place: -print-contract, which exits
// immediately afterwards.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"winsvpn.local/winnprotocol/datapath"
	"winsvpn.local/winnprotocol/datapath/carrierhost"
	"winsvpn.local/winnprotocol/datapath/duplex"
)

// carrierDialTimeout bounds one carrier dial: a QUIC or TLS handshake plus the
// authenticated CONNECT-UDP or POST exchange. It is generous because a mobile
// radio can be slow, and it is bounded because a host waiting forever on a
// CreateAck looks identical to a hung engine. The Android bridge gives up on
// CreateAck after 10 seconds, so a dial that exceeds this has already lost its
// caller; the timeout exists to release the descriptor, not to race the host.
const carrierDialTimeout = 30 * time.Second

func main() {
	// context.Background on purpose. A process-wide NotifyContext would
	// swallow SIGTERM while duplex.Serve or the frame reader is blocked on
	// stdin, and the process would hang instead of dying. Desktop v3 is the
	// one mode whose loop already takes a ctx; it installs the handler below
	// so a supervisor SIGTERM writes a "stopped" status line instead of EOF.
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "winn-datapath: %v\n", err)
		os.Exit(1)
	}
}

type options struct {
	transport       string
	control         string
	udpFD           int
	receiveFD       bool
	carrierProfile  string
	carrierFallback profilePaths
	printContract   bool
}

// profilePaths collects a repeatable -carrier-fallback flag.
//
// A repeatable flag rather than a comma-separated list because these are
// filesystem paths and a comma is a legal character in one; splitting on it
// would make a legal path unnameable and, worse, would make it unnameable only
// on the deployments that happened to use one.
type profilePaths []string

func (paths *profilePaths) String() string { return strings.Join(*paths, ",") }

func (paths *profilePaths) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("-carrier-fallback needs a path")
	}
	*paths = append(*paths, value)
	return nil
}

func run(ctx context.Context, arguments []string) error {
	var opts options
	var v3 winn3Options
	flags := flag.NewFlagSet("winn-datapath", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	// The Winn Protocol v3 modes. See winn3_run.go for why they live in this
	// binary and why they refuse to be combined with any winn/1 flag, and
	// winn3_frame.go for the difference between the two.
	flags.BoolVar(&v3.frame, "winn3", false,
		"run the standalone Winn Protocol v3 over the duplex frame channel: "+
			"the host owns the tun device and Inbound/Outbound frames carry "+
			"inner IP packets instead of AmneziaWG datagrams. Needs -winn3-keys")
	flags.StringVar(&v3.keys, "winn3-keys", "",
		"path to a Winn Protocol v3 key document for -winn3; it names key "+
			"FILES and contains no key material")
	flags.StringVar(&v3.profile, "winn3-profile", "",
		"path to a Winn Protocol v3 host profile; selects the standalone v3 "+
			"protocol instead of the winn/1 AmneziaWG datapath")
	flags.IntVar(&v3.tunFD, "winn3-tun-fd", -1,
		"already-inherited /dev/net/tun descriptor for device kind "+
			winn3DeviceTunFD+" (Linux only)")
	flags.BoolVar(&v3.printSizing, "winn3-print-sizing", false,
		"compute the plan floor from the v3 profile, print one status "+
			"document and exit, so a host can set the interface MTU before "+
			"starting a tunnel")
	flags.StringVar(&opts.transport, "transport", "stdio",
		"frame transport: stdio or unix")
	flags.StringVar(&opts.control, "control", "",
		"unix stream socket path for -transport unix")
	flags.IntVar(&opts.udpFD, "udp-fd", -1,
		"already-inherited UDP descriptor to adopt, or -1")
	flags.BoolVar(&opts.receiveFD, "receive-fd", false,
		"receive the UDP descriptor from the control socket (unix only)")
	flags.StringVar(&opts.carrierProfile, "carrier-profile", "",
		"path to a carrier profile document; without it only "+
			datapath.CarrierDirectAWG+" can be opened")
	flags.Var(&opts.carrierFallback, "carrier-fallback",
		"path to a carrier profile for a FALLBACK carrier, repeatable; "+
			"enables multi-carrier failover over the configuration's "+
			"carrier_escalation plan. Requires allow_own_socket and no "+
			"descriptor")
	flags.BoolVar(&opts.printContract, "print-contract", false,
		"print the contract banner and exit")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if opts.printContract {
		return printContract()
	}
	if err := winn3RefuseMixedModes(opts, v3); err != nil {
		return err
	}
	if v3.enabled() {
		// stdout carries line-delimited status documents in this mode, not
		// duplex frames, and no transport is established at all: v3 is a
		// standalone protocol with its own session, its own crypto and its own
		// datapath, so there is nothing here for duplex.Serve to serve.
		winn3AdoptedTunFD = v3.tunFD
		ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runWinn3(ctx, v3, os.Stdout)
	}
	if v3.frameEnabled() {
		// The frame channel, with inner IP packets on it. Note what does NOT
		// happen below this line: no carrier profile is loaded, no
		// datapath.Open is reachable, and a create this mode refuses leaves the
		// process with no tunnel rather than with a relay one. A -winn3 process
		// that quietly started AmneziaWG would take a session the gateway
		// negotiated as winn/3 and put classical AWG on the wire with nobody
		// told, which is the silent downgrade the Apple providers were found
		// with today.
		return runWinn3Frames(ctx, opts, v3)
	}

	// Same shape as winn3-gateway's -forward needing -accept-transit=true: the
	// flag help already said -carrier-fallback requires no descriptor, but the
	// process used to start, consume a handed-over socket, and only refuse at
	// Create. An operator who then "fixed" a missing profile path would next
	// see an Error frame, not a process that would not start.
	if len(opts.carrierFallback) > 0 && (opts.udpFD >= 0 || opts.receiveFD) {
		return errors.New(
			"-carrier-fallback cannot be used with -udp-fd or -receive-fd: a " +
				"failover successor would have to open its own socket, which on " +
				"a protected-socket platform routes outer traffic back into the " +
				"tunnel. Start this process without a descriptor and set " +
				"allow_own_socket, or drop -carrier-fallback")
	}

	// The profile is loaded and validated BEFORE any transport is established.
	// A bad profile must kill this process with a message on stderr, not
	// surface later as an Error frame at Create time, because by then the host
	// has already protected a socket and handed the descriptor over.
	carriers, err := loadCarriers(opts)
	if err != nil {
		return err
	}

	switch opts.transport {
	case "stdio":
		if opts.receiveFD {
			return errors.New(
				"-receive-fd needs -transport unix: a descriptor cannot be " +
					"passed over a pipe",
			)
		}
		if opts.control != "" {
			return errors.New("-control applies only to -transport unix")
		}
		return serve(os.Stdin, os.Stdout, opts.udpFD, nil, carriers)
	case "unix":
		return serveUnix(opts, carriers)
	default:
		return fmt.Errorf(
			"unknown -transport %q; use stdio or unix", opts.transport,
		)
	}
}

// carrierSet is the profiles this process was started with.
//
// head is the carrier the datapath.Config must name; fallbacks are the
// successors the escalation plan may escalate to. An empty fallback list is
// today's behaviour and is the shape every existing host starts this binary in.
type carrierSet struct {
	head      *carrierhost.Profile
	fallbacks []carrierhost.Profile
}

// loadCarriers reads and validates every profile BEFORE any transport is
// established.
//
// A bad profile must kill this process with a message on stderr, not surface
// later as an Error frame at Create time, because by then the host has already
// protected a socket and handed the descriptor over. That reasoning applied to
// one profile and applies with more force to several: discovering at Create
// time that the FALLBACK was malformed would mean discovering it while a
// censor was already blocking the primary.
func loadCarriers(opts options) (carrierSet, error) {
	var carriers carrierSet
	if opts.carrierProfile != "" {
		loaded, err := carrierhost.LoadProfile(opts.carrierProfile)
		if err != nil {
			return carrierSet{}, err
		}
		carriers.head = &loaded
		// Key names and modes only. The profile names private files and must
		// never be logged whole.
		fmt.Fprintln(os.Stderr, "winn-datapath: "+loaded.DescribeForLog())
	}
	if len(opts.carrierFallback) == 0 {
		return carriers, nil
	}
	// -carrier-fallback deliberately does NOT require -carrier-profile. The
	// measured scenario is a session on direct-awg killed by a UDP block, and
	// direct-awg has no profile: the datapath builds it from the gateway
	// endpoint. So the common and most important invocation is fallbacks with
	// no primary profile at all, and requiring one would have excluded exactly
	// the case this exists for.
	seen := map[string]bool{}
	if carriers.head != nil {
		seen[carriers.head.Carrier] = true
	}
	for _, path := range opts.carrierFallback {
		loaded, err := carrierhost.LoadProfile(path)
		if err != nil {
			return carrierSet{}, err
		}
		if seen[loaded.Carrier] {
			return carrierSet{}, fmt.Errorf(
				"carrier %q appears twice across the supplied profiles: "+
					"retrying a carrier that already failed is a loop, not an "+
					"escalation", loaded.Carrier,
			)
		}
		seen[loaded.Carrier] = true
		carriers.fallbacks = append(carriers.fallbacks, loaded)
		fmt.Fprintln(os.Stderr,
			"winn-datapath: fallback "+loaded.DescribeForLog())
	}
	return carriers, nil
}

func serveUnix(opts options, carriers carrierSet) error {
	if opts.control == "" {
		return errors.New("-transport unix requires -control PATH")
	}
	conn, err := net.Dial("unix", opts.control)
	if err != nil {
		return fmt.Errorf("connect control socket %q: %w", opts.control, err)
	}
	defer func() { _ = conn.Close() }()
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("control socket %q is not a unix stream socket",
			opts.control)
	}
	descriptor := opts.udpFD
	if opts.receiveFD {
		if descriptor >= 0 {
			return errors.New("-receive-fd and -udp-fd are mutually exclusive")
		}
		descriptor, err = receiveDescriptor(unixConn)
		if err != nil {
			return err
		}
	}
	return serve(unixConn, unixConn, descriptor, unixConn, carriers)
}

// serve wires one conversation. The descriptor is consumed at most once: a
// second Open frame in the same session is refused by the duplex session, so a
// peer cannot make the engine adopt an already-closed descriptor.
func serve(
	input io.Reader,
	output io.Writer,
	descriptor int,
	closer io.Closer,
	carriers carrierSet,
) error {
	consumed := false
	opener := func(configJSON []byte) (*datapath.Engine, error) {
		if consumed {
			return nil, errors.New(
				"the UDP descriptor supplied to this process has already been " +
					"consumed by an earlier open",
			)
		}
		consumed = true
		if len(carriers.fallbacks) > 0 {
			return openWithFailover(configJSON, descriptor, carriers)
		}
		if carriers.head == nil {
			return datapath.Open(configJSON, descriptor)
		}
		return openWithProfile(configJSON, descriptor, *carriers.head)
	}
	err := duplex.Serve(input, output, opener)
	if closer != nil {
		_ = closer.Close()
	}
	if err != nil && errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// openWithProfile opens the datapath over the carrier the profile describes.
//
// It is the anti-downgrade seam on this side of the boundary. Two documents now
// name a carrier — the Create frame's datapath.Config and the profile on argv —
// and this function exists so they can never quietly disagree:
//
//   - profile present, configuration says direct-awg: REFUSED. Opening
//     direct-awg here would take a session an operator configured for an
//     authenticated, post-quantum carrier and put it on the wire as plain
//     AmneziaWG, which is exactly the silent downgrade the winn/3 dispatch
//     gates in the Flutter client exist to prevent.
//   - profile present, configuration names a different carrier: REFUSED, by
//     name, saying which document said what.
//   - configuration names a carrier with no profile: already refused by
//     datapath.Open, which returns ErrCarrierNoDialer rather than building
//     direct-awg. Nothing here weakens that; it is restated in the test.
//
// The dialer is built per open rather than once at startup because a carrier
// dialer built around a caller-supplied socket is single-use, and because a
// dialer constructed but never dialled would hold the device's ML-DSA signer
// in memory for the whole life of a process that may never open a tunnel.
func openWithProfile(
	configJSON []byte,
	descriptor int,
	profile carrierhost.Profile,
) (*datapath.Engine, error) {
	config, err := datapath.ParseConfig(configJSON)
	if err != nil {
		return nil, err
	}
	if config.Carrier == datapath.CarrierDirectAWG {
		return nil, fmt.Errorf(
			"this engine was started with a %s carrier profile but the "+
				"configuration asks for %q: refusing rather than opening an "+
				"unauthenticated carrier for a session that was configured for "+
				"an authenticated one",
			profile.Carrier, config.Carrier,
		)
	}
	if config.Carrier != profile.Carrier {
		return nil, fmt.Errorf(
			"carrier disagreement: the configuration asks for %q and the "+
				"carrier profile builds %q",
			config.Carrier, profile.Carrier,
		)
	}
	dialer, err := carrierhost.BuildDialer(profile)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(
		context.Background(), carrierDialTimeout,
	)
	defer cancel()
	return datapath.OpenConfigWithCarrier(ctx, config, descriptor, dialer)
}

// openWithFailover opens the datapath over the whole escalation plan rather
// than over a single carrier.
//
// It is the shipping entry point to datapath.OpenConfigWithFailover, and
// therefore to internal/carrier.Manager's multi-candidate failover, which until
// now was reachable only from cmd/winn-carrier-client.
//
// The anti-downgrade rules openWithProfile enforces all still apply and are
// applied here through the same function-level reasoning: the Create frame's
// configuration and the head profile must name the same carrier, and a profile
// alongside a direct-awg configuration is refused — EXCEPT that direct-awg is
// legitimate as the plan HEAD here, because the measured defect is a session on
// direct-awg being killed by a UDP block, and a failover that could not start
// there would never be exercised where it is needed. The distinction is exact:
// direct-awg may be the carrier the session STARTS on, and it is still refused
// as a carrier the session falls BACK to, by the escalation plan's own
// UDP-survival check.
func openWithFailover(
	configJSON []byte,
	descriptor int,
	carriers carrierSet,
) (*datapath.Engine, error) {
	config, err := datapath.ParseConfig(configJSON)
	if err != nil {
		return nil, err
	}
	// The socket rule, stated here as well as in the datapath because this is
	// the process that HOLDS the descriptor and can say what to do about it.
	if descriptor >= 0 {
		return nil, fmt.Errorf(
			"%w (a descriptor was supplied on argv or over the control "+
				"socket); start this process without one and set "+
				"allow_own_socket, or drop -carrier-fallback and act on the "+
				"carrier_escalation verdict in the status document instead",
			datapath.ErrFailoverSuppliedSocket,
		)
	}
	profiles := make([]carrierhost.Profile, 0, len(carriers.fallbacks)+1)
	if carriers.head != nil {
		if config.Carrier != datapath.CarrierDirectAWG &&
			config.Carrier != carriers.head.Carrier {
			return nil, fmt.Errorf(
				"carrier disagreement: the configuration asks for %q and the "+
					"primary carrier profile builds %q",
				config.Carrier, carriers.head.Carrier,
			)
		}
		profiles = append(profiles, *carriers.head)
	} else if config.Carrier != datapath.CarrierDirectAWG {
		return nil, fmt.Errorf(
			"the configuration asks for carrier %q and no -carrier-profile "+
				"was supplied to build it: only %s can be built without a "+
				"profile", config.Carrier, datapath.CarrierDirectAWG,
		)
	}
	profiles = append(profiles, carriers.fallbacks...)

	candidates := make([]datapath.CarrierCandidate, 0, len(profiles)+1)
	if config.Carrier == datapath.CarrierDirectAWG {
		// The datapath builds this leg itself from the gateway endpoint; it has
		// no dialer and must not be given one.
		candidates = append(candidates, datapath.CarrierCandidate{
			Carrier: datapath.CarrierDirectAWG,
		})
	}
	for _, profile := range profiles {
		dialer, buildErr := carrierhost.BuildDialer(profile)
		if buildErr != nil {
			return nil, buildErr
		}
		candidates = append(candidates, datapath.CarrierCandidate{
			Carrier:  profile.Carrier,
			Endpoint: profile.CarrierEndpoint(),
			Dialer:   dialer,
		})
	}

	ctx, cancel := context.WithTimeout(
		context.Background(), carrierDialTimeout,
	)
	defer cancel()
	return datapath.OpenConfigWithFailover(ctx, config, candidates)
}

// Contract is the banner -print-contract emits. It is a plain JSON document on
// stdout, NOT a frame: the normative opcode set has no banner opcode, and
// emitting one would make a conforming host tear the channel down. A host uses
// this by running the binary once at install or startup, never on the wire.
type Contract struct {
	Contract        string `json:"contract"`
	ProtocolVersion string `json:"protocol_version"`
	Wire            string `json:"wire"`
	FrameMagic      string `json:"frame_magic"`
	FrameVersion    uint16 `json:"frame_version"`
	FrameHeaderSize int    `json:"frame_header_size"`
	MaxFramePayload int    `json:"max_frame_payload"`
	MaxDatagram     int    `json:"max_datagram"`

	// Payloads is the MACHINE-READABLE payload list, and it is the field a host
	// probes to decide whether this build can carry a v3 session.
	//
	// It exists because the prose below cannot be probed safely.
	// payload_semantics says "...carry AmneziaWG outer datagrams, NOT raw IP
	// packets", and a host searching that sentence for "ip-packet" — or for "ip
	// packets" — finds it in a clause that says the opposite. A build that
	// predates this field returns no "payloads" key at all, so the probe fails
	// closed and the host refuses to start a v3 session rather than starting a
	// v2 one in its place. WinnV3Host.engineSupportsV3 and its test "the probe
	// refuses the shipping banner" are the other half of this.
	//
	// The names are exact, not substrings: "ip-packet" is the payload class
	// datapath.Config refuses at create time and winn3 requires.
	Payloads []string `json:"payloads"`

	PayloadSemantics string `json:"payload_semantics"`

	// CarrierProfileVersion and Carriers let a host discover, without spawning
	// a tunnel, whether this build can be given a carrier profile and which
	// carriers it would build from one. A host that finds an older banner here
	// knows the binary it packaged predates the seam and can say so, instead of
	// passing -carrier-profile to a process that will exit with "flag provided
	// but not defined".
	CarrierProfileVersion string   `json:"carrier_profile_version"`
	Carriers              []string `json:"carriers_buildable"`

	GOOS   string `json:"goos"`
	GOARCH string `json:"goarch"`
}

func printContract() error {
	banner, err := json.Marshal(Contract{
		Contract:        datapath.ContractVersion,
		ProtocolVersion: datapath.ProtocolVersion,
		Wire:            duplex.WireVersion,
		FrameMagic:      fmt.Sprintf("0x%08X", duplex.Magic),
		FrameVersion:    duplex.Version,
		FrameHeaderSize: duplex.HeaderSize,
		MaxFramePayload: duplex.MaxPayload,
		MaxDatagram:     datapath.MaxDatagramCeiling,
		// Both classes this build can carry, in the order they were added.
		// awg-datagram is the winn/1 relay and is what every host drives today;
		// ip-packet is -winn3, where winn3/core is the crypto and the frames
		// carry inner IP.
		Payloads: []string{winn3RelayPayload, winn3FramePayload},
		// Said in the banner, not only in the documentation, because this is
		// the one thing a host can get wrong in a way that puts cleartext on
		// the wire. It is prose, and a host must probe "payloads" above rather
		// than match this.
		PayloadSemantics: "without -winn3, inbound and outbound frames carry " +
			"AmneziaWG outer datagrams and not raw IP packets; with -winn3 they " +
			"carry raw inner IP packets and no AmneziaWG is involved at all",
		CarrierProfileVersion: carrierhost.ProfileVersion,
		// direct-awg is listed first because it is what this binary builds when
		// no profile is supplied, which is still the default and still what the
		// shipping Android host uses.
		Carriers: []string{
			datapath.CarrierDirectAWG,
			carrierhost.CarrierHTTP3,
			carrierhost.CarrierHTTP2,
		},
		GOOS:   runtime.GOOS,
		GOARCH: runtime.GOARCH,
	})
	if err != nil {
		return fmt.Errorf("encode contract banner: %w", err)
	}
	if _, err := os.Stdout.Write(append(banner, '\n')); err != nil {
		return err
	}
	return nil
}
