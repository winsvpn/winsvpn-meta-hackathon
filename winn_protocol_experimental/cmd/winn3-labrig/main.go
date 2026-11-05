// Command winn3-labrig is the lab-side rig for Winn Protocol v3.
//
// # Why this exists
//
// cmd/winn-datapath's -winn3-profile mode is the SHIPPING client. It dials:
// winn3DialCarrier calls carrier.DialUDP, which opens a connected socket on an
// ephemeral local port and writes nothing until the session sends. That is
// correct for a client and it is unusable for a responder, because a responder
// has to be found at an address the client already knows, and a connected
// socket on an unknown ephemeral port cannot be. So `-winn3-profile role=gateway
// class=udp` cannot accept an inbound session at all: both ends would dial and
// neither would ever be listening.
//
// carrier.NewUDP already supports exactly the missing shape — an unconnected
// socket plus an explicit Peer — so the responding half is a small amount of
// wiring rather than a new carrier. This binary is that wiring, and nothing
// else. It exists so that a v3 session can be stood up against something on
// Linux at all.
//
// # What it is NOT
//
// It is not a gateway. It has no admission policy (it admits every
// authenticated client, and says so), no session table, no forwarding, no
// multi-client dispatch — winn3/gateway is where those live. It terminates ONE
// session against ONE kernel tun device so that the kernel on the far side
// answers ICMP, which is what makes "a packet moved" a statement about the
// whole chain rather than about a counter.
//
// It is a TEST RIG and every claim built on it inherits that. A session carried
// here is evidence that the protocol and the datapath work; it is not evidence
// about any shipping path, on either end.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// statusInterval matches cmd/winn-datapath's own cadence so that the two ends
// of a session produce comparable timelines.
const statusInterval = time.Second

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "winn3-labrig: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, out *os.File) error {
	flags := flag.NewFlagSet("winn3-labrig", flag.ContinueOnError)
	mode := flags.String("mode", "", "keygen, gateway or tunfd-exec")

	// keygen
	outDir := flags.String("out", "", "keygen: directory to write key files into")

	// gateway
	listen := flags.String("listen", "", "gateway: UDP address to bind, e.g. 0.0.0.0:51833")
	gwStatic := flags.String("static", "", "gateway: path to this end's 32-byte X25519 private key")
	admission := flags.String("admission", "", "gateway: path to the admission secret")
	gatewayID := flags.String("gateway-id", "", "gateway: the authenticated gateway identifier")
	innerV4 := flags.String("inner-v4", "", "gateway: this end's inner IPv4 address")
	routerV4 := flags.String("router-v4", "", "gateway: the inner next hop, for PMTU signals only")

	// gateway + tunfd-exec
	tunName := flags.String("tun", "", "the tun interface name to create")
	tunMTU := flags.Int("mtu", 0, "the inner MTU to set on the interface")
	tunAddr := flags.String("tun-addr", "", "the address to configure on the interface, as a /32")
	// The inner IPv6 address the PROFILE assigns, or empty when it assigns none.
	// Empty is not "don't care": it is the signal that makes configureInterface
	// disable IPv6 on the interface before it comes up, so the kernel never
	// emits a router solicitation that winn3/tun must then refuse as
	// ErrFamilyOff and count tx_dropped_invalid. See configureInterface in
	// tun_linux.go for the measurement behind that.
	tunAddr6 := flags.String("tun-addr6", "",
		"the inner IPv6 address the profile assigns, as a /128. Empty means the "+
			"profile assigns no inner IPv6, and IPv6 is disabled on the interface "+
			"before it is brought up")
	tunRoutes := flags.String("routes", "",
		"comma-separated host routes to add out of the interface, e.g. 10.99.3.1/32. "+
			"Host routes only: the bootstrap posture has no default route in it")

	// tunfd-exec
	childFD := flags.Int("child-fd", 3, "tunfd-exec: the descriptor number the child sees")

	if err := flags.Parse(args); err != nil {
		return err
	}

	switch *mode {
	case "keygen":
		if err := refusePositionalArgs("keygen", flags.Args()); err != nil {
			return err
		}
		return runKeygen(*outDir, out)
	case "gateway":
		if err := refusePositionalArgs("gateway", flags.Args()); err != nil {
			return err
		}
		return runGateway(gatewayOptions{
			listen:     *listen,
			staticPath: *gwStatic,
			admission:  *admission,
			gatewayID:  *gatewayID,
			innerV4:    *innerV4,
			routerV4:   *routerV4,
			tunName:    *tunName,
			tunMTU:     *tunMTU,
			tunAddr:    *tunAddr,
			tunAddr6:   *tunAddr6,
			tunRoutes:  splitRoutes(*tunRoutes),
		}, out)
	case "tunfd-exec":
		// Every flag this mode can decide without a device is decided HERE,
		// before runTunFDExec opens /dev/net/tun. The Linux body used to check
		// -child-fd after creating and addressing the interface; the copy in
		// runTunFDExec is belt-to-braces for a direct caller, not a second
		// policy.
		if err := tunfdExecFlagError(*tunName, *tunAddr, *tunMTU, *childFD, flags.Args()); err != nil {
			return err
		}
		return runTunFDExec(*tunName, *tunAddr, *tunAddr6, *tunMTU, *childFD,
			splitRoutes(*tunRoutes), flags.Args())
	default:
		return fmt.Errorf("-mode is %q; use keygen, gateway or tunfd-exec", *mode)
	}
}

// refusePositionalArgs is the keygen/gateway half of "an argument the operator
// typed was not silently dropped". tunfd-exec consumes remaining args as the
// child command; these two modes do not.
func refusePositionalArgs(mode string, leftover []string) error {
	if len(leftover) == 0 {
		return nil
	}
	return fmt.Errorf("%s takes no positional arguments, got %q", mode, leftover)
}

// tunfdExecFlagError is every tunfd-exec refusal that needs no device, no
// privilege and no platform. run() calls it before runTunFDExec; the Linux
// body calls it again so a direct caller cannot recreate the old order.
func tunfdExecFlagError(name, addr string, mtu, childFD int, argv []string) error {
	if childFD != 3 {
		return fmt.Errorf(
			"-child-fd %d: the first inherited descriptor is always 3", childFD)
	}
	if len(argv) == 0 {
		return errors.New("tunfd-exec needs a command to run after the flags")
	}
	if mtu <= 0 {
		return errors.New("tunfd-exec needs -mtu")
	}
	if strings.TrimSpace(name) == "" {
		return errors.New("tunfd-exec needs -tun")
	}
	if strings.TrimSpace(addr) == "" {
		return errors.New("tunfd-exec needs -tun-addr")
	}
	return nil
}

// runKeygen writes one static key pair and one admission secret.
//
// The private scalar is drawn HERE and the StaticKey built from it, rather than
// asking core.GenerateStaticKey for a key and then trying to get the private
// half back out: core.StaticKey deliberately exposes only Public(), and a lab
// rig that needs to persist a key should respect that rather than reach through
// it. crypto/rand is the same source GenerateStaticKey uses.
//
// Hex rather than raw bytes because cmd/winn-datapath accepts both and hex
// survives being copied through a shell, which raw key bytes do not.
func runKeygen(dir string, out *os.File) error {
	if strings.TrimSpace(dir) == "" {
		return errors.New("keygen needs -out")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	private := make([]byte, core.KeySize)
	if _, err := rand.Read(private); err != nil {
		return err
	}
	key, err := core.NewStaticKey(private)
	if err != nil {
		return err
	}
	// The admission secret is not a key of a fixed size; it is a shared secret
	// the initiation's admission tag and the stream carrier's length layer are
	// both derived from. 32 bytes is what the provisioning path in this tree
	// uses.
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	files := map[string][]byte{
		"static.key":    []byte(hex.EncodeToString(private)),
		"static.pub":    []byte(hex.EncodeToString(key.Public())),
		"admission.key": []byte(hex.EncodeToString(secret)),
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "{\"event\":\"keygen\",\"dir\":%q,\"public\":%q}\n",
		dir, hex.EncodeToString(key.Public()))
	return nil
}

type gatewayOptions struct {
	listen     string
	staticPath string
	admission  string
	gatewayID  string
	innerV4    string
	routerV4   string
	tunName    string
	tunMTU     int
	tunAddr    string
	tunAddr6   string
	tunRoutes  []string
}

// splitRoutes turns the comma-separated -routes value into a list.
func splitRoutes(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.Split(value, ",")
}

// runGateway terminates one v3 session against one kernel tun device.
func runGateway(opts gatewayOptions, out *os.File) error {
	if strings.TrimSpace(opts.listen) == "" {
		return errors.New("gateway needs -listen")
	}
	if strings.TrimSpace(opts.tunName) == "" {
		return errors.New("gateway needs -tun")
	}

	sizing, err := driver.NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP)
	if err != nil {
		return err
	}
	if opts.tunMTU != 0 && opts.tunMTU != sizing.InnerMTU {
		return fmt.Errorf(
			"-mtu %d disagrees with the plan floor %d; the inner MTU is not a "+
				"choice, it is what the floor implies", opts.tunMTU, sizing.InnerMTU)
	}

	// Everything decidable from the flags alone is decided HERE, before the
	// kernel interface exists and before the socket is bound. See
	// preflightSession for why, and checkTunAddrMatchesAssignment for the one
	// rule winn3/tun cannot make on its own.
	assign, err := parseAssignment(opts.innerV4, opts.routerV4)
	if err != nil {
		return err
	}
	sessionConfig, err := buildGatewaySession(opts)
	if err != nil {
		return err
	}
	if err := checkTunAddrMatchesAssignment(opts.tunAddr, assign); err != nil {
		return err
	}
	// In gateway mode the ASSIGNMENT is the authority on inner IPv6, not a flag:
	// parseAssignment builds it, and winn3/tun's familyAllowed answers off the
	// same value. -tun-addr6 may only agree with it, exactly as -tun-addr may
	// only agree with -inner-v4. Today parseAssignment takes no v6 input, so the
	// gateway's inner v6 is always unassigned and -tun-addr6 must be empty; when
	// a v6 assignment lands, this derivation lights up on its own and the
	// disable step in configureInterface stops firing without anyone editing it.
	innerV6 := ""
	if assign.V6.IsValid() {
		innerV6 = assign.V6.String()
	}
	if want := strings.TrimSpace(opts.tunAddr6); want != innerV6 {
		return fmt.Errorf(
			"-tun-addr6 %q does not match this gateway's inner IPv6 assignment %q; "+
				"the interface address and the tunnel's assignment must be the same "+
				"address or the kernel sources packets winn3/tun will refuse",
			want, innerV6)
	}
	if err := preflightSession(sizing, sessionConfig, assign); err != nil {
		return err
	}

	device, closeTun, err := openConfiguredTun(
		opts.tunName, opts.tunAddr, innerV6, sizing.InnerMTU, opts.tunRoutes)
	if err != nil {
		return err
	}
	defer func() { _ = closeTun() }()

	conn, peer, err := listenAndLearnPeer(opts.listen, out)
	if err != nil {
		return err
	}
	carrierConn, err := carrier.NewUDP(carrier.UDPConfig{
		Conn:           conn,
		Peer:           peer,
		OwnsConn:       true,
		MaxMessageSize: sizing.MessageSize,
		PathMTU:        sizing.PathMTU,
		// NewUDP requests DefaultUDPSocketBufferBytes (8 MiB) and does not
		// refuse a short kernel grant — that is the client pattern. This binary
		// is a responder, but it is still the caller the carrier package told
		// to print FormatUDPSocketBufferGrant: without the hook a clamped
		// SO_RCVBUF is indistinguishable from a slow path, which is the
		// throughput ceiling this tree already measured. The shipping gateway
		// refuses below 4 MiB; this rig logs and continues, because a laptop
		// lab cannot raise rmem_max.
		SocketBufferHook: func(requested, gotRead, gotWrite int, setErr error) {
			fmt.Fprintf(os.Stderr, "winn3-labrig: %s\n",
				carrier.FormatUDPSocketBufferGrant(requested, gotRead, gotWrite, setErr))
		},
	})
	if err != nil {
		_ = conn.Close()
		return err
	}

	tunConfig := tun.Config{
		Assign: assign,
		Device: device,
		Clock:  driver.SessionClock{Clock: driver.SystemClock{}},
	}

	loop, err := driver.NewGateway(driver.Config{
		Session: sessionConfig,
		Sizing:  sizing,
		Carrier: carrierConn,
		Tun:     &tunConfig,
	})
	if err != nil {
		_ = carrierConn.Close()
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serve(ctx, loop, sizing, out)
}

// preflightSession proves the operator's configuration can build a session at
// all, BEFORE the kernel interface is created and BEFORE the socket is bound,
// by building one exactly the way the first datagram will and throwing it away.
//
// # The defect this closes
//
// This is the lab rig's copy of silent-refusal instance #8, and it is worse here
// than it was in cmd/winn3-gateway. The rig used to resolve its assignment at
// main.go:239 and build the session at main.go:249 — both AFTER
// listenAndLearnPeer, which binds the socket and then blocks in MSG_PEEK until a
// client shows up. So a permanent, operator-caused configuration error
// (-router-v4 equal to -inner-v4, an IPv6 literal in -inner-v4, an empty
// -gateway-id, an admission file below the 32-byte floor) produced exactly this:
//
//	winn3-labrig: listening on 0.0.0.0:51833, waiting for an initiation
//	{"event":"listening","gate_state":"closed",...}
//
// and then nothing, for as long as nobody connected — with a kernel tun
// interface already created and addressed on the host. The rejection was real,
// loud and correct; winn3/tun (tun.go:169) and winn3/core (params.go:350) both
// state it. It simply arrived after the operator had stopped watching, and under
// this threat model a responder that binds and then says nothing is
// indistinguishable from one a censor is holding down.
//
// # Why a dry run and not a list of checks
//
// A hand-written copy of winn3/tun's and winn3/core's rules in this file would
// agree with itself while the real constructors rejected something else. So this
// runs the REAL constructors — driver.NewGateway -> session.NewGateway and
// driver.NewGateway -> tun.New — in the same order and with the same values the
// first datagram will use. A rule added to either package is enforced here on
// the day it is added, and this file does not have to be touched.
//
// It opens nothing and sends nothing. The carrier is a Pipe whose Out is never
// called and the device is preflightDevice, which has no descriptor, so this is
// safe to run before /dev/net/tun is opened and before the socket exists.
func preflightSession(
	sizing driver.Sizing, sessionCfg session.Config, assign tun.Assignment,
) error {
	pipe, err := carrier.NewPipe(carrier.PipeConfig{
		Class:          carrier.ClassUDP,
		Out:            func([]byte) error { return errors.New("preflight carrier never sends") },
		MaxMessageSize: sizing.MessageSize,
		PathMTU:        sizing.PathMTU,
	})
	if err != nil {
		return fmt.Errorf("this configuration cannot carry traffic: %w", err)
	}
	defer func() { _ = pipe.Close() }()

	tunConfig := tun.Config{
		Assign: assign,
		Device: preflightDevice{mtu: sizing.InnerMTU},
		Clock:  driver.SessionClock{Clock: driver.SystemClock{}},
	}
	loop, err := driver.NewGateway(driver.Config{
		Session: sessionCfg,
		Sizing:  sizing,
		Carrier: pipe,
		Tun:     &tunConfig,
	})
	if err != nil {
		return fmt.Errorf(
			"this configuration cannot build a session, so no client could ever be "+
				"admitted and the rig refuses to start rather than bind a socket and "+
				"wait in silence (-inner-v4 %s, -router-v4 %s, -gateway-id %s): %w",
			addrOrUnset(assign.V4), addrOrUnset(assign.RouterV4),
			quotedOrUnset(string(sessionCfg.Core.Gateway.GatewayID)), err)
	}
	return loop.Close()
}

// preflightDevice is the tun.Device the dry run builds against. It holds no
// descriptor and neither reads nor writes: preflightSession constructs a session
// and immediately closes it, so MTU is the only method that is ever called.
//
// The MTU it reports is not a convenient number, it is sizing.InnerMTU —
// precisely what openConfiguredTun will set on the real interface and therefore
// what labTun.MTU will report. tun.New refuses a device MTU above the inner MTU
// and below the IPv4 floor, and a dry run that reported some other MTU would be
// answering a question the real start never asks.
type preflightDevice struct{ mtu int }

// errPreflightIO is returned by both packet methods. Reaching either one means
// the dry run was wired into a running loop, which it never is.
var errPreflightIO = errors.New("winn3-labrig: the preflight device carries no packets")

func (d preflightDevice) ReadPacket([]byte) (int, error)  { return 0, errPreflightIO }
func (d preflightDevice) WritePacket([]byte) (int, error) { return 0, errPreflightIO }
func (d preflightDevice) MTU() int                        { return d.mtu }

var _ tun.Device = preflightDevice{}

// checkTunAddrMatchesAssignment refuses a rig whose interface address is not the
// address the tunnel was told it owns.
//
// This is the one rule preflightSession cannot make, because winn3/tun never
// sees -tun-addr: the host owns the interface and the tun layer owns the
// assignment, and nothing in the tree had ever compared them. They are the same
// address by construction — openConfiguredTun addresses the interface as a /32
// exactly so the kernel sources from it — and when they disagree the result is
// the purest form of the failure this file is being swept for:
//
//   - outbound, the kernel sources every packet from -tun-addr and
//     winn3/tun/ip.go's outbound rule requires src == the assignment, so every
//     packet the rig's kernel originates is refused with ErrSourceNotOurs and
//     counted in tx_dropped_invalid;
//   - inbound, the client addresses the assignment and the inbound rule requires
//     dst == the assignment, which holds — so the packet is delivered to an
//     interface that does not have that address, and the kernel drops it.
//
// The session handshakes, rekeys, moves bytes on the wire and delivers nothing.
// That is exactly the "looks alive, carries nothing" symptom the IFF_NO_PI note
// in tun_linux.go warns about, from a second cause, and it parsed cleanly.
func checkTunAddrMatchesAssignment(tunAddr string, assign tun.Assignment) error {
	trimmed := strings.TrimSpace(tunAddr)
	if trimmed == "" {
		// configureInterface refuses an empty address, and it does so before the
		// socket is bound. Not this function's rule to duplicate.
		return nil
	}
	addr, err := netip.ParseAddr(trimmed)
	if err != nil {
		return fmt.Errorf("-tun-addr: %w", err)
	}
	if addr != assign.V4 {
		return fmt.Errorf(
			"-tun-addr %s is not -inner-v4 %s; the kernel would source every packet "+
				"from %s and winn3/tun refuses any source that is not the assigned "+
				"address, so the session would handshake and carry nothing",
			addr, addrOrUnset(assign.V4), addr)
	}
	return nil
}

// addrOrUnset renders an optional address for an operator-facing message. The
// zero netip.Addr prints as "invalid IP", which reads as a complaint about a
// value the operator may never have typed.
func addrOrUnset(a netip.Addr) string {
	if !a.IsValid() {
		return "unset"
	}
	return a.String()
}

// quotedOrUnset is the same courtesy for a string flag: an empty -gateway-id is
// a flag the operator did not pass, not a flag they passed as "".
func quotedOrUnset(s string) string {
	if s == "" {
		return "unset"
	}
	return fmt.Sprintf("%q", s)
}

// serve runs the loop and publishes the same predicate cmd/winn-datapath does.
//
// The predicate is deliberately re-stated rather than imported: winn3_status.go
// is in package main of another command. Any drift between the two is a bug in
// THIS file, because the shipping side is the authority.
func serve(
	ctx context.Context, loop *driver.Loop, sizing driver.Sizing, out *os.File,
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- loop.Run(ctx) }()

	ticker := time.NewTicker(statusInterval)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			final := statusOf(loop, sizing)
			final.Event = "stopped"
			final.PromotionReady = false
			if err != nil {
				final.Refusal = err.Error()
			}
			_ = writeStatus(out, final)
			return err
		case <-ticker.C:
			if err := writeStatus(out, statusOf(loop, sizing)); err != nil {
				cancel()
				<-done
				return err
			}
		}
	}
}

// labStatus is a deliberately small echo of cmd/winn-datapath's status
// document: the same two counters the promotion predicate is built from, so the
// two ends of a session can be compared line for line.
type labStatus struct {
	Event          string `json:"event"`
	GateState      string `json:"gate_state"`
	PromotionReady bool   `json:"promotion_ready"`
	RxPackets      uint64 `json:"rx_packets"`
	RxOffered      uint64 `json:"rx_offered"`
	RxBytes        uint64 `json:"rx_bytes"`
	TxPackets      uint64 `json:"tx_packets"`
	TxBytes        uint64 `json:"tx_bytes"`

	// The two counters that tell a silent tunnel apart from a broken one.
	// RxDroppedInvalid climbing while RxOffered climbs is the IFF_NO_PI
	// mistake or a source address the gateway never assigned; RxDroppedClosed
	// climbing is the gate refusing to leak, which is the behaviour.
	RxDroppedInvalid uint64 `json:"rx_dropped_invalid"`
	RxDroppedClosed  uint64 `json:"rx_dropped_closed"`
	TxDroppedInvalid uint64 `json:"tx_dropped_invalid"`
	TxDroppedClosed  uint64 `json:"tx_dropped_closed"`

	InnerMTU    int    `json:"inner_mtu"`
	MessageSize int    `json:"message_size"`
	Refusal     string `json:"refusal,omitempty"`
}

func statusOf(loop *driver.Loop, sizing driver.Sizing) labStatus {
	status := labStatus{
		Event:       "posture",
		GateState:   "unknown",
		InnerMTU:    sizing.InnerMTU,
		MessageSize: sizing.MessageSize,
	}
	tunnel := loop.Tunnel()
	if tunnel == nil {
		return status
	}
	gate := tunnel.Gate().State()
	stats := tunnel.Stats()
	status.GateState = gate.String()
	status.RxPackets = stats.RxPackets
	status.RxOffered = stats.RxOffered
	status.RxBytes = stats.RxBytes
	status.TxPackets = stats.TxPackets
	status.TxBytes = stats.TxBytes
	status.RxDroppedInvalid = stats.RxDroppedInvalid
	status.RxDroppedClosed = stats.RxDroppedClosed
	status.TxDroppedInvalid = stats.TxDroppedInvalid
	status.TxDroppedClosed = stats.TxDroppedClosed
	// The same conjunction winn3PromotionReady states, and for the same reason:
	// RxPackets counts DELIVERIES, RxOffered counts arrivals.
	status.PromotionReady = gate == tun.StateCarrying && stats.RxPackets > 0
	return status
}

func writeStatus(out *os.File, status labStatus) error {
	encoded, err := json.Marshal(status)
	if err != nil {
		return err
	}
	if _, err := out.Write(append(encoded, '\n')); err != nil {
		return err
	}
	return nil
}

// buildGatewaySession assembles the responder's configuration.
func buildGatewaySession(opts gatewayOptions) (session.Config, error) {
	staticBytes, err := readKeyFile(opts.staticPath)
	if err != nil {
		return session.Config{}, fmt.Errorf("-static: %w", err)
	}
	staticKey, err := core.NewStaticKey(staticBytes)
	if err != nil {
		return session.Config{}, fmt.Errorf("-static: %w", err)
	}
	secret, err := os.ReadFile(opts.admission) //nolint:gosec // operator-named
	if err != nil {
		return session.Config{}, fmt.Errorf("-admission: %w", err)
	}
	secret = []byte(strings.TrimRight(string(secret), "\r\n"))

	return session.Config{
		Core: core.Config{
			Gateway: core.GatewayParams{
				AdmissionKeys: [][]byte{secret},
				GatewayID:     []byte(opts.gatewayID),
			},
		},
		Static:  staticKey,
		Padding: core.PadBucket,
		// ADMIT-ALL, stated rather than hidden. core refuses a responder with no
		// Accept precisely so that "authenticated" is never silently read as
		// "authorised"; this rig has no policy to apply and says so here rather
		// than shipping a stub that looks like one.
		Accept: func([]byte) error { return nil },
	}, nil
}

// readKeyFile accepts the same two encodings cmd/winn-datapath does.
func readKeyFile(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("empty path")
	}
	raw, err := os.ReadFile(path) //nolint:gosec // operator-named
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) == hex.EncodedLen(core.KeySize) {
		decoded, decodeErr := hex.DecodeString(trimmed)
		if decodeErr == nil {
			return decoded, nil
		}
	}
	if len(raw) == core.KeySize {
		return raw, nil
	}
	return nil, fmt.Errorf("%d bytes; expected %d raw or %d hex characters",
		len(raw), core.KeySize, hex.EncodedLen(core.KeySize))
}

// parseAssignment builds the inner address authority.
func parseAssignment(v4, routerV4 string) (tun.Assignment, error) {
	var out tun.Assignment
	if strings.TrimSpace(v4) == "" {
		return out, errors.New("-inner-v4 is empty")
	}
	addr, err := netip.ParseAddr(v4)
	if err != nil {
		return out, fmt.Errorf("-inner-v4: %w", err)
	}
	out.V4 = addr
	if strings.TrimSpace(routerV4) != "" {
		router, routerErr := netip.ParseAddr(routerV4)
		if routerErr != nil {
			return out, fmt.Errorf("-router-v4: %w", routerErr)
		}
		out.RouterV4 = router
	}
	return out, nil
}

// listenAndLearnPeer binds the responder's socket and waits for the first
// datagram, WITHOUT consuming it.
//
// MSG_PEEK rather than a read, because the datagram is the session's initiation
// and the session driver has to be the one that reads it. Peeking learns the
// address the carrier must reply to and leaves the bytes in the receive buffer
// for the loop that starts immediately afterwards.
func listenAndLearnPeer(
	listen string, out *os.File,
) (*net.UDPConn, *net.UDPAddr, error) {
	addr, err := net.ResolveUDPAddr("udp4", listen)
	if err != nil {
		return nil, nil, fmt.Errorf("-listen: %w", err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, nil, err
	}
	fmt.Fprintf(os.Stderr, "winn3-labrig: listening on %s, waiting for an initiation\n",
		conn.LocalAddr())
	if err := writeStatus(out, labStatus{Event: "listening", GateState: "closed"}); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}

	peer, err := peekPeer(conn)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	fmt.Fprintf(os.Stderr, "winn3-labrig: first datagram from %s\n", peer)
	return conn, peer, nil
}
