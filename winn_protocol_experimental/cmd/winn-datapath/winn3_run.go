package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"

	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// The Winn Protocol v3 mode.
//
// # Why this lives in winn-datapath and not in a second binary
//
// Both desktop hosts already start THIS process, already stage THIS filename,
// and already have the code that watches it and tears the tunnel down when it
// dies. A second binary would need a second set of all of that on two
// platforms, and the packaging gap it would open is exactly the one that left
// the Linux release archive with no engine in it at all.
//
// The two modes cannot be mixed. -winn3-profile refuses every winn/1 flag and
// vice versa: winn/1 relays AmneziaWG datagrams and v3 replaces AmneziaWG
// outright, so a process that had both configured would have two opinions about
// what its payloads are, and the failure mode of guessing wrong is cleartext on
// the wire.
//
// # Why the loop is built here rather than in the host
//
// winn3/driver refuses a session whose MaxMessageSize was set by anybody else,
// and computes it from the plan floor instead. That refusal is what stops a
// host sizing the tunnel to the carrier it dialled and black-holing every
// full-size flow on the first migration. Building the loop in the host would
// mean five hosts each holding a Sizing they could get wrong; building it here
// means the number is computed once, from the plan the host declared, and
// published back to the host as the MTU it must set.

// winn3DialTimeout bounds one carrier dial. Generous because a censored path is
// slow, bounded because a host waiting forever on a first status line looks
// identical to a hung engine.
const winn3DialTimeout = 30 * time.Second

// winn3StatusInterval is how often the status document is republished while
// nothing changes. A host polls its own state machine off these lines, so a
// silent engine must not be indistinguishable from a stalled one.
const winn3StatusInterval = time.Second

// winn3CloseGrace bounds how long a host stop waits for Loop.Close to put the
// CLOSE on the wire before Run's context is cancelled. Handing one message to
// the carrier takes milliseconds; the bound only matters when the carrier is
// already wedged.
const winn3CloseGrace = time.Second

// winn3Options is the v3 half of the command line.
//
// There are two v3 modes and they are mutually exclusive:
//
//   - -winn3-profile PATH is the DESKTOP mode. There is no Create frame; the
//     profile is the whole configuration, the engine owns the outer socket, and
//     status is line-delimited JSON on stdout.
//   - -winn3 is the FRAME mode. The host owns the tun device and pumps inner IP
//     packets over the duplex Inbound and Outbound frames, the create document
//     arrives in a Create frame, and status travels in StatusResponse. It needs
//     -winn3-keys for the material that must not cross the frame channel.
//
// Frame mode is the seam every platform can implement; the desktop mode is an
// optimisation for hosts that can hand a descriptor over. Both refuse every
// winn/1 flag.
type winn3Options struct {
	profile string
	tunFD   int

	// frame selects the frame mode.
	frame bool

	// keys names the winn/3 key document. Required by frame mode and refused by
	// the desktop mode, which carries its key paths in the profile.
	keys string
	// printSizing computes the plan floor from the profile and exits, so that a
	// host can configure its interface to the exact inner MTU BEFORE it starts
	// a tunnel. Without it a host has to start the engine to learn the number
	// it was supposed to have applied first.
	printSizing bool
}

// enabled reports whether the desktop profile mode was selected.
func (o winn3Options) enabled() bool { return o.profile != "" }

// frameEnabled reports whether the frame mode was selected.
func (o winn3Options) frameEnabled() bool { return o.frame }

// anyWinn3 reports whether this process is running the standalone v3 protocol
// in either of its two shapes.
func (o winn3Options) anyWinn3() bool { return o.enabled() || o.frameEnabled() }

// winn3RefuseMixedModes keeps the two protocols — and the two v3 modes — apart.
//
// decomposition that hides which one fired.
//
//nolint:gocyclo // a flat list of independent refusals reads better than a
func winn3RefuseMixedModes(opts options, v3 winn3Options) error {
	if v3.enabled() && v3.frameEnabled() {
		return errors.New(
			"-winn3 and -winn3-profile are the two v3 modes and this process " +
				"runs one of them: -winn3-profile owns the outer socket and the " +
				"tun device, and -winn3 lets the host own the tun and pump " +
				"inner packets over the frame channel. A process configured for " +
				"both would have two answers to who owns the device")
	}
	if !v3.anyWinn3() {
		if v3.tunFD >= 0 {
			return errors.New(
				"-winn3-tun-fd needs -winn3-profile: this process does not " +
					"own a tun device in winn/1 mode")
		}
		if v3.printSizing {
			return errors.New("-winn3-print-sizing needs -winn3-profile")
		}
		if v3.keys != "" {
			return errors.New(
				"-winn3-keys needs -winn3: the winn/1 datapath has no winn/3 " +
					"session to key")
		}
		return nil
	}
	if v3.frameEnabled() {
		return winn3RefuseMixedFrameModes(opts, v3)
	}
	if v3.keys != "" {
		return errors.New(
			"-winn3-keys applies to -winn3 only; the desktop profile carries " +
				"its own key paths, and two documents naming key files is two " +
				"documents that will eventually name different ones")
	}
	switch {
	case opts.carrierProfile != "":
		return errors.New(
			"-carrier-profile is a winn/1 carrier and -winn3-profile is the " +
				"standalone v3 protocol; they are different protocols and this " +
				"process runs one of them")
	case len(opts.carrierFallback) > 0:
		return errors.New("-carrier-fallback is winn/1 only")
	case opts.udpFD >= 0:
		return errors.New(
			"-udp-fd hands over a protected outer socket, which is the mobile " +
				"model; the v3 desktop mode opens its own socket under " +
				"allow_own_socket and needs the host's route exclusion instead")
	case opts.receiveFD:
		return errors.New(
			"-receive-fd is the winn/1 socket hand-off; use -winn3-tun-fd to " +
				"pass a tun descriptor")
	// "" is options' zero value, used by in-process callers that never went
	// through the flag set; the flag's own default is "stdio". Neither is a
	// request for a socket, and refusing them would make this function reject
	// a clean v3 configuration — which the over-fire control in
	// TestTheTwoProtocolsCannotBeMixed caught on the first run.
	case opts.transport != "" && opts.transport != "stdio":
		// run() returns into runWinn3 before it ever reaches the transport
		// switch, so these two flags used to reach NO code in this mode: not
		// honoured, not refused, no message. -transport unix -control PATH
		// alongside -winn3-profile left a host blocking on accept() forever
		// while the engine wrote status documents to a stdout nobody was
		// reading — both halves silent, which is the one outcome this protocol
		// must never be indistinguishable from.
		//
		// The frame mode refuses the same pair (winn3_frame.go:132-149) and the
		// winn/1 path honours it. Only the v3 desktop mode had neither.
		return fmt.Errorf(
			"-transport %q does not apply to -winn3-profile: the desktop v3 mode "+
				"establishes no frame transport at all and writes line-delimited "+
				"status documents to stdout, so a host waiting on a %s socket would "+
				"wait forever with nothing said on either side",
			opts.transport, opts.transport)
	case opts.control != "":
		return errors.New(
			"-control is the frame channel's control socket and the desktop v3 " +
				"mode has no frame channel; it would be silently ignored, and a " +
				"host that passed it is waiting to be connected to")
	}
	return nil
}

// winn3RefuseDeviceFlagMismatch is the remaining pair of the shape that kept
// winn3-gateway from starting: a required combination the process did not name.
//
// device.kind tun-fd requires -winn3-tun-fd N at the real start. The Linux
// backend used to say only "tun descriptor -1 is not usable", which does not
// name the flag, and the Darwin stub used to say the platform cannot do tun-fd
// at all, which is also true but hides a missing flag on Linux. -winn3-tun-fd
// with device.kind loopback-udp used to be stored in winn3AdoptedTunFD and then
// never read — not honoured, not refused, no message.
//
// -winn3-print-sizing may omit the descriptor: it is the pre-start hook, and
// the host has not opened /dev/net/tun yet. Passing -winn3-tun-fd alongside a
// loopback profile is still refused, including under print-sizing, because that
// flag would be ignored.
func winn3RefuseDeviceFlagMismatch(profile winn3Profile, v3 winn3Options) error {
	switch profile.Device.Kind {
	case winn3DeviceTunFD:
		if v3.tunFD < 0 && !v3.printSizing {
			return fmt.Errorf(
				"device.kind %s needs -winn3-tun-fd N: the host opens /dev/net/tun, "+
					"configures the interface, and passes the descriptor; this process "+
					"was started without one. -winn3-print-sizing may omit the flag "+
					"because it does not adopt a descriptor",
				winn3DeviceTunFD)
		}
	case winn3DeviceLoopbackUDP:
		if v3.tunFD >= 0 {
			return fmt.Errorf(
				"-winn3-tun-fd does not apply to device.kind %s: that backend is a "+
					"loopback seam the host already bound, and a tun descriptor passed "+
					"alongside it would be silently ignored. Omit -winn3-tun-fd, or set "+
					"device.kind %s",
				winn3DeviceLoopbackUDP, winn3DeviceTunFD)
		}
	}
	return nil
}

// runWinn3 is the v3 entry point.
//
// stdout carries the line-delimited status documents and NOTHING else; every
// diagnostic goes to stderr. A stray print to stdout would be read by a host as
// a status line, and a host that cannot parse a status line holds the bootstrap
// posture — which is safe, but it is also a tunnel that never works and never
// says why.
func runWinn3(ctx context.Context, v3 winn3Options, out io.Writer) error {
	profile, err := loadWinn3Profile(v3.profile)
	if err != nil {
		return err
	}
	if err := winn3RefuseDeviceFlagMismatch(profile, v3); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "winn-datapath: "+profile.describeForLog())

	classes, err := profile.classes()
	if err != nil {
		return err
	}
	pathMTU := profile.PathMTU
	if pathMTU == 0 {
		pathMTU = carrier.DefaultPathMTU
	}
	sizing, err := driver.NewSizing(pathMTU, classes...)
	if err != nil {
		return err
	}
	if v3.printSizing {
		// The pre-start hook must PRE-FLIGHT, not just measure. See
		// winn3PreflightSession: this used to return the plan floor here
		// without ever constructing a session, so a host asked "can I start
		// this?", was told a number, set its interface MTU to it, and then
		// started an engine that refused the same profile.
		if err := winn3PreflightSession(profile, sizing); err != nil {
			return err
		}
		return winn3WriteStatus(out, winn3StatusFrom(
			"sizing", nil, sizing, profile.OuterSocketExclusion))
	}

	// Everything that can fail without touching the network fails first. A
	// refusal after the socket is open is a refusal the host has already told
	// its user about.
	device, closeDevice, err := winn3BuildDevice(profile, sizing)
	if err != nil {
		return err
	}
	defer func() { _ = closeDevice() }()

	sessionConfig, admission, err := winn3BuildSession(profile)
	if err != nil {
		return err
	}

	conn, err := winn3DialCarrier(ctx, profile, sizing, admission)
	if err != nil {
		return err
	}

	assignment, err := profile.Inner.assignmentAddrs()
	if err != nil {
		return err
	}
	// CarrierFloorMessageSize is deliberately NOT set here. driver.Config
	// refuses a tun configuration that carries one and pins it from Sizing
	// itself, which is what stops a host sizing the tunnel to the carrier it
	// dialled rather than to the plan floor.
	tunConfig := tun.Config{
		Assign: tun.Assignment{
			V4:       assignment.V4,
			V6:       assignment.V6,
			RouterV4: assignment.RouterV4,
			RouterV6: assignment.RouterV6,
		},
		Device: device,
		Clock:  driver.SessionClock{Clock: driver.SystemClock{}},
	}

	build := driver.NewClient
	if profile.Role == winn3RoleGateway {
		build = driver.NewGateway
	}
	loop, err := build(driver.Config{
		Session: sessionConfig,
		Sizing:  sizing,
		Carrier: conn,
		Tun:     &tunConfig,
	})
	if err != nil {
		_ = conn.Close()
		return err
	}

	var tcpFallback func(context.Context) (carrier.Conn, error)
	if profile.Role == winn3RoleClient && conn.Class() == carrier.ClassUDP &&
		sizing.Allows(carrier.ClassTCP) {
		tcpProfile := profile
		tcpProfile.Carrier.Class = "tcp"
		tcpFallback = func(ctx context.Context) (carrier.Conn, error) {
			return winn3DialCarrier(ctx, tcpProfile, sizing, admission)
		}
	}
	return winn3Serve(ctx, loop, sizing, profile.OuterSocketExclusion, out, tcpFallback)
}

// winn3PreflightSession proves the profile can build a session at all, by
// building one exactly the way runWinn3 will and throwing it away.
//
// # The defect this closes
//
// -winn3-print-sizing is documented as the host's pre-start hook, and the
// Windows supervisor uses it for exactly that: STEP 3 runs it "with nothing yet
// touching the network" and treats success as permission to create the Wintun
// adapter. But the branch above used to return the plan floor immediately,
// BEFORE winn3BuildDevice, BEFORE winn3DialCarrier and — the part that matters
// — before driver.NewClient, which is the only place tun.New runs and therefore
// the only place the inner assignment is checked at all
// (winn3/tun/tun.go:165-180, winn3/tun/params.go:168-205). The profile
// validator does not restate those rules: winn3InnerSpec.assignmentAddrs parses
// and family-checks and nothing more.
//
// So a profile with inner.router_v4 equal to inner.v4 — silent-refusal instance
// #8, in this binary — passed the pre-start hook, and the real start then died
// on stderr one line after printing the loopback seam port. The supervisor's
// stderr reader keeps the seam port and discards every other line, so the
// operator was told "the datapath stopped before it carried anything": a
// liveness sentence for a permanent configuration error, under a threat model
// where liveness sentences mean a censor.
//
// # Why a dry run and not a list of checks
//
// A hand-written copy of the address rules here would agree with itself while
// tun.New rejected something else. This runs the REAL constructors — the same
// driver.NewClient or driver.NewGateway, with the same session config and the
// same assignment — so a rule added to winn3/tun, winn3/session or winn3/core is
// enforced by the pre-start hook on the day it is added.
//
// # What it does NOT prove, stated so nobody reads more into a pass
//
// It opens nothing: the carrier is a Pipe whose Out is never called and the
// device is winn3PreflightDevice, which has no descriptor. That is the point,
// and it is also the limit. Two things therefore remain checkable only at the
// real start, and both already refuse loudly there:
//
//   - the HOST's interface MTU, which winn3BuildDevice reads from the kernel
//     for device kind tunfd and compares against the plan floor;
//   - reachability of carrier.endpoint, which is a peer fact and not an
//     operator one.
func winn3PreflightSession(profile winn3Profile, sizing driver.Sizing) error {
	sessionConfig, _, err := winn3BuildSession(profile)
	if err != nil {
		return err
	}
	assignment, err := profile.Inner.assignmentAddrs()
	if err != nil {
		return err
	}

	pipe, err := carrier.NewPipe(carrier.PipeConfig{
		Class:          carrier.ClassUDP,
		Out:            func([]byte) error { return errors.New("preflight carrier never sends") },
		MaxMessageSize: sizing.MessageSize,
		PathMTU:        sizing.PathMTU,
	})
	if err != nil {
		return fmt.Errorf("this profile cannot carry traffic: %w", err)
	}
	defer func() { _ = pipe.Close() }()

	// CarrierFloorMessageSize is deliberately NOT set, for the reason runWinn3
	// states: driver.Config pins it from Sizing and refuses a tun configuration
	// that carries its own.
	tunConfig := tun.Config{
		Assign: tun.Assignment{
			V4:       assignment.V4,
			V6:       assignment.V6,
			RouterV4: assignment.RouterV4,
			RouterV6: assignment.RouterV6,
		},
		Device: winn3PreflightDevice{mtu: sizing.InnerMTU},
		Clock:  driver.SessionClock{Clock: driver.SystemClock{}},
	}
	build := driver.NewClient
	if profile.Role == winn3RoleGateway {
		build = driver.NewGateway
	}
	loop, err := build(driver.Config{
		Session: sessionConfig,
		Sizing:  sizing,
		Carrier: pipe,
		Tun:     &tunConfig,
	})
	if err != nil {
		return fmt.Errorf(
			"this profile cannot build a session, so the tunnel could never carry "+
				"anything and this process refuses to report a plan floor a host "+
				"would then configure an interface to (inner.v4 %s, inner.router_v4 %s, "+
				"inner.v6 %s, inner.router_v6 %s, path_mtu %d): %w",
			winn3AddrOrUnset(assignment.V4), winn3AddrOrUnset(assignment.RouterV4),
			winn3AddrOrUnset(assignment.V6), winn3AddrOrUnset(assignment.RouterV6),
			sizing.PathMTU, err)
	}
	return loop.Close()
}

// winn3PreflightDevice is the tun.Device the dry run builds against. It holds no
// descriptor and neither reads nor writes; MTU is the only method ever called.
//
// The MTU it reports is the plan floor, which is the BEST case rather than a
// measurement — for device kind tunfd the host's real interface may be wider,
// and winn3BuildDevice refuses that at the real start. Reporting the floor here
// keeps the dry run from inventing a refusal the real start would not make.
type winn3PreflightDevice struct{ mtu int }

var errWinn3PreflightIO = errors.New(
	"winn-datapath: the winn3 preflight device carries no packets")

func (d winn3PreflightDevice) ReadPacket([]byte) (int, error)  { return 0, errWinn3PreflightIO }
func (d winn3PreflightDevice) WritePacket([]byte) (int, error) { return 0, errWinn3PreflightIO }
func (d winn3PreflightDevice) MTU() int                        { return d.mtu }

var _ tun.Device = winn3PreflightDevice{}

// winn3AddrOrUnset renders an optional address for an operator-facing message.
// The zero netip.Addr prints as "invalid IP", which reads as a complaint about a
// value the operator may never have written.
func winn3AddrOrUnset(a netip.Addr) string {
	if !a.IsValid() {
		return "unset"
	}
	return a.String()
}

// winn3Serve runs the loop and publishes status until it stops.
//
// The status writer runs in THIS goroutine and the loop in the other, so that a
// host blocked on reading the pipe cannot wedge the datapath, and so that the
// final "stopped" document is written after Run has returned — by which time
// the gate is latched down and no packet can still be in flight.
func winn3Serve(
	ctx context.Context,
	loop *driver.Loop,
	sizing driver.Sizing,
	exclusion string,
	out io.Writer,
	tcpFallback ...func(context.Context) (carrier.Conn, error),
) error {
	// Run does not take the host's context directly. A host stop (SIGTERM,
	// through the NotifyContext in run) is answered with Loop.Close, which
	// latches the gate down at once and then puts an ordinary CLOSE on the
	// wire, and only then ends Run; cancelling Run's context first returns
	// with the session still ESTABLISHED and says nothing, so the gateway kept
	// the session, its -max-sessions slot and its probes toward a dead port
	// for 50 to 80 s (L22b: 7 to 74 s of datagrams after every SIGTERM).
	// winn3CloseGrace bounds the wait, and cancel is the backstop.
	hostCtx := ctx
	ctx, cancel := context.WithCancel(context.WithoutCancel(hostCtx))
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- loop.Run(ctx) }()
	if len(tcpFallback) > 0 && tcpFallback[0] != nil {
		go driver.MigrateSilentUDP(ctx, loop, tcpFallback[0])
	}

	if err := winn3WriteStatus(out, winn3StatusFrom(
		"posture", loop, sizing, exclusion)); err != nil {
		cancel()
		<-done
		return err
	}

	ticker := time.NewTicker(winn3StatusInterval)
	defer ticker.Stop()
	promoted := false
	stopping := hostCtx.Done()
	for {
		select {
		case <-stopping:
			stopping = nil
			_ = loop.Close()
			go func() {
				select {
				case <-time.After(winn3CloseGrace):
					cancel()
				case <-ctx.Done():
				}
			}()
		case err := <-done:
			if err == nil && hostCtx.Err() != nil {
				// The host stopped us and the orderly close completed. Report it
				// exactly as the cancelled Run used to, so a host reading the
				// final document or the exit status sees no change.
				err = hostCtx.Err()
			}
			final := winn3StatusFrom("stopped", loop, sizing, exclusion)
			// A stopped loop has a latched gate, so the promotion predicate is
			// false by construction here. Saying it explicitly means a host
			// that reads only the last line still tears the posture down.
			final.PromotionReady = false
			final.Posture = winn3PostureBootstrap
			if err != nil {
				final.Refusal = err.Error()
			}
			if writeErr := winn3WriteStatus(out, final); writeErr != nil {
				return writeErr
			}
			return err
		case <-ticker.C:
			status := winn3StatusFrom("posture", loop, sizing, exclusion)
			if status.PromotionReady && !promoted {
				// The one transition a host acts on. It is announced once, as
				// its own event, so that a host does not have to diff two
				// documents to find it.
				promoted = true
				status.Event = "carrying"
			}
			if err := winn3WriteStatus(out, status); err != nil {
				cancel()
				<-done
				return err
			}
		}
	}
}

// winn3BuildDevice builds the host device backend named in the profile.
func winn3BuildDevice(
	profile winn3Profile, sizing driver.Sizing,
) (tun.Device, func() error, error) {
	switch profile.Device.Kind {
	case winn3DeviceLoopbackUDP:
		device, err := newWinn3LoopbackDevice(
			profile.Device.HostPort, sizing.InnerMTU)
		if err != nil {
			return nil, nil, err
		}
		// The port is printed to STDERR, not into the status document: the host
		// needs it before the first status line to finish wiring its own half
		// of the seam, and it is not a counter.
		fmt.Fprintf(os.Stderr,
			"winn-datapath: winn3 loopback seam engine port %d\n",
			device.LocalPort())
		return device, device.Close, nil
	case winn3DeviceTunFD:
		descriptor := winn3AdoptedTunFD
		device, err := newWinn3TunFDDevice(descriptor, profile.Device.Name)
		if err != nil {
			return nil, nil, err
		}
		if device.MTU() > sizing.InnerMTU {
			_ = device.Close()
			return nil, nil, fmt.Errorf(
				"the host set %q to MTU %d and the plan floor is %d: a device "+
					"MTU larger than the tunnel can carry black holes every "+
					"full-size flow, so this is a refusal rather than a warning",
				profile.Device.Name, device.MTU(), sizing.InnerMTU)
		}
		return device, device.Close, nil
	default:
		return nil, nil, winn3Refuse("device.kind %q", profile.Device.Kind)
	}
}

// winn3AdoptedTunFD is the descriptor -winn3-tun-fd supplied, or -1.
//
// A package-level variable rather than a parameter because the flag is parsed
// in run() and the device is built several calls deeper; threading an int
// through three signatures to avoid one variable would be the worse trade.
var winn3AdoptedTunFD = -1

// winn3BuildSession assembles the session configuration and returns the
// admission secret alongside it, because the stream carrier needs the same
// bytes and reading the file twice is a second chance to read a different file.
func winn3BuildSession(
	profile winn3Profile,
) (session.Config, []byte, error) {
	staticKeyBytes, err := winn3ReadKeyFile(profile.Keys.StaticPath, "keys.static_path")
	if err != nil {
		return session.Config{}, nil, err
	}
	staticKey, err := core.NewStaticKey(staticKeyBytes)
	// ecdh.NewPrivateKey keeps its own copy of the scalar (as in
	// winn3/hostqueue's winn3BuildSession).
	clear(staticKeyBytes)
	if err != nil {
		return session.Config{}, nil, fmt.Errorf("keys.static_path: %w", err)
	}
	admission, err := readPrivateKeyFile(profile.Keys.AdmissionPath, "keys.admission_path")
	if err != nil {
		return session.Config{}, nil, err
	}
	admission = bytes.TrimRight(admission, "\r\n")

	cfg := session.Config{
		Core: core.Config{
			Gateway: core.GatewayParams{
				AdmissionKeys: [][]byte{admission},
				GatewayID:     []byte(profile.GatewayID),
			},
		},
		Static: staticKey,
		// PadBucket is the design's default and PadNone is the zero value, so
		// leaving this unset would silently ship the unshaped one.
		Padding:   core.PadBucket,
		FastPQ:    profile.FastPQ,
		SendQueue: 65536,
	}
	switch profile.Role {
	case winn3RoleClient:
		cfg.Core.TokenWindow = winn3ClientTokenWindow
		gatewayBytes, err := winn3ReadKeyFile(
			profile.Keys.GatewayStaticPath, "keys.gateway_static_path")
		if err != nil {
			return session.Config{}, nil, err
		}
		gatewayStatic, err := core.NewPublicKey(gatewayBytes)
		if err != nil {
			return session.Config{}, nil, fmt.Errorf(
				"keys.gateway_static_path: %w", err)
		}
		cfg.GatewayStatic = gatewayStatic
		if err := applyDualAuthPublics(
			&cfg, profile.Keys.DualAuthEd25519PubPath, profile.Keys.DualAuthMLDSA65PubPath,
		); err != nil {
			return session.Config{}, nil, err
		}
	case winn3RoleGateway:
		// The core refuses a responder with no Accept, deliberately, because
		// "authenticated" and "authorised" are different questions. This mode
		// exists to serve the lab's responding half, so the honest thing is an
		// admit-all that says so rather than a stub that looks like policy.
		cfg.Accept = func([]byte) error { return nil }
	}
	return cfg, admission, nil
}

// winn3DialCarrier opens the class the profile named.
//
// The MESSAGE SIZE handed to every carrier is the plan floor, never the class's
// own ceiling. That is the whole point of Sizing and it is applied here so that
// no carrier constructor in this file can be given anything else.
func winn3DialCarrier(
	ctx context.Context,
	profile winn3Profile,
	sizing driver.Sizing,
	admission []byte,
) (carrier.Conn, error) {
	class, err := winn3ClassNamed(profile.Carrier.Class)
	if err != nil {
		return nil, err
	}
	dialCtx, cancel := context.WithTimeout(ctx, winn3DialTimeout)
	defer cancel()

	role := carrier.RoleClient
	if profile.Role == winn3RoleGateway {
		role = carrier.RoleGateway
	}

	switch class {
	case carrier.ClassUDP:
		remote, resolveErr := net.ResolveUDPAddr("udp", profile.Carrier.Endpoint)
		if resolveErr != nil {
			return nil, fmt.Errorf("carrier.endpoint: %w", resolveErr)
		}
		return carrier.DialUDP(dialCtx, carrier.UDPConfig{
			Remote:         remote,
			MaxMessageSize: sizing.MessageSize,
			PathMTU:        sizing.PathMTU,
			SocketBufferHook: func(requested, gotRead, gotWrite int, setErr error) {
				fmt.Fprintf(os.Stderr, "winn-datapath: %s\n",
					carrier.FormatUDPSocketBufferGrant(requested, gotRead, gotWrite, setErr))
			},
		})
	case carrier.ClassTCP:
		return carrier.DialStream(dialCtx,
			carrier.DialTCP(profile.Carrier.Endpoint),
			carrier.StreamConfig{
				Secret:         admission,
				Role:           role,
				MaxMessageSize: sizing.MessageSize,
				PathMTU:        sizing.PathMTU,
				TCPFirstFlight: true,
			})
	case carrier.ClassTLS:
		return winn3DialTLS(dialCtx, profile, sizing, admission, role)
	default:
		return nil, winn3Refuse("carrier.class %s", class)
	}
}

// winn3DialTLS opens a TLS stream through internal/tlsconfig. That package is
// the single typed entry point for every client hello in this tree; building a
// *tls.Config here would be a second hello to keep in step, and dialling bare
// TCP while reporting TLS would be a silent downgrade.
func winn3DialTLS(
	ctx context.Context,
	profile winn3Profile,
	sizing driver.Sizing,
	admission []byte,
	role carrier.Role,
) (carrier.Conn, error) {
	suite, err := tlsconfig.ParseSuite(profile.Carrier.Suite)
	if err != nil {
		return nil, winn3Refuse("carrier.suite: %v", err)
	}
	alpn := profile.Carrier.tlsALPN()
	trust := tlsconfig.ClientTrust{
		Anchor:     tlsconfig.TrustAnchor(profile.Carrier.TrustAnchor),
		RootCAPath: profile.Carrier.RootCAPath,
	}
	var clientTLS *tls.Config
	if trust.Anchor == tlsconfig.TrustWebPKI {
		clientTLS, err = tlsconfig.ClientAnonymousTrusted(
			trust, profile.Carrier.ServerName, suite, alpn)
	} else {
		clientTLS, err = tlsconfig.ClientForALPN(
			profile.Carrier.ClientCertPath,
			profile.Carrier.ClientKeyPath,
			profile.Carrier.RootCAPath,
			profile.Carrier.ServerName,
			suite,
			alpn,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("winn3 tls client: %w", err)
	}
	echList, err := echconfig.LoadClientConfigList(profile.Carrier.ECHConfigListPath)
	if err != nil {
		return nil, fmt.Errorf("winn3 tls ECH config list: %w", err)
	}
	err = echconfig.ConfigureClient(clientTLS, echList, true)
	clear(echList)
	if err != nil {
		return nil, fmt.Errorf("winn3 tls ECH: %w", err)
	}

	endpoint := profile.Carrier.Endpoint
	raw, err := (&tls.Dialer{Config: clientTLS}).DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, err
	}
	tlsConn, ok := raw.(*tls.Conn)
	if !ok {
		_ = raw.Close()
		return nil, winn3Refuse(
			"dialled class tls but the connection is %T: refusing a silent downgrade",
			raw)
	}
	state := tlsConn.ConnectionState()
	if !state.ECHAccepted {
		_ = tlsConn.Close()
		return nil, winn3Refuse("dialled class tls but ECH was not accepted")
	}
	if err := tlsconfig.ValidateStateForALPN(&state, suite, alpn); err != nil {
		_ = tlsConn.Close()
		return nil, winn3Refuse("winn3 tls handshake: %v", err)
	}
	stream, err := carrier.NewStream(carrier.StreamConfig{
		Conn:           tlsConn,
		Secret:         admission,
		Role:           role,
		MaxMessageSize: sizing.MessageSize,
		PathMTU:        sizing.PathMTU,
	})
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	if stream.Class() != carrier.ClassTLS {
		_ = stream.Close()
		return nil, winn3Refuse(
			"dialled class tls but the stream is %s: refusing a silent downgrade",
			stream.Class())
	}
	return stream, nil
}
