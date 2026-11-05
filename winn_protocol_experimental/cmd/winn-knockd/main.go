// Command winn-knockd is the node-side daemon for Winn's alternative
// connection initiation: it listens for internal/knock Single Packet
// Authorization datagrams and, for each verified knock, adds the source address
// to an nftables set that a kernel rule uses to admit that source to ports this
// process does not own.
//
// # What this adds that cmd/winn-carrier-server's -spa-required does not
//
// -spa-required wraps the carrier server's OWN listeners with a knock.Gate. It
// is complete and tested, and it protects exactly one thing: the carrier
// server's port. On a production Winn node the ports that matter are bound by
// other processes entirely - udp/9110 by amneziawg-go in a --network host
// container, tcp/80 and tcp/443 by nginx in front of Xray - and a Go wrapper
// cannot reach any of them. docs/SPA_DESIGN.md §4.4 identified this and left it
// as "a reasonable v2 for Linux fleet nodes specifically". This is that v2.
//
// The verification logic is NOT reimplemented here. internal/knock's Gate does
// every cryptographic and anti-abuse decision, unchanged, through its exported
// Consider method; this binary only turns a grant into a firewall element.
//
// # This daemon can only ever open a port, never close one
//
// It adds set elements. It never deletes one, never writes an nftables rule,
// and never touches a table it did not authorize into. Authorization is removed
// by exactly two mechanisms, both outside this process: the kernel's own
// per-element timeout, and an operator deleting the table. That is deliberate,
// and it is what makes the failure analysis short - see the -h text for
// "IF THIS DAEMON DIES".
//
// # It never answers
//
// internal/knock's central property is that a knock's success and failure are
// indistinguishable on the wire. This daemon never writes to its socket on any
// path.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"winsvpn.local/winnprotocol/internal/knock"
	"winsvpn.local/winnprotocol/internal/spagate"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.SetPrefix("winn-knockd: ")

	var (
		keysPath   string
		listenAddr string
		packetSize int
		grace      time.Duration

		bucketWindow time.Duration
		maxSkew      time.Duration

		nftBinary string
		nftFamily string
		nftTable  string
		nftSetV4  string
		nftSetV6  string

		dryRun         bool
		statusInterval time.Duration

		limits = spagate.DefaultLimits()
	)

	flag.StringVar(&keysPath, "keys", "",
		"REQUIRED. Path to this deployment's SPA key file: one hex-encoded key "+
			"per line, most current FIRST. Additional lines are accepted and "+
			"are the rotation overlap window (see internal/knock.Verify). The "+
			"file must be readable only by this daemon's user; it is a "+
			"credential and is never logged.")
	flag.StringVar(&listenAddr, "listen", "",
		"REQUIRED. UDP address to receive knocks on, e.g. 0.0.0.0:9111. This "+
			"is NOT the port being protected -- it cannot be, because the "+
			"protected port is bound by another process (amneziawg-go, nginx). "+
			"Nothing is ever written back to this socket, so a scanner sees a "+
			"port that is indistinguishable from filtered.")
	flag.IntVar(&packetSize, "packet-size", 0,
		"REQUIRED. Exact knock datagram size in bytes. Must match every "+
			"client's exactly; a mismatch fails closed (no knock ever "+
			"verifies). Pick the size of the traffic this port should blend "+
			"into -- see docs/SPA_DESIGN.md §4.1.")
	flag.DurationVar(&grace, "grace", spagate.DefaultGrace,
		"How long an authorization survives SILENCE from that source. The "+
			"kernel re-arms it on every matching packet, so this is not a "+
			"session limit: an active tunnel stays authorized indefinitely. "+
			"Only a source quieter than a live connection falls out. This is "+
			"MUCH longer than internal/knock's own 90s default on purpose -- a "+
			"knock here opens a firewall for a client that may be a phone with "+
			"its screen off, and the cost of expiring too early is a lockout, "+
			"not a retry.")
	flag.DurationVar(&bucketWindow, "bucket-window", 0,
		"SPA freshness bucket width. Zero uses internal/knock's default (10s). "+
			"Must match every client's or no knock verifies.")
	flag.DurationVar(&maxSkew, "max-skew", 0,
		"Maximum tolerated clock difference in either direction. Zero uses "+
			"internal/knock's default (60s). Must match every client's.")

	flag.StringVar(&nftBinary, "nft", spagate.DefaultNFTBinary,
		"Path to nft(8).")
	flag.StringVar(&nftFamily, "nft-family", spagate.DefaultFamily,
		"nftables address family holding the allow sets.")
	flag.StringVar(&nftTable, "nft-table", spagate.DefaultTable,
		"nftables table holding the allow sets. It MUST be a table dedicated "+
			"to SPA and to nothing else, because the documented revert is "+
			"nft delete table FAMILY TABLE and that must not remove any "+
			"other rule.")
	flag.StringVar(&nftSetV4, "nft-set-v4", spagate.DefaultSetV4,
		"nftables set for authorized IPv4 sources. Empty disables IPv4.")
	flag.StringVar(&nftSetV6, "nft-set-v6", "",
		"nftables set for authorized IPv6 sources. Empty (the default) "+
			"disables IPv6, which matches a node whose edge hardening drops "+
			"IPv6 wholesale.")

	flag.BoolVar(&dryRun, "dry-run", false,
		"Verify and log knocks but NEVER touch the firewall. This is the safe "+
			"first deployment step: it proves keys, sizing and reachability "+
			"against real traffic on a live node while no packet's fate "+
			"changes. Nothing is gated until an operator installs the ruleset "+
			"and restarts without this flag.")
	flag.DurationVar(&statusInterval, "status-interval", 15*time.Minute,
		"How often to log a counter summary. Zero disables.")

	flag.IntVar(&limits.RateBurst, "rate-burst", limits.RateBurst,
		"Pre-verification burst allowance per SOURCE ADDRESS. Note a CGNAT "+
			"egress is one address for everyone behind it, which is why this "+
			"is larger than internal/knock's own default of 4.")
	flag.Float64Var(&limits.RatePerMinute, "rate-per-minute", limits.RatePerMinute,
		"Pre-verification sustained rate per source address.")
	flag.IntVar(&limits.MaxSources, "rate-max-sources", limits.MaxSources,
		"How many distinct source addresses the rate limiter tracks. WHEN THIS "+
			"FILLS, NEW SOURCES ARE REFUSED BEFORE VERIFICATION -- and because "+
			"the limiter runs on unauthenticated, spoofable input, a flood of "+
			"forged sources can fill it and deny authorization to everyone new "+
			"while this daemon stays healthy (so no watchdog fires). Raising "+
			"this raises the attacker's cost linearly; it does not remove the "+
			"attack.")
	flag.IntVar(&limits.MaxAuthorized, "max-authorized-sources", limits.MaxAuthorized,
		"Bound on the Gate's own authorization map. The kernel's set is the "+
			"real authority, so this mostly bounds memory.")
	flag.IntVar(&limits.MaxReplayNonces, "max-replay-nonces", limits.MaxReplayNonces,
		"Bound on the replay cache.")

	flag.Usage = usage
	flag.Parse()

	if flag.NArg() > 0 {
		exitError("unexpected positional argument %q", flag.Arg(0))
	}
	if keysPath == "" {
		exitError("-keys is required")
	}
	if listenAddr == "" {
		exitError("-listen is required")
	}
	if packetSize < knock.HeaderSize {
		exitError(
			"-packet-size is required and must be at least %d "+
				"(the knock header size); got %d",
			knock.HeaderSize, packetSize,
		)
	}
	if grace <= 0 {
		exitError("-grace must be positive")
	}
	if err := validateSPALimits(limits); err != nil {
		exitError("%v", err)
	}

	// Refuse to be pointed at the SSH port. A knock daemon in front of SSH is a
	// defensible design, but it is not THIS change, and an operator who typed
	// it by accident on the only reachable node would have no way back in. The
	// listen socket is not the gated port, so this only catches the obvious
	// slip, which is exactly the one worth catching.
	if _, port, err := net.SplitHostPort(listenAddr); err == nil && port == "22" {
		exitError(
			"refusing to listen for knocks on port 22: SSH must stay reachable " +
				"and must not be entangled with SPA in this change",
		)
	}

	keys, err := knock.LoadKeysFromFile(keysPath)
	if err != nil {
		// The loader's message names the file and the failure, never a byte of
		// its contents.
		exitError("%v", err)
	}
	defer func() {
		for _, key := range keys {
			clear(key)
		}
	}()

	var counters *spagate.Counters
	options := knock.Options{BucketWindow: bucketWindow, MaxSkew: maxSkew}

	// Build the enforcer first, so a misconfigured firewall is refused before
	// the socket is bound and before any key is held any longer than needed.
	var enforcer spagate.Enforcer
	if dryRun {
		enforcer = &spagate.DryRunEnforcer{}
	} else {
		nftEnforcer, nftErr := spagate.NewNFTEnforcer(spagate.NFTConfig{
			Binary: nftBinary,
			Family: nftFamily,
			Table:  nftTable,
			SetV4:  nftSetV4,
			SetV6:  nftSetV6,
		})
		if nftErr != nil {
			exitError("%v", nftErr)
		}
		// A missing table means every knock would verify, every counter would
		// increment, and no packet would ever be admitted -- "SPA appears to be
		// running". Refuse at startup instead.
		preflightCtx, cancelPreflight := context.WithTimeout(
			context.Background(), 10*time.Second,
		)
		preflightErr := nftEnforcer.Preflight(preflightCtx, grace)
		cancelPreflight()
		if preflightErr != nil {
			exitError(
				"%v\n\nInstall the ruleset first: deploy/spa/winn-spa-nft apply",
				preflightErr,
			)
		}
		enforcer = nftEnforcer
	}

	counters = new(spagate.Counters)
	gate, err := spagate.NewGateFor(
		keys, packetSize, options, grace, limits, counters,
	)
	if err != nil {
		exitError("%v", err)
	}

	daemon, err := spagate.New(spagate.Config{
		Gate:       gate,
		Enforcer:   enforcer,
		PacketSize: packetSize,
		Grace:      grace,
		Counters:   counters,
		Log:        func(format string, args ...any) { log.Printf(format, args...) },
	})
	if err != nil {
		exitError("%v", err)
	}

	packetConn, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		exitError("binding knock socket %s: %v", listenAddr, err)
	}
	defer packetConn.Close()

	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
	defer stop()

	log.Printf("listening for SPA knocks on udp/%s", packetConn.LocalAddr())
	log.Printf("%s", enforcer.DescribeForLog())
	log.Printf(
		"packet_size=%d grace=%s keys_loaded=%d (never logged)",
		packetSize, grace, len(keys),
	)
	log.Printf(
		"limits: rate_burst=%d rate_per_minute=%g rate_max_sources=%d "+
			"max_authorized=%d max_replay_nonces=%d",
		limits.RateBurst, limits.RatePerMinute, limits.MaxSources,
		limits.MaxAuthorized, limits.MaxReplayNonces,
	)

	// Clock skew is a silent, total lockout and this daemon cannot detect or
	// correct it. No timestamp is transmitted in a knock (see internal/knock's
	// package doc): the verifier recomputes the tag over time buckets near its
	// OWN clock. If this node's clock drifts further than the tolerated skew,
	// every knock from every correct client fails verification, forever, and the
	// only symptom is rejected_unauthenticated climbing. The unit additionally
	// sets ProtectClock=yes, so this process could not fix the clock even if it
	// noticed. NTP on the node is therefore a hard operational dependency, and
	// saying so at startup is the cheapest place to say it.
	effectiveBucket, effectiveSkew := bucketWindow, maxSkew
	if effectiveBucket == 0 {
		effectiveBucket = 10 * time.Second // internal/knock's default
	}
	if effectiveSkew == 0 {
		effectiveSkew = 60 * time.Second // internal/knock's default
	}
	log.Printf(
		"freshness: bucket=%s max_skew=%s -- clients MUST match these, and this "+
			"node's clock must stay within %s of theirs or EVERY knock fails "+
			"silently (keep chrony/systemd-timesyncd running)",
		effectiveBucket, effectiveSkew, effectiveSkew,
	)
	if dryRun {
		log.Printf(
			"DRY RUN: no firewall rule will be touched; no port is gated by " +
				"this process",
		)
	}

	if statusInterval > 0 {
		go func() {
			ticker := time.NewTicker(statusInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					log.Printf("status: %s", daemon.Counters.Snapshot())
				}
			}
		}()
	}

	err = daemon.Serve(ctx, packetConn)
	log.Printf("final: %s", daemon.Counters.Snapshot())
	if err != nil && !errors.Is(err, context.Canceled) {
		exitError("%v", err)
	}
	log.Printf("shutting down cleanly")
}

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprint(out, `winn-knockd - node-side Single Packet Authorization daemon

Listens for internal/knock SPA datagrams and adds each verified source address
to an nftables set, so a kernel rule can admit that source to a port this
process does not own (udp/9110 AmneziaWG, tcp/80 and tcp/443).

USAGE
  winn-knockd -keys PATH -listen ADDR -packet-size N [options]

THIS DAEMON CAN ONLY OPEN A PORT, NEVER CLOSE ONE
  It adds set elements and nothing else. It writes no nftables rule, deletes no
  element, and creates no table. Authorization is withdrawn only by the kernel's
  own per-element timeout or by an operator deleting the table.

IF THIS DAEMON DIES
  Nothing it did is undone by its death. The nftables RULES stay installed.
  The kernel track chain still re-arms any source that keeps sending traffic,
  so those addresses stay authorized until they go silent for longer than
  grace. New sources cannot knock. The gated port therefore stays closed to
  everyone new, while live sessions persist. Do not rely on this binary to
  notice. The supervisor must tear the gate down instead:

    ExecStopPost=/usr/local/sbin/winn-spa-nft revert

  systemd runs ExecStopPost on crash, OOM-kill and SIGKILL alike, so daemon
  death removes the gate and the node returns to its pre-SPA behaviour. The
  shipped unit in deploy/spa/ does this, plus an independent watchdog timer in
  case ExecStopPost itself fails.

RECOVERY WITHOUT A WORKING KNOCK
  The revert never requires a knock, this daemon, or a key:

    nft delete table inet winn_spa

  That is atomic and total. Because the table is dedicated to SPA, it cannot
  affect any other rule -- including SSH, which this change never gates.

OPTIONS
`)
	flag.PrintDefaults()
	fmt.Fprint(out, `
SEE ALSO
  docs/SPA_DESIGN.md            the wire format, threat model and rationale
  deploy/spa/winn-spa-nft       ruleset install / revert / status / seed
  internal/knock                the verifier this daemon reuses unchanged
`)
}

// validateSPALimits refuses non-positive anti-abuse knobs. knock.NewGate treats
// every <=0 value as "use the Gate default", and those defaults (burst 4,
// 6/minute, 100000 sources) are the fail-closed in-process numbers, not this
// daemon's CGNAT-sized DefaultLimits. Passing -rate-burst 0 therefore used to
// start successfully while silently installing the tighter bound — a lockout
// of a shared egress with no log line naming the substitution.
func validateSPALimits(limits spagate.Limits) error {
	if limits.RateBurst <= 0 {
		return fmt.Errorf("-rate-burst must be positive, got %d", limits.RateBurst)
	}
	if limits.RatePerMinute <= 0 {
		return fmt.Errorf("-rate-per-minute must be positive, got %g", limits.RatePerMinute)
	}
	if limits.MaxSources <= 0 {
		return fmt.Errorf("-rate-max-sources must be positive, got %d", limits.MaxSources)
	}
	if limits.MaxAuthorized <= 0 {
		return fmt.Errorf("-max-authorized-sources must be positive, got %d", limits.MaxAuthorized)
	}
	if limits.MaxReplayNonces <= 0 {
		return fmt.Errorf("-max-replay-nonces must be positive, got %d", limits.MaxReplayNonces)
	}
	return nil
}

func exitError(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	if !strings.HasSuffix(message, "\n") {
		message += "\n"
	}
	fmt.Fprint(os.Stderr, "winn-knockd: "+message)
	os.Exit(1)
}
