package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/driver"
)

// defaultProbeTarget is the ICMP echo destination when -dns is unset.
// DNS mode does not send ICMP; a non-default -target beside -dns is an
// inert operator statement and is refused rather than ignored.
const defaultProbeTarget = "1.1.1.1"

// handshakeWait is how long run() waits for StateCarrying. It is NOT
// -budget: -budget starts after the last probe is queued. A mismatch here
// is how an operator can believe -budget=2s failed fast when the process
// sat on the handshake for 40s.
const handshakeWait = 40 * time.Second

// dnsUDPSrcPortBase is the first inner UDP source port DNS mode uses.
// Each query increments it so a stale reply cannot share a 4-tuple with
// a later query. The value is uint16; -count must not wrap it.
const dnsUDPSrcPortBase = 40000

// icmpSeqMax is the largest -count ICMP mode can send without wrapping
// the 16-bit sequence number (seq is i+1, so count 65535 → seq 65535).
const icmpSeqMax = 65535

// icmpNoReplyFix / dnsNoReplyFix are the got==0 strings. After the unit
// started passing -accept-transit=true, "needs -forward and -accept-transit"
// alone pointed at a pair that was already set; the remaining causes are
// -inner outside -forward-cidr and a target that is not the public internet.
const icmpNoReplyFix = "no reply: for ICMP the gateway needs -forward and -accept-transit=true AND a working host FORWARD/NAT path; -inner must be a host inside that gateway's -forward-cidr and not equal to its -inner-v4; -target must be a public address the gateway can reach (the gateway's own inner address or a loopback target does not prove internet transit)"

const dnsNoReplyFix = "no reply: for -dns the gateway needs -resolver, and -dns-server must be that gateway's -inner-v4 (not the client's -inner, and not a different subnet the resolver does not bind)"

const reflectNoReplyFix = "no reply: for -reflect-to the gateway must be a local winn3-gateway reflector (not -forward); -reflect-to must be that process's -inner-v4, and -inner a different host address, not equal to -reflect-to"

// canaryRekeyAfterDefault is the volume trigger -canary installs when
// -rekey-after is left at 0. core.RekeyAfterMessages is 1<<28, which a
// loopback canary cannot reach. 32 is above the post-quantum chunk count at
// the fleet path MTU so the handshake itself does not fire the ratchet, and
// low enough that a few dozen inner packets will.
const canaryRekeyAfterDefault uint64 = 32

// probeOptions is the flag surface of cmd/winn3-probe. Defaults live in
// defineProbeFlags so a test can Parse(nil) and read them off the struct
// rather than trusting a comment.
type probeOptions struct {
	gw, dir, gatewayID, inner, target, dnsName, dnsServer, reflectTo string
	dualEDPub, dualMLPub                                    string
	pathMTU, count                                                   int
	interval, budget                                                 time.Duration
	canary                                                           bool
	rekeyAfter                                                       uint64
}

// probeParsed is the subset of probeOptions that survived validateProbeFlags.
// File reads (-dir) happen after this, so a bad flag combination never
// touches the filesystem or dials.
type probeParsed struct {
	gwAddr           *net.UDPAddr
	srcAddr, dstAddr netip.Addr
	dnsAddr          netip.Addr
	reflectAddr      netip.Addr
	dnsMode          bool
	canary           bool
	rekeyAfter       uint64
	sizing           driver.Sizing
}

func defineProbeFlags(fs *flag.FlagSet) *probeOptions {
	o := &probeOptions{}
	fs.StringVar(&o.gw, "gw", "", "gateway UDP address, e.g. 127.0.0.1:51833")
	fs.StringVar(&o.dir, "dir", "",
		"key directory produced by winn3-gateway -mode keygen (client.key, static.pub, admission.key)")
	fs.StringVar(&o.gatewayID, "gateway-id", "", "the authenticated gateway identifier")
	fs.StringVar(&o.inner, "inner", "", "this client's inner IPv4 address")
	fs.StringVar(&o.target, "target", defaultProbeTarget, "public IPv4 to echo-request through the gateway (ICMP mode only; unused and refused when -dns is set to a non-default value)")
	fs.StringVar(&o.dnsName, "dns", "",
		"if set, send DNS A queries for this name INSTEAD of ICMP echo requests. Used to prove\n"+
			"    \tcmd/winn3-gateway's -resolver answers across the v3 datapath rather than on the\n"+
			"    \tgateway host's own loopback -- the query is built as an inner UDP datagram and\n"+
			"    \thanded to the session, so it can only arrive by being carried. Requires -dns-server.")
	fs.StringVar(&o.dnsServer, "dns-server", "",
		"inner IPv4 the -dns query is addressed to. This is the gateway's own -inner-v4: the\n"+
			"    \tresolver answers only there, because winn3/tun's outbound rule refuses to carry a\n"+
			"    \treply sourced from any other address (ErrSourceNotOurs). Required with -dns;\n"+
			"    \trefused without -dns, because the value would otherwise be ignored.")
	fs.StringVar(&o.reflectTo, "reflect-to", "",
		"gateway inner IPv4 for a local reflector canary. cmd/winn3-gateway without -forward\n"+
			"    \tswaps addresses and returns the same L4 bytes; that is NOT an ICMP echo reply, so\n"+
			"    \t-target 1.1.1.1 against a local gateway is a guaranteed miss. Required by -canary.")
	fs.StringVar(&o.dualEDPub, "dual-ed-pub", "",
		"gateway ed25519 attestation public key (hex, 32 bytes); pairs with -dual-ml-pub to require the dual-signature attestation")
	fs.StringVar(&o.dualMLPub, "dual-ml-pub", "",
		"gateway ML-DSA-65 attestation public key (hex, 1952 bytes); pairs with -dual-ed-pub to require the dual-signature attestation")
	fs.BoolVar(&o.canary, "canary", false,
		"local carrier handshake canary: wait for StateCarrying, prove a captured initiation\n"+
			"    \treplayed from a second UDP source stays silent, send inner packets to -reflect-to,\n"+
			"    \tand wait for a volume rekey. Requires -reflect-to. Refused with -dns.")
	fs.Uint64Var(&o.rekeyAfter, "rekey-after", 0,
		"session.Config.RekeyAfterMessages for -canary. 0 with -canary means 32. Refused without -canary,\n"+
			"    \tbecause a production ICMP/DNS probe must not silently change the rekey schedule.")
	fs.IntVar(&o.pathMTU, "path-mtu", carrier.DefaultPathMTU, "planning path MTU; must match the gateway")
	fs.IntVar(&o.count, "count", 4, "echo requests, DNS queries, or reflector packets to send")
	fs.DurationVar(&o.interval, "interval", time.Second, "gap between echo requests")
	fs.DurationVar(&o.budget, "budget", 45*time.Second, "how long to wait for a reply after the last request (not the handshake wait)")
	return o
}

// validateProbeFlags refuses combinations that cannot work, before any key
// file is read and before DialUDP. Every error names the flag to change.
//
// This is the same class of defect as winn3-gateway's -forward requiring
// -accept-transit=true: a required companion that is easy to omit, and a
// message that does not name the companion costs a debugging cycle under a
// protocol that answers unauthenticated datagrams with silence.
func validateProbeFlags(o probeOptions) (probeParsed, error) {
	if empty := requiredProbeFlagEmpties(o); len(empty) > 0 {
		verb := "is"
		if len(empty) != 1 {
			verb = "are"
		}
		return probeParsed{}, fmt.Errorf(
			"%s %s empty; -gw, -dir, -gateway-id and -inner are all required",
			strings.Join(empty, ", "), verb)
	}
	if trimmed := strings.TrimSpace(o.gatewayID); trimmed != o.gatewayID {
		if trimmed == "" {
			return probeParsed{}, fmt.Errorf(
				"-gateway-id is only whitespace: %s. Pass a non-empty identifier with no leading or trailing whitespace; an empty -gateway-id is also refused",
				probeEdgeWhitespaceReport(o.gatewayID))
		}
		return probeParsed{}, fmt.Errorf(
			"-gateway-id carries whitespace at its edges: %s. winn3-gateway refuses that spelling "+
				"and every host that reads the id as transport text trims it, so this client would "+
				"compute a different admission tag and the gateway would answer with silence. "+
				"Pass -gateway-id %q",
			probeEdgeWhitespaceReport(o.gatewayID), trimmed)
	}
	if len(o.gatewayID) > 255 {
		return probeParsed{}, fmt.Errorf(
			"-gateway-id is %d bytes, more than 255; shorten it", len(o.gatewayID))
	}
	if o.count < 1 {
		return probeParsed{}, fmt.Errorf("-count %d must be at least 1", o.count)
	}
	if o.count > icmpSeqMax {
		return probeParsed{}, fmt.Errorf(
			"-count %d exceeds %d; ICMP sequence and DNS transaction-id are uint16 and would wrap, so two probes would share an id and a stale reply could be counted as a fresh one",
			o.count, icmpSeqMax)
	}
	if o.interval < 0 {
		return probeParsed{}, fmt.Errorf("-interval %s must not be negative", o.interval)
	}
	if o.budget <= 0 {
		return probeParsed{}, fmt.Errorf("-budget %s must be positive; this is the post-send wait, not the handshake", o.budget)
	}

	srcAddr, err := netip.ParseAddr(o.inner)
	if err != nil {
		return probeParsed{}, fmt.Errorf("-inner: %w", err)
	}
	if !srcAddr.Is4() {
		return probeParsed{}, fmt.Errorf("-inner %s must be IPv4; icmpEcho/udpDNS call As4 and this probe has no inner IPv6 path", srcAddr)
	}
	if err := refuseUnusableIPv4("-inner", srcAddr); err != nil {
		return probeParsed{}, err
	}

	if o.rekeyAfter > 0 && !o.canary {
		return probeParsed{}, errors.New(
			"-rekey-after is set but -canary is not; the value would change the rekey schedule of an ICMP or DNS probe. Set -canary, or unset -rekey-after")
	}
	if o.canary && o.reflectTo == "" {
		return probeParsed{}, errors.New(
			"-canary needs -reflect-to: the local winn3-gateway reflector answers at its own -inner-v4, and -target 1.1.1.1 is not an ICMP echo reply from a reflector")
	}
	if o.reflectTo != "" && !o.canary {
		return probeParsed{}, errors.New(
			"-reflect-to is set but -canary is not; the value would be ignored. Set -canary, or unset -reflect-to")
	}

	dnsMode := o.dnsName != ""
	if !dnsMode && o.dnsServer != "" {
		return probeParsed{}, errors.New(
			"-dns-server is set but -dns is not; the value would be ignored. Set -dns, or unset -dns-server")
	}
	if dnsMode && o.canary {
		return probeParsed{}, errors.New(
			"-dns is set with -canary; DNS mode is a resolver proof and -canary is a local reflector handshake. Unset -dns, or omit -canary")
	}

	var dstAddr, dnsAddr, reflectAddr netip.Addr
	if dnsMode {
		if o.dnsServer == "" {
			return probeParsed{}, errors.New(
				"-dns needs -dns-server: the resolver answers only at the gateway's own -inner-v4")
		}
		if o.target != "" && o.target != defaultProbeTarget {
			return probeParsed{}, fmt.Errorf(
				"-target %s is set but -dns is set; ICMP is not sent in DNS mode so -target would be ignored. Unset -target, or omit -dns",
				o.target)
		}
		dnsAddr, err = netip.ParseAddr(o.dnsServer)
		if err != nil {
			return probeParsed{}, fmt.Errorf("-dns-server: %w", err)
		}
		if !dnsAddr.Is4() {
			return probeParsed{}, errors.New("-dns-server must be IPv4")
		}
		if err := refuseUnusableIPv4("-dns-server", dnsAddr); err != nil {
			return probeParsed{}, err
		}
		if srcAddr == dnsAddr {
			return probeParsed{}, fmt.Errorf(
				"-inner %s equals -dns-server; -dns-server is the gateway's -inner-v4, so this client needs a different address in the same subnet",
				srcAddr)
		}
		if _, err := dnsQueryWire(1, o.dnsName); err != nil {
			return probeParsed{}, fmt.Errorf("-dns: %w", err)
		}
		dnsPortSpan := int(^uint16(0)) - dnsUDPSrcPortBase + 1
		if o.count > dnsPortSpan {
			return probeParsed{}, fmt.Errorf(
				"-count %d would wrap the DNS source port (base %d, uint16 max 65535); lower -count",
				o.count, dnsUDPSrcPortBase)
		}
	} else if o.canary {
		if o.target != "" && o.target != defaultProbeTarget {
			return probeParsed{}, fmt.Errorf(
				"-target %s is set but -canary is set; ICMP internet echo is not sent in canary mode so -target would be ignored. Unset -target, or omit -canary",
				o.target)
		}
		reflectAddr, err = netip.ParseAddr(o.reflectTo)
		if err != nil {
			return probeParsed{}, fmt.Errorf("-reflect-to: %w", err)
		}
		if !reflectAddr.Is4() {
			return probeParsed{}, fmt.Errorf("-reflect-to %s must be IPv4; icmpEcho calls As4 and this probe has no inner IPv6 path", reflectAddr)
		}
		if err := refuseUnusableIPv4("-reflect-to", reflectAddr); err != nil {
			return probeParsed{}, err
		}
		if srcAddr == reflectAddr {
			return probeParsed{}, fmt.Errorf(
				"-inner %s equals -reflect-to; -reflect-to is the gateway's -inner-v4, so this client needs a different address",
				srcAddr)
		}
		dstAddr = reflectAddr
	} else {
		dstAddr, err = netip.ParseAddr(o.target)
		if err != nil {
			return probeParsed{}, fmt.Errorf("-target: %w", err)
		}
		if !dstAddr.Is4() {
			return probeParsed{}, fmt.Errorf("-target %s must be IPv4; icmpEcho calls As4 and would panic", dstAddr)
		}
		if err := refuseUnusableIPv4("-target", dstAddr); err != nil {
			return probeParsed{}, fmt.Errorf(
				"%w; ICMP to a loopback/unspecified/multicast/link-local/reserved address through the gateway does not prove internet transit (it can even echo the gateway host's own loopback and look like a pass)",
				err)
		}
		if srcAddr == dstAddr {
			return probeParsed{}, fmt.Errorf(
				"-target %s equals -inner; winn3/tun refuses a packet addressed to this endpoint's own inner address as a martian, so this probe would queue ICMP that is dropped before the gateway and then report no reply as if -forward were missing. Pick a destination that is not this client",
				dstAddr)
		}
	}

	gwAddr, err := net.ResolveUDPAddr("udp4", o.gw)
	if err != nil {
		return probeParsed{}, fmt.Errorf("-gw: %w (need host:port, IPv4, e.g. 127.0.0.1:51833)", err)
	}
	if gwAddr.Port == 0 {
		return probeParsed{}, errors.New("-gw port is 0; DialUDP refuses a zero port. Pass a non-zero UDP port")
	}
	if gwAddr.IP == nil || gwAddr.IP.IsUnspecified() {
		return probeParsed{}, fmt.Errorf(
			"-gw %s has no usable IPv4 host (resolved IP is empty or unspecified). Pass host:port, e.g. 127.0.0.1:51833",
			o.gw)
	}

	sizing, err := driver.NewSizing(o.pathMTU, carrier.ClassUDP)
	if err != nil {
		return probeParsed{}, fmt.Errorf("-path-mtu %d: %w", o.pathMTU, err)
	}

	rekeyAfter := o.rekeyAfter
	if o.canary && rekeyAfter == 0 {
		rekeyAfter = canaryRekeyAfterDefault
	}

	return probeParsed{
		gwAddr:      gwAddr,
		srcAddr:     srcAddr,
		dstAddr:     dstAddr,
		dnsAddr:     dnsAddr,
		reflectAddr: reflectAddr,
		dnsMode:     dnsMode,
		canary:      o.canary,
		rekeyAfter:  rekeyAfter,
		sizing:      sizing,
	}, nil
}

// requiredProbeFlagEmpties names which of the four always-required flags are
// empty. The combined "all required" string used to fire for any one of them,
// so an operator who had set three still had to re-read the fourth by eye.
func requiredProbeFlagEmpties(o probeOptions) []string {
	var empty []string
	if o.gw == "" {
		empty = append(empty, "-gw")
	}
	if o.dir == "" {
		empty = append(empty, "-dir")
	}
	if o.gatewayID == "" {
		empty = append(empty, "-gateway-id")
	}
	if o.inner == "" {
		empty = append(empty, "-inner")
	}
	return empty
}

// noReplyError is the got==0 path. A single string that always blamed
// -forward/-accept-transit (ICMP) or -resolver (DNS) is how a self-addressed
// -target, a send that never queued, or a sub-second -budget all cost a
// debugging cycle pointed at the gateway unit. The gateway companions stay
// the message for the case that is actually those companions.
func noReplyError(dnsMode, reflectMode bool, sent, txDroppedInvalid int, budget time.Duration) error {
	if sent == 0 {
		return errors.New(
			"no packet was queued on the in-memory device; this is not a gateway -forward or -resolver failure")
	}
	if txDroppedInvalid > 0 {
		return fmt.Errorf(
			"no reply: the tunnel dropped %d outbound packet(s) as invalid (tx_dropped_invalid) before they reached the gateway; this is not a missing -forward/-accept-transit. Check -inner versus -target (tun refuses a destination equal to this client's inner) and that -path-mtu matches",
			txDroppedInvalid)
	}
	if budget < time.Second {
		return fmt.Errorf(
			"no reply: -budget %s is much shorter than the default 45s; this wait starts after the last send and is not the handshake. Raise -budget before blaming the gateway's -forward/-accept-transit or -resolver",
			budget)
	}
	if reflectMode {
		return errors.New(reflectNoReplyFix)
	}
	if dnsMode {
		return errors.New(dnsNoReplyFix)
	}
	return errors.New(icmpNoReplyFix)
}

// unexpectedSessionEnd is the path where loop.Run returned before the
// probe cancelled it. Discarding that error used to fall through to
// noReplyError, which blamed -forward/-resolver for a session that had
// already died.
func unexpectedSessionEnd(runErr error) error {
	if runErr == nil {
		return errors.New(
			"the winn/3 session returned without a reply and without an error; this is not a missing gateway -forward/-accept-transit or -resolver")
	}
	return fmt.Errorf(
		"the winn/3 session ended without a reply; this is not a missing gateway -forward/-accept-transit or -resolver: %w",
		runErr)
}

// unmatchedNoReplyError is got==0 with inner packets that were not a
// matching ICMP echo reply or DNS response. Counting those as a pass
// was a false green: an ICMP destination-unreachable or a stray packet
// would print VERDICT success.
func unmatchedNoReplyError(unmatched int, dnsMode, reflectMode bool, sent, txDroppedInvalid int, budget time.Duration) error {
	return fmt.Errorf(
		"received %d inner packet(s) that were not a matching ICMP echo reply, DNS response, or reflector swap; not counting them as a pass: %w",
		unmatched, noReplyError(dnsMode, reflectMode, sent, txDroppedInvalid, budget))
}

// refuseExtraProbeArgs is the leftover-argv check flag.Parse does not do.
// A hostname or a gateway flag typed without a dash used to be ignored, so the
// process ran a different probe than the operator typed.
func refuseExtraProbeArgs(fs *flag.FlagSet) error {
	if fs.NArg() == 0 {
		return nil
	}
	return fmt.Errorf(
		"unexpected positional argument(s) %q; winn3-probe takes flags only (see -h). -accept-transit, -forward and -resolver are winn3-gateway flags, not this client",
		fs.Args())
}

// refuseUnusableIPv4 is the probe-side copy of the martian rules winn3/tun
// applies to an assignment. tun.Assignment.validate is unexported, and calling
// tun.New just to learn the address is illegal would dial nothing and still
// need a Device. A loopback -inner used to survive flag parsing, DialUDP, and
// then fail inside NewClient with a message that did not name -inner.
func refuseUnusableIPv4(flagName string, a netip.Addr) error {
	switch {
	case a.IsUnspecified():
		return fmt.Errorf("%s %s is unusable: unspecified", flagName, a)
	case a.IsLoopback():
		return fmt.Errorf("%s %s is unusable: loopback", flagName, a)
	case a.IsMulticast():
		return fmt.Errorf("%s %s is unusable: multicast", flagName, a)
	case a.IsLinkLocalUnicast():
		return fmt.Errorf("%s %s is unusable: link-local unicast", flagName, a)
	}
	b := a.As4()
	switch {
	case b[0] == 0:
		return fmt.Errorf("%s %s is unusable: reserved leading zero block", flagName, a)
	case b[0] >= 240:
		return fmt.Errorf("%s %s is unusable: reserved high block or limited broadcast", flagName, a)
	}
	return nil
}

// probeEdgeWhitespaceReport is the probe-side copy of winn3-gateway's
// edgeWhitespaceReport: a value whose whitespace is invisible in a terminal
// must have its bytes spelled out, or the operator cannot see what to delete.
func probeEdgeWhitespaceReport(s string) string {
	noLead := strings.TrimLeftFunc(s, unicode.IsSpace)
	lead := s[:len(s)-len(noLead)]
	noTrail := strings.TrimRightFunc(noLead, unicode.IsSpace)
	trail := noLead[len(noTrail):]

	var b strings.Builder
	fmt.Fprintf(&b, "%q (hex %x)", s, s)
	for _, part := range []struct {
		where string
		runes string
	}{{"leading", lead}, {"trailing", trail}} {
		if part.runes == "" {
			continue
		}
		fmt.Fprintf(&b, ", %d %s whitespace byte(s)", len(part.runes), part.where)
		if n := utf8.RuneCountInString(part.runes); n != len(part.runes) {
			fmt.Fprintf(&b, " in %d code point(s)", n)
		}
		b.WriteString(":")
		for _, r := range part.runes {
			fmt.Fprintf(&b, " %+q (%U)", r, r)
		}
	}
	return b.String()
}
