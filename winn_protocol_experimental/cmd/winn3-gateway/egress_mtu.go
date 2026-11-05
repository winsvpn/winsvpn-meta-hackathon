package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"syscall"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/driver"
)

// The listener's datagram ceiling against the device that carries it out.
//
// WHY THIS EXISTS (Round CM, 2026-09-26). us-chicago1's provider NIC is 1400
// bytes and the fleet plan was -path-mtu 1450, so every full-size datagram was
// 1402 + 28 = 1430 bytes on IPv4. The listener had no DF, the kernel split
// each one into two fragments, the fragments died on the way to the phone, and
// the ML-DSA-65 attestation chunks (always full size) never arrived. Nothing
// on the gateway counted a failure: send_failed stayed 0 and the client timed
// out 23.5 s later with the bare dual-auth sentinel.
//
// Two changes address it:
//
//   - At startup, before the socket exists, checkEgressMTU refuses a plan
//     whose widest IPv4 datagram is wider than the device the kernel routes
//     the listener's UDP through (see WHICH DEVICE below). This is the
//     part that closes Chicago's outage class, and it runs on every start
//     whatever -listener-df says.
//   - With -listener-df (WINN3_GATEWAY_LISTENER_DF=1) the listener sets
//     IP_PMTUDISC_DO (carrier.EnableDontFragment), so an oversized datagram
//     fails its send with EMSGSIZE, which the session loop already counts
//     (send_refused on every refusal, send_failed when it abandons the
//     message), instead of leaving as fragments nobody measures.
//
// DF IS OFF BY DEFAULT (Round CM2, OI-CM2-1a). The client carrier sets DF only
// on Linux and Android (winn3/carrier/pmtud_other.go); iOS, macOS and Windows
// clients send without it and can complete sessions today on a path narrower
// than this node's NIC wherever fragments are delivered. DF on the shared
// listener would drop every full-size download datagram to such a client at
// the narrow hop, and nothing negotiates or lowers the path MTU per client.
// Turning DF on is a separate decision, taken after measuring how often real
// client paths need fragmentation.
//
// WHICH DEVICE (Round CM2 retro, GPT-6 Sol OI-CM2-1a; lane L80). CM2 read the
// lowest-metric default route of the main table from /proc/net/route. With
// policy routing that is not the listener's egress: a rule matching the
// listener's source address, UDP, its port or the service uid sends the
// replies through another table, so a 1400-byte main default could refuse a
// plan whose replies leave through a 1500-byte device, and the reverse could
// pass a plan that fragments. measureEgressRoute (egress_mtu_linux.go) now
// asks the kernel the `ip route get` question for this listener's own flow
// (RTM_GETROUTE: its bound address, UDP, its port, the process's uid) to a
// few representative destinations, and the device and route MTU in the answer
// are what is compared. A cached path MTU for one destination is the path
// beyond this host, not the egress, and is logged, never compared. Not seen by
// the lookup: an fwmark set later by an OUTPUT rule (iptables/nft) and a
// reroute on it; the fleet had none on 2026-09-26.
//
// REFUSE, NOT WARN, when the numbers are measured and disagree. The mismatch
// is certain, it breaks every session that sends a full-size message, and the
// operator is at the terminal when the service starts. The owner's standing
// rule is to fail closed on a known defect. Every destination probed must
// leave through a device too narrow for the refusal; destinations that
// disagree (some routes wide enough, some not) are a warning naming them,
// since the lookup cannot establish which one clients' replies follow. WARN,
// NOT REFUSE, when the device cannot be measured (no route in a lab
// namespace, a platform without rtnetlink): refusing on the absence of a
// number would make the gateway unrunnable in exactly the places that cannot
// reach Chicago's failure, and DF still turns any residual oversize into a
// counted send error.
//
// THE RULE IS THE PHYSICAL ONE. The datagram this listener emits is
// sizing.MessageSize plus the IPv4 and UDP headers, and it must fit the
// device. The installer (wins_winn3_gateway_install.sh,
// check_gateway_egress_mtu) applies the same rule at install time with the
// same lookup (`ip route get`), plus the plan floor as a separate check. It
// used to hold path MTU <= device MTU, which refused legal plans: a TLS plan
// at 1450 emits 1366-byte datagrams, which fit a 1400-byte device (Sol,
// OI-CM2-2).

// runServe calls these through variables so a test can prove both are wired
// in without a host whose NIC is narrower than the plan, and can read the real
// listener's socket option back.
var (
	measureEgress       = measureEgressRoute
	enableListenerDF    = enableListenerDontFragment
	configureListenerDF = configureListenerDontFragment
)

// listenerDFEnv is -listener-df's environment variable.
const listenerDFEnv = "WINN3_GATEWAY_LISTENER_DF"

// resolveListenerDF maps -listener-df and WINN3_GATEWAY_LISTENER_DF the way
// runServe maps -demux and WINN3_GATEWAY_DEMUX: the environment is read when
// the flag holds its default. The accepted values are the installer's own
// boolean values, 0 and 1, plus unset. Anything else is refused whatever the
// flag says, so a mistyped value never reads as a decision.
func resolveListenerDF(flagOn bool, env string) (bool, error) {
	switch env {
	case "", "0":
		return flagOn, nil
	case "1":
		return true, nil
	default:
		return false, fmt.Errorf("%s=%q must be 0, 1 or unset", listenerDFEnv, env)
	}
}

// egressRoute is the kernel's answer for one representative destination:
// the device a datagram from this listener to Dest leaves through, and the
// MTU the kernel applies to it.
type egressRoute struct {
	Dest      netip.Addr
	DestPort  uint16 // the client's port for a per-client lookup; 0 for a probe
	Device    string
	MTU       int // what the kernel applies: DeviceMTU, or RouteMTU when that is lower
	DeviceMTU int
	RouteMTU  int // the route's own mtu metric; 0 when the route has none
	Table     int
	// PMTUException is a cached path MTU the kernel learned for Dest (the
	// reply carried a nonzero expiry). It describes the path beyond this
	// host, not the egress device, and is logged but never compared.
	PMTUException int
	Err           error
}

// egressProbeDestinations stand in for client addresses. The listener
// replies to whoever sent to it, so no single address is "the" client; these
// are anycast resolvers that every fleet node routes like the rest of the
// internet (L80, 2026-09-26: on all eight nodes `ip route get` for each of
// them from the listener's port returned the main-table default). A test
// replaces them to probe its own namespace.
var egressProbeDestinations = []netip.Addr{
	netip.AddrFrom4([4]byte{1, 1, 1, 1}),
	netip.AddrFrom4([4]byte{8, 8, 8, 8}),
	netip.AddrFrom4([4]byte{9, 9, 9, 9}),
	netip.AddrFrom4([4]byte{208, 67, 222, 222}),
}

// egressLookup is the listener's half of the reply flow the kernel is asked
// about: its own bound address (unspecified for 0.0.0.0, so the kernel picks
// the source the way it will for the listener's replies), its port, its
// fwmark (SO_MARK; 0, sent as nothing, unless something set one), UDP, and
// the calling process's uid, which the kernel supplies itself when the
// request carries no RTA_UID. The other half is the destination: the client's
// address and port (a probe has port 0). Together they are every selector an
// IPv4 policy rule can match on a reply from this socket: from, to, ipproto,
// sport, dport, fwmark, uidrange. (tos and iif do not apply: the listener sets
// no TOS and a locally generated reply has no input interface.) One flow
// description, used by the startup probes, the per-client guard and, in the
// installer, `ip route get`.
type egressLookup struct {
	Source netip.Addr // invalid means unspecified
	Port   uint16     // 0 means no RTA_SPORT
	Mark   uint32     // 0 means no RTA_MARK
}

// errFlowNotDescribable means the kernel could not be asked about the exact
// reply flow: strict request checking is unavailable, or the kernel refused
// an attribute of the request. The per-client guard fails CLOSED on it, and
// startup refuses (Round CM3 Turn 2).
var errFlowNotDescribable = errors.New("the kernel cannot be asked about the exact reply flow")

func egressLookupFor(listen *net.UDPAddr) egressLookup {
	var l egressLookup
	if listen == nil {
		return l
	}
	if ip4 := listen.IP.To4(); ip4 != nil && !ip4.IsUnspecified() {
		l.Source = netip.AddrFrom4([4]byte(ip4))
	}
	if listen.Port > 0 && listen.Port <= 0xffff {
		l.Port = uint16(listen.Port)
	}
	return l
}

func (l egressLookup) String() string {
	src := "0.0.0.0"
	if l.Source.IsValid() {
		src = l.Source.String()
	}
	if l.Mark != 0 {
		return fmt.Sprintf("udp from %s:%d mark %#x", src, l.Port, l.Mark)
	}
	return fmt.Sprintf("udp from %s:%d", src, l.Port)
}

// plannedIPv4Datagram is the widest datagram this listener emits: the plan's
// message ceiling plus 20 bytes of IPv4 and 8 of UDP. The listener is udp4
// (runServe binds "udp4"), so IPv4 is the family that goes on the wire.
func plannedIPv4Datagram(sizing driver.Sizing) int {
	return sizing.MessageSize + carrier.Overhead(carrier.ClassUDP, carrier.FamilyIPv4)
}

func describeEgress(routes []egressRoute) string {
	parts := make([]string, 0, len(routes))
	for _, r := range routes {
		dest := r.Dest.String()
		if r.DestPort != 0 {
			dest = netip.AddrPortFrom(r.Dest, r.DestPort).String()
		}
		s := fmt.Sprintf("%s via %s mtu %d", dest, r.Device, r.MTU)
		if r.RouteMTU > 0 {
			s += fmt.Sprintf(" (route mtu %d, device %d)", r.RouteMTU, r.DeviceMTU)
		}
		if r.Table > 0 {
			s += fmt.Sprintf(" table %d", r.Table)
		}
		if r.PMTUException > 0 {
			s += fmt.Sprintf(" [cached path mtu %d to this destination, not compared]", r.PMTUException)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, "; ")
}

// checkEgressMTU compares the plan against what the kernel's route lookup
// says about this listener's UDP (Round CM2 retro, L80). It returns an error
// only when every destination it measured leaves through a device narrower
// than the plan's widest datagram. Nothing measured is a warning; some
// destinations narrower and some wide enough is a warning naming them, since
// the lookup cannot establish which one the clients' replies follow.
func checkEgressMTU(sizing driver.Sizing, lookup egressLookup, routes []egressRoute, measureErr error, logw io.Writer) error {
	datagram := plannedIPv4Datagram(sizing)
	if errors.Is(measureErr, errFlowNotDescribable) {
		// Every client would be refused by the per-client guard (it fails
		// closed on the same condition), so say so now, while the operator
		// is here, instead of starting a gateway that serves nobody.
		return fmt.Errorf("egress MTU check: %v. The per-client egress guard fails closed on this, so "+
			"this gateway would refuse every client; it needs Linux 4.20 or later "+
			"(NETLINK_GET_STRICT_CHK) to route-check replies by port", measureErr)
	}
	if measureErr != nil {
		if platformUnsupported(measureErr) {
			fmt.Fprintf(logw, "winn3-gateway: egress MTU check not available on this platform; "+
				"the plan's widest datagram is %d bytes\n", datagram)
			return nil
		}
		fmt.Fprintf(logw, "winn3-gateway: WARNING: egress MTU NOT CHECKED (%v). "+
			"The plan's widest IPv4 datagram is %d bytes (-path-mtu %d). If the device "+
			"that carries it is narrower, every full-size send fails with EMSGSIZE and "+
			"sessions that need a full-size message (the dual-auth attestation always "+
			"does) cannot complete.\n", measureErr, datagram, sizing.PathMTU)
		return nil
	}
	var measured []egressRoute
	var unmeasured []string
	for _, r := range routes {
		if errors.Is(r.Err, errNetlinkIncomplete) {
			// Round CM3 Turn 6: an answer that is not known to be complete,
			// after every retry, is not "unmeasured": fail closed.
			return fmt.Errorf("egress MTU check: the kernel's answer for %s was incomplete (%v); the egress "+
				"cannot be accounted for", r.Dest, r.Err)
		}
		switch {
		case r.Err != nil:
			unmeasured = append(unmeasured, fmt.Sprintf("%s: %v", r.Dest, r.Err))
		case r.MTU <= 0:
			unmeasured = append(unmeasured, fmt.Sprintf("%s: device %q reports MTU %d", r.Dest, r.Device, r.MTU))
		default:
			measured = append(measured, r)
		}
	}
	if len(measured) == 0 {
		if len(unmeasured) == 0 {
			unmeasured = append(unmeasured, "no destination probed")
		}
		fmt.Fprintf(logw, "winn3-gateway: WARNING: egress MTU NOT CHECKED (%s: %s). "+
			"The plan's widest IPv4 datagram is %d bytes (-path-mtu %d).\n",
			lookup, strings.Join(unmeasured, "; "), datagram, sizing.PathMTU)
		return nil
	}
	widest, narrowest := measured[0], measured[0]
	for _, r := range measured[1:] {
		if r.MTU > widest.MTU {
			widest = r
		}
		if r.MTU < narrowest.MTU {
			narrowest = r
		}
	}
	if len(unmeasured) > 0 {
		fmt.Fprintf(logw, "winn3-gateway: WARNING: egress lookup failed for some destinations (%s)\n",
			strings.Join(unmeasured, "; "))
	}
	if datagram > widest.MTU {
		advice := fmt.Sprintf("Set -path-mtu (WINN3_GATEWAY_PATH_MTU) and the hub's "+
			"nodes.path_mtu for this node to the same value, at most %d and at least "+
			"this plan's floor %d; the two ends must change together",
			widest.MTU+sizing.PathMTU-datagram, sizing.MinPathMTUForInnerIPv6)
		if widest.MTU+sizing.PathMTU-datagram < sizing.MinPathMTUForInnerIPv6 {
			advice = fmt.Sprintf("No path MTU this plan accepts (floor %d) fits the "+
				"device: raise the device MTU or fix the route", sizing.MinPathMTUForInnerIPv6)
		}
		return fmt.Errorf(
			"-path-mtu %d plans %d-byte IPv4 datagrams (message %d + 28), but the kernel "+
				"routes this listener's %s through %s with MTU %d at the widest (%s). "+
				"With DF set every full-size send would fail; without it the kernel "+
				"fragments them and the fragments are lost (Round CM, us-chicago1). %s",
			sizing.PathMTU, datagram, sizing.MessageSize, lookup, widest.Device, widest.MTU,
			describeEgress(measured), advice)
	}
	if datagram > narrowest.MTU {
		fmt.Fprintf(logw, "winn3-gateway: WARNING: egress MTU AMBIGUOUS: the plan's widest IPv4 "+
			"datagram is %d bytes (-path-mtu %d); the kernel routes this listener's %s through "+
			"devices that disagree (%s). Datagrams that leave through %s (mtu %d) will be "+
			"fragmented. Not refused: the lookup cannot establish which route the clients' "+
			"replies follow.\n", datagram, sizing.PathMTU, lookup, describeEgress(measured),
			narrowest.Device, narrowest.MTU)
		return nil
	}
	fmt.Fprintf(logw, "winn3-gateway: egress MTU ok: widest IPv4 datagram %d <= %s mtu %d (%s: %s)\n",
		datagram, narrowest.Device, narrowest.MTU, lookup, describeEgress(measured))
	return nil
}

// PER CLIENT (Round CM3, GPT-6 Sol OI-CM3-1; lane L80). The startup check
// asks about four representative destinations, so it cannot see a route to
// one client's prefix: a 1500-byte default and a 1400-byte route to
// 45.0.0.0/16 pass it, and every reply to a client in 45.0.0.0/16 leaves
// fragmented. No static check is exact for a gateway that answers arbitrary
// addresses, and routes change while it runs. So before a client's first
// session is built (and before a token-demux session is rebound to a new
// address) the gateway asks the kernel the same question for THAT address,
// with the listener's source, port, mark and uid and the client's port (Round
// CM3 Turn 2: a `dport` rule is matched on the reply's destination port, so
// the lookup without RTA_DPORT measured another route). A measured route
// narrower than
// the plan's widest datagram refuses the session in silence toward the peer,
// counted (egress_mtu_refused) and logged without the address: the same
// local-fragmentation class Round CM refuses at startup. A lookup the kernel
// REFUSED (strict checking unavailable, EINVAL, EOPNOTSUPP) fails CLOSED:
// the flow could not be described, and answering it with a less specific
// lookup is exactly the defect Sol found. So does an answer that is not
// known to be complete after its retries (Round CM3 Turn 6,
// egress_netlink_answer.go), and any other failure. Only the kernel's
// complete answer that there is no route at all (unreachable, prohibit) is
// served, as at startup: such a reply cannot leave fragmented. Another
// platform is served. A
// cached PMTU exception is not compared here either: it is learned from ICMP,
// which an off-path sender can forge to deny a victim address.
//
// The lookup runs only for a datagram that has passed the admission screen
// (or matched a live session's token), so an unauthenticated sender cannot
// make the gateway issue netlink requests.

// detectRoutingSelectors is a variable so a test can stand in for the
// kernel's rule and route dump (listRoutingSelectors).
var detectRoutingSelectors = listRoutingSelectors

// checkRoutingAccountable refuses startup when the host has a policy rule or
// route that selects on the fwmark or the TOS (see routingSelector): the
// replies' route could then be changed by a netfilter mark or TOS rewrite the
// gateway cannot see, and no lookup it makes would show it (Round CM3 Turn 4,
// GPT-6 Sol OI-CM3-1). A dump the kernel refuses, or one that is not known to
// be complete after its retries (Round CM3 Turn 6), also refuses; another
// platform is skipped.
func checkRoutingAccountable(logw io.Writer) error {
	sel, err := detectRoutingSelectors()
	switch {
	case platformUnsupported(err):
		return nil
	case err != nil:
		return fmt.Errorf("egress check: cannot list the policy rules and routes (%v); the replies' route "+
			"cannot be accounted for", err)
	case len(sel) > 0:
		return fmt.Errorf("egress check: policy routing selects on the packet mark or TOS (%s). A netfilter "+
			"OUTPUT mark or TOS rewrite, which this gateway cannot see, could then move its replies to "+
			"another route after every check; remove those rules or routes, or serve from a host without them",
			describeSelectors(sel))
	}
	fmt.Fprintln(logw, "winn3-gateway: egress routing accountable: no policy rule or route selects on mark or TOS")
	return nil
}

func describeSelectors(sel []routingSelector) string {
	parts := make([]string, 0, len(sel))
	for _, s := range sel {
		parts = append(parts, s.String())
	}
	return strings.Join(parts, "; ")
}

// measureClientEgress is a variable so a test can stand in for the kernel.
var measureClientEgress = func(lookup egressLookup, dst netip.AddrPort) egressRoute {
	routes, err := measureEgressRouteTo(lookup, []netip.AddrPort{dst})
	if err != nil {
		return egressRoute{Dest: dst.Addr(), DestPort: dst.Port(), Err: err}
	}
	if len(routes) != 1 {
		return egressRoute{Dest: dst.Addr(), DestPort: dst.Port(),
			Err: fmt.Errorf("route lookup for %s returned %d answers", dst, len(routes))}
	}
	return routes[0]
}

// lookupSaysNoRoute reports whether err is the kernel's complete answer that
// there is no route for the reply at all (unreachable, or prohibit), or a
// platform without rtnetlink. Such a reply cannot leave fragmented, so the
// client is served, as at startup. Every other error fails closed: a lookup
// the kernel refused (strict checking unavailable, EINVAL for an attribute
// it does not accept, EOPNOTSUPP, a blackhole) and, Round CM3 Turn 6, an
// answer that is not known to be complete, even one that carries a no-route
// errno of its own.
func lookupSaysNoRoute(err error) bool {
	if errors.Is(err, errNetlinkIncomplete) || errors.Is(err, errFlowNotDescribable) {
		return false
	}
	return errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.EACCES) || platformUnsupported(err)
}

// platformUnsupported reports the other-platform stubs' errors.ErrUnsupported
// (egress_mtu_other.go: no rtnetlink here) and nothing else. A kernel errno
// ENOSYS, ENOTSUP or EOPNOTSUPP also matches errors.ErrUnsupported
// (syscall.Errno.Is), and a kernel that answers one of them has rtnetlink:
// read as "another platform", an EOPNOTSUPP inside a rule dump would have let
// startup serve (Round CM3 Turn 6, found by its own test).
func platformUnsupported(err error) bool {
	var errno syscall.Errno
	return errors.Is(err, errors.ErrUnsupported) && !errors.As(err, &errno)
}

// clientEgressGuard holds what the per-client check needs: the listener's
// flow and the plan's widest IPv4 datagram.
type clientEgressGuard struct {
	lookup   egressLookup
	datagram int
}

// check reports the route the kernel would use for replies to dst (address
// AND port) and whether the plan's widest datagram fits it. Only a complete
// "no route" answer is served without a measured MTU (lookupSaysNoRoute);
// a refused, incomplete or otherwise failed lookup does not fit (Round CM3
// Turn 6: it used to be served as "unmeasured").
func (g *clientEgressGuard) check(dst netip.AddrPort) (egressRoute, bool) {
	r := measureClientEgress(g.lookup, netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port()))
	if r.Err != nil {
		return r, lookupSaysNoRoute(r.Err)
	}
	if r.MTU <= 0 {
		return r, false
	}
	return r, g.datagram <= r.MTU
}

// configureListenerDontFragment applies -listener-df to the shared listener
// and logs exactly one line with the resulting DF state. Off leaves the socket
// untouched: the kernel's default IP_MTU_DISCOVER, fragmentation allowed.
func configureListenerDontFragment(conn *net.UDPConn, on bool, logw io.Writer) error {
	if !on {
		fmt.Fprintln(logw, "winn3-gateway: listener DF off (-listener-df not set): kernel default, "+
			"datagrams wider than the path may leave as fragments")
		return nil
	}
	return enableListenerDF(conn, logw)
}

// enableListenerDontFragment sets DF on the shared listener. Linux and
// Android fail closed if the kernel refuses; elsewhere the platform keeps its
// behaviour and a line says so.
func enableListenerDontFragment(conn *net.UDPConn, logw io.Writer) error {
	err := carrier.EnableDontFragment(conn)
	switch {
	case err == nil:
		fmt.Fprintln(logw, "winn3-gateway: listener DF on (IP_PMTUDISC_DO)")
		return nil
	case errors.Is(err, errors.ErrUnsupported):
		fmt.Fprintln(logw, "winn3-gateway: listener DF not available on this platform")
		return nil
	default:
		return fmt.Errorf("set IP_PMTUDISC_DO on the listener: %w", err)
	}
}
