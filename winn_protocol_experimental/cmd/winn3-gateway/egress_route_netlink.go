package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"syscall"
)

// The rtnetlink RTM_GETROUTE request and reply, encoded and decoded without
// a socket so both halves are tested on every platform. The Linux measurement
// (egress_mtu_linux.go) sends the request over NETLINK_ROUTE; this is the
// question `ip route get <dst> [from <src>] ipproto udp sport <port>` asks,
// and the kernel answers it through the full policy-rule walk (fib_lookup),
// not the main table alone. Values are from <linux/netlink.h> and
// <linux/rtnetlink.h>; egress_mtu_linux_test.go holds them equal to
// golang.org/x/sys/unix.
const (
	nlmsgHdrLen  = 16
	rtMsgLen     = 12
	rtAttrHdrLen = 4

	nlmsgError  = 2
	rtmNewRoute = 24
	rtmGetRoute = 26
	nlmFRequest = 0x1

	// rtmFLookupTable asks the kernel to report the table the rule walk
	// chose in RTA_TABLE; without it the reply names the main table for
	// every lookup (measured on 6.8). Reporting only.
	rtmFLookupTable = 0x1000

	afInet     = 2
	ipprotoUDP = 17

	rtaDst       = 1
	rtaSrc       = 2
	rtaOIF       = 4
	rtaMetrics   = 8
	rtaCacheInfo = 12
	rtaTable     = 15
	rtaMark      = 16
	rtaIPProto   = 27
	rtaSport     = 28
	rtaDport     = 29

	rtaxMTU = 2

	// nlaTypeMask strips NLA_F_NESTED and NLA_F_NET_BYTEORDER.
	nlaTypeMask = 0x3fff
	// rtaCacheInfoExpiresOffset is rta_expires inside struct rta_cacheinfo
	// (rta_clntref, rta_lastuse, rta_expires, ...).
	rtaCacheInfoExpiresOffset = 8
)

func nlAlign(n int) int { return (n + 3) &^ 3 }

func appendRtAttr(b []byte, typ uint16, value []byte) []byte {
	var hdr [rtAttrHdrLen]byte
	binary.NativeEndian.PutUint16(hdr[0:2], uint16(rtAttrHdrLen+len(value)))
	binary.NativeEndian.PutUint16(hdr[2:4], typ)
	b = append(b, hdr[:]...)
	b = append(b, value...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// encodeRouteGetRequest builds one RTM_GETROUTE request describing the reply
// flow the kernel will route: an IPv4 UDP datagram from the listener
// (lookup: bound source, source port, mark) to dst (the client's address
// and, when known, its port: RTA_DPORT). Every selector a policy rule can
// match on that datagram is carried (from, to, ipproto, sport, dport, fwmark);
// uidrange is matched against the requesting process's own uid, which the
// kernel applies when the request carries no RTA_UID, and that is the
// listener's. A destination port of 0 means "unknown" (the startup probes)
// and sends no RTA_DPORT. Round CM3 Turn 2 (Sol): RTA_DPORT was missing.
// The socket asks for strict checking (egress_mtu_linux.go), so a kernel
// that does not know an attribute refuses the request instead of ignoring it.
func encodeRouteGetRequest(seq uint32, dstAP netip.AddrPort, lookup egressLookup) ([]byte, error) {
	dst := dstAP.Addr()
	if !dst.Is4() {
		return nil, fmt.Errorf("route lookup destination %s is not IPv4", dst)
	}
	b := make([]byte, nlmsgHdrLen+rtMsgLen, 128)
	binary.NativeEndian.PutUint16(b[4:6], rtmGetRoute)
	binary.NativeEndian.PutUint16(b[6:8], nlmFRequest)
	binary.NativeEndian.PutUint32(b[8:12], seq)
	rt := b[nlmsgHdrLen:]
	rt[0] = afInet // rtm_family
	rt[1] = 32     // rtm_dst_len
	binary.NativeEndian.PutUint32(rt[8:12], rtmFLookupTable)
	d := dst.As4()
	b = appendRtAttr(b, rtaDst, d[:])
	if lookup.Source.IsValid() {
		if !lookup.Source.Is4() {
			return nil, fmt.Errorf("route lookup source %s is not IPv4", lookup.Source)
		}
		b[nlmsgHdrLen+2] = 32 // rtm_src_len
		s := lookup.Source.As4()
		b = appendRtAttr(b, rtaSrc, s[:])
	}
	b = appendRtAttr(b, rtaIPProto, []byte{ipprotoUDP})
	if lookup.Port != 0 {
		var port [2]byte
		binary.BigEndian.PutUint16(port[:], lookup.Port)
		b = appendRtAttr(b, rtaSport, port[:])
	}
	if dstAP.Port() != 0 {
		var port [2]byte
		binary.BigEndian.PutUint16(port[:], dstAP.Port())
		b = appendRtAttr(b, rtaDport, port[:])
	}
	if lookup.Mark != 0 {
		var mark [4]byte
		binary.NativeEndian.PutUint32(mark[:], lookup.Mark)
		b = appendRtAttr(b, rtaMark, mark[:])
	}
	binary.NativeEndian.PutUint32(b[0:4], uint32(len(b)))
	return b, nil
}

// EVERY ANSWER IS HELD TO ITS REQUEST (Round CM3 Turn 5, GPT-6 Sol OI-CM3-1;
// lane L80). The parsers below never read a partial or foreign answer as a
// complete one. Each message of a datagram must carry the request's sequence
// number and the requesting socket's port id; a message flagged
// NLM_F_DUMP_INTR (the kernel's "this dump may be missing objects", on any
// message including NLMSG_DONE), NLMSG_OVERRUN, an NLMSG_ERROR inside a dump,
// an NLMSG_DONE carrying an error, a message type the request cannot produce,
// and any malformed length or attribute are all errNetlinkIncomplete. The
// receive side (egress_mtu_linux.go) adds MSG_TRUNC, a sender that is not the
// kernel, and no complete answer within netlinkAnswerBound. An incomplete
// answer is retried on a fresh socket (netlinkAttempts in all), then fails
// CLOSED: startup refuses, the per-client guard refuses or closes, and the
// sweep treats routing as unaccountable (egress_netlink_answer.go).
const (
	nlmsgOverrun = 4
	nlmFDumpIntr = 0x10

	rtmNewLink   = 16
	rtmGetLink   = 18
	ifInfomsgLen = 16
	iflaIfname   = 3
	iflaMTU      = 4

	// minDeviceMTU is IPv4's minimum (RFC 791, 68). A link answer below it is
	// not a device the kernel routes IPv4 through.
	minDeviceMTU = 68
)

// errRouteReplyMalformed is one kind of incomplete answer.
var errRouteReplyMalformed = fmt.Errorf("%w: malformed rtnetlink message", errNetlinkIncomplete)

// nlMessage is one message of a datagram, already held to its request.
type nlMessage struct {
	typ   uint16
	flags uint16
	body  []byte
}

// splitAnswer splits one datagram from the kernel into its messages. Every
// message must answer request seq on socket port; a sequence number or port
// id that does not match, an interrupted dump, an overrun and a malformed
// length are incomplete answers, never skipped.
func splitAnswer(b []byte, seq, port uint32) ([]nlMessage, error) {
	if len(b) == 0 {
		return nil, incompleteAnswer("an empty datagram")
	}
	var out []nlMessage
	for len(b) > 0 {
		if len(b) < nlmsgHdrLen {
			return nil, fmt.Errorf("%w: %d bytes left, less than a message header", errRouteReplyMalformed, len(b))
		}
		msgLen := int(binary.NativeEndian.Uint32(b[0:4]))
		if msgLen < nlmsgHdrLen || msgLen > len(b) {
			return nil, fmt.Errorf("%w: message length %d in %d bytes", errRouteReplyMalformed, msgLen, len(b))
		}
		m := nlMessage{
			typ:   binary.NativeEndian.Uint16(b[4:6]),
			flags: binary.NativeEndian.Uint16(b[6:8]),
			body:  b[nlmsgHdrLen:msgLen],
		}
		if s := binary.NativeEndian.Uint32(b[8:12]); s != seq {
			return nil, incompleteAnswer("a message for sequence %d while waiting for %d", s, seq)
		}
		if p := binary.NativeEndian.Uint32(b[12:16]); p != port {
			return nil, incompleteAnswer("a message for port id %d on port id %d", p, port)
		}
		if m.flags&nlmFDumpIntr != 0 {
			return nil, incompleteAnswer("NLM_F_DUMP_INTR: the dump was interrupted and may be missing objects")
		}
		if m.typ == nlmsgOverrun {
			return nil, incompleteAnswer("NLMSG_OVERRUN")
		}
		out = append(out, m)
		b = b[min(nlAlign(msgLen), len(b)):]
	}
	return out, nil
}

// nlErrno reads the int error at the start of an NLMSG_ERROR or NLMSG_DONE
// payload. The kernel sends 0 or a negative errno; anything else is malformed.
func nlErrno(body []byte) (int32, error) {
	if len(body) < 4 {
		return 0, fmt.Errorf("%w: a %d-byte error payload", errRouteReplyMalformed, len(body))
	}
	code := int32(binary.NativeEndian.Uint32(body[0:4]))
	if code > 0 {
		return 0, fmt.Errorf("%w: error code %d is not a negative errno", errRouteReplyMalformed, code)
	}
	return code, nil
}

// walkAttrs visits every attribute of a message, strictly: a truncated
// header, a length outside the remaining bytes, and trailing bytes that are
// not a whole attribute are malformed, never the end of the list. A lenient
// walk could stop before an fwmark attribute and read the rule as clean.
func walkAttrs(attrs []byte, visit func(typ uint16, v []byte) error) error {
	for len(attrs) > 0 {
		if len(attrs) < rtAttrHdrLen {
			return fmt.Errorf("%w: %d trailing attribute bytes", errRouteReplyMalformed, len(attrs))
		}
		l := int(binary.NativeEndian.Uint16(attrs[0:2]))
		typ := binary.NativeEndian.Uint16(attrs[2:4]) & nlaTypeMask
		if l < rtAttrHdrLen || l > len(attrs) {
			return fmt.Errorf("%w: attribute %d of length %d in %d bytes", errRouteReplyMalformed, typ, l, len(attrs))
		}
		if err := visit(typ, attrs[rtAttrHdrLen:l]); err != nil {
			return err
		}
		attrs = attrs[min(nlAlign(l), len(attrs)):]
	}
	return nil
}

func attrValueU32(typ uint16, v []byte) (uint32, error) {
	if len(v) < 4 {
		return 0, fmt.Errorf("%w: attribute %d has %d bytes, want 4", errRouteReplyMalformed, typ, len(v))
	}
	return binary.NativeEndian.Uint32(v[0:4]), nil
}

// routeReply is the part of an RTM_NEWROUTE answer the egress check uses.
type routeReply struct {
	OIF      int
	Table    int
	RouteMTU int   // RTAX_MTU from RTA_METRICS; 0 when absent
	Expires  int32 // rta_expires; nonzero when RouteMTU is a cached PMTU exception
}

// parseRouteReply reads the kernel's answer to one RTM_GETROUTE request: one
// datagram holding either the RTM_NEWROUTE or an NLMSG_ERROR. A kernel errno
// (ENETUNREACH for no route, EINVAL for a request strict checking refused, a
// source this host does not own, or a blackhole) is returned as that errno
// and is a complete answer. Everything else that is not one well-formed
// RTM_NEWROUTE for this request and socket is incomplete.
func parseRouteReply(b []byte, seq, port uint32) (routeReply, error) {
	msgs, err := splitAnswer(b, seq, port)
	if err != nil {
		return routeReply{}, err
	}
	if len(msgs) != 1 {
		return routeReply{}, incompleteAnswer("%d messages in a route answer, want 1", len(msgs))
	}
	m := msgs[0]
	switch m.typ {
	case nlmsgError:
		code, err := nlErrno(m.body)
		if err != nil {
			return routeReply{}, err
		}
		if code == 0 {
			return routeReply{}, incompleteAnswer("the kernel acknowledged the lookup without a route")
		}
		return routeReply{}, fmt.Errorf("kernel route lookup: %w", syscall.Errno(-code))
	case rtmNewRoute:
		return parseNewRoute(m.body)
	}
	return routeReply{}, incompleteAnswer("message type %d in a route answer", m.typ)
}

func parseNewRoute(body []byte) (routeReply, error) {
	if len(body) < rtMsgLen || body[0] != afInet {
		return routeReply{}, errRouteReplyMalformed
	}
	r := routeReply{Table: int(body[4])}
	err := walkAttrs(body[rtMsgLen:], func(typ uint16, v []byte) error {
		var err error
		var x uint32
		switch typ {
		case rtaOIF:
			x, err = attrValueU32(typ, v)
			r.OIF = int(x)
		case rtaTable:
			x, err = attrValueU32(typ, v)
			r.Table = int(x)
		case rtaMetrics:
			r.RouteMTU, err = parseMetricsMTU(v)
		case rtaCacheInfo:
			if len(v) >= rtaCacheInfoExpiresOffset+4 {
				r.Expires = int32(binary.NativeEndian.Uint32(v[rtaCacheInfoExpiresOffset:]))
			}
		}
		return err
	})
	if err != nil {
		return routeReply{}, err
	}
	if r.OIF <= 0 {
		return routeReply{}, incompleteAnswer("the kernel's route answer names no output device")
	}
	return r, nil
}

func parseMetricsMTU(nested []byte) (int, error) {
	mtu := 0
	err := walkAttrs(nested, func(typ uint16, v []byte) error {
		if typ != rtaxMTU {
			return nil
		}
		x, err := attrValueU32(typ, v)
		mtu = int(x)
		return err
	})
	return mtu, err
}

// encodeLinkGetRequest asks for one device by index (RTM_GETLINK without
// NLM_F_DUMP): its name and MTU in one answer, on the same strict socket as
// the route lookup. It replaces net.InterfaceByIndex, which dumps every link
// through the standard library's parser, which does not check NLM_F_DUMP_INTR.
func encodeLinkGetRequest(seq uint32, index int) []byte {
	b := make([]byte, nlmsgHdrLen+ifInfomsgLen)
	binary.NativeEndian.PutUint32(b[0:4], uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:6], rtmGetLink)
	binary.NativeEndian.PutUint16(b[6:8], nlmFRequest)
	binary.NativeEndian.PutUint32(b[8:12], seq)
	binary.NativeEndian.PutUint32(b[nlmsgHdrLen+4:nlmsgHdrLen+8], uint32(index))
	return b
}

// parseLinkReply reads the answer to encodeLinkGetRequest. The device must be
// the one asked for and must name itself and its MTU. Any error, including the
// kernel's ENODEV for a device that vanished after the route answer named it,
// is incomplete: the route answer it belongs to is stale, so the pair is
// asked again.
func parseLinkReply(b []byte, seq, port uint32, index int) (string, int, error) {
	msgs, err := splitAnswer(b, seq, port)
	if err != nil {
		return "", 0, err
	}
	if len(msgs) != 1 {
		return "", 0, incompleteAnswer("%d messages in a link answer, want 1", len(msgs))
	}
	m := msgs[0]
	switch m.typ {
	case nlmsgError:
		code, err := nlErrno(m.body)
		if err != nil {
			return "", 0, err
		}
		if code == 0 {
			return "", 0, incompleteAnswer("the kernel acknowledged the link request without a link")
		}
		return "", 0, fmt.Errorf("%w: link %d: %w", errNetlinkIncomplete, index, syscall.Errno(-code))
	case rtmNewLink:
	default:
		return "", 0, incompleteAnswer("message type %d in a link answer", m.typ)
	}
	if len(m.body) < ifInfomsgLen {
		return "", 0, errRouteReplyMalformed
	}
	if got := int(int32(binary.NativeEndian.Uint32(m.body[4:8]))); got != index {
		return "", 0, incompleteAnswer("link answer for index %d, asked for %d", got, index)
	}
	name, mtu := "", 0
	err = walkAttrs(m.body[ifInfomsgLen:], func(typ uint16, v []byte) error {
		switch typ {
		case iflaIfname:
			if i := bytes.IndexByte(v, 0); i >= 0 {
				v = v[:i]
			}
			name = string(v)
		case iflaMTU:
			x, err := attrValueU32(typ, v)
			mtu = int(x)
			return err
		}
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	if name == "" || mtu < minDeviceMTU {
		return "", 0, incompleteAnswer("link %d answered with name %q and mtu %d", index, name, mtu)
	}
	return name, mtu, nil
}

// egressFromReply turns a reply into the MTU the kernel applies. A route
// mtu metric lowers the device MTU; a PMTU exception (nonzero expiry) is the
// path beyond this host and is recorded without lowering it.
func egressFromReply(dst netip.Addr, r routeReply, device string, deviceMTU int) egressRoute {
	e := egressRoute{Dest: dst, Device: device, DeviceMTU: deviceMTU, MTU: deviceMTU, Table: r.Table}
	switch {
	case r.RouteMTU > 0 && r.Expires != 0:
		e.PMTUException = r.RouteMTU
	case r.RouteMTU > 0:
		e.RouteMTU = r.RouteMTU
		if r.RouteMTU < e.MTU {
			e.MTU = r.RouteMTU
		}
	}
	return e
}

// Policy rules and routes the per-client lookup cannot account for (Round CM3
// Turn 4, GPT-6 Sol OI-CM3-1; lane L80). The lookup asks about the reply as
// the socket emits it: unmarked (or the listener's own SO_MARK) and TOS 0.
// A netfilter OUTPUT hook (iptables mangle MARK/CONNMARK/TOS, an nft route
// chain setting meta mark) can change the mark or the TOS after that, and the
// kernel then routes the packet again (ip_route_me_harder). That second
// lookup can pick another route only through something that SELECTS on the
// mark or the TOS: an `ip rule` with an fwmark selector, an `ip rule` with a
// tos/dsfield selector, or a route with a TOS key. Measured on 6.8
// (lane_l80/vm/cm3t5_reroute_premises.txt): MARK without an fwmark rule, and
// an fwmark or tos rule without a marker, change nothing; each pair moves the
// reply. The gateway cannot see netfilter's rules from its sandbox, so any
// such rule or route makes the reply route unaccountable.
//
// Round CM3 Turn 6: the rule check is an ALLOWLIST. A rule attribute is
// accepted only when the kernel's own rule walk evaluates it the same way for
// the gateway's RTM_GETROUTE and for the real reply, so a rewrite of the mark
// or the TOS cannot change its outcome: the addresses, the ports and their
// masks, the protocol, the uid, iif/oif (measured in Turn 5), and the
// attributes that are actions or bookkeeping (table, priority, goto, realms,
// suppress_*, protocol, padding). Every other attribute makes the rule
// unaccountable: fwmark and its mask, and also FRA_DSCP and FRA_DSCP_MASK
// (the `ip rule dscp` selector newer kernels send instead of the tos header
// field), FRA_TUN_ID, FRA_L3MDEV (a reroute takes its VRF from the first
// route's device, not from anything the lookup describes), and any attribute
// this code does not know.
const (
	rtmNewRule    = 32
	rtmGetRule    = 34
	nlmsgDone     = 3
	nlmFDump      = 0x300
	fibRuleHdrLen = 12
	fibRuleInvert = 0x2

	fraDst               = 1
	fraSrc               = 2
	fraIifname           = 3
	fraGoto              = 4
	fraPriority          = 6
	fraFwmark            = 10
	fraFlow              = 11
	fraTunID             = 12
	fraSuppressIfgroup   = 13
	fraSuppressPrefixlen = 14
	fraTable             = 15
	fraFwmask            = 16
	fraOifname           = 17
	fraPad               = 18
	fraL3mdev            = 19
	fraUIDRange          = 20
	fraProtocol          = 21
	fraIPProto           = 22
	fraSportRange        = 23
	fraDportRange        = 24
	fraDSCP              = 25
	fraSportMask         = 28
	fraDportMask         = 29
	fraDSCPMask          = 30
)

// ruleAttrAccountable is the allowlist above.
func ruleAttrAccountable(typ uint16) bool {
	switch typ {
	case fraDst, fraSrc, fraIifname, fraGoto, fraPriority, fraFlow, fraSuppressIfgroup, fraSuppressPrefixlen,
		fraTable, fraOifname, fraPad, fraUIDRange, fraProtocol, fraIPProto, fraSportRange, fraDportRange,
		fraSportMask, fraDportMask:
		return true
	}
	return false
}

func ruleAttrName(typ uint16) string {
	switch typ {
	case fraTunID:
		return "tun_id"
	case fraL3mdev:
		return "l3mdev"
	case fraDSCP:
		return "dscp"
	case fraDSCPMask:
		return "dscp mask"
	}
	return fmt.Sprintf("attribute %d", typ)
}

// routingSelector is one rule or route that selects on a reply attribute the
// lookup cannot see.
type routingSelector struct {
	Kind     string // "fwmark rule", "tos rule", "rule", "tos route"
	Priority int
	Table    int
	Tos      int
	Mark     uint32
	Mask     uint32
	HasMask  bool
	Invert   bool
	Attrs    []uint16     // attributes outside the allowlist other than fwmark/fwmask
	Dst      netip.Prefix // a tos route's destination; invalid when not known
}

func (r routingSelector) String() string {
	extra := ""
	for _, a := range r.Attrs {
		extra += " " + ruleAttrName(a)
	}
	switch r.Kind {
	case "fwmark rule":
		not := ""
		if r.Invert {
			not = "not "
		}
		mask := ""
		if r.HasMask {
			mask = fmt.Sprintf("/%#x", r.Mask)
		}
		return fmt.Sprintf("rule pref %d %sfwmark %#x%s%s lookup %d", r.Priority, not, r.Mark, mask, extra, r.Table)
	case "tos rule":
		return fmt.Sprintf("rule pref %d tos %#x%s lookup %d", r.Priority, r.Tos, extra, r.Table)
	case "rule":
		return fmt.Sprintf("rule pref %d selects on%s lookup %d", r.Priority, extra, r.Table)
	default:
		if r.Dst.IsValid() {
			return fmt.Sprintf("route %s in table %d keyed on tos %#x", r.Dst, r.Table, r.Tos)
		}
		return fmt.Sprintf("route in table %d keyed on tos %#x", r.Table, r.Tos)
	}
}

// encodeDumpRequest builds an RTM_GETRULE or RTM_GETROUTE dump request for
// IPv4 with a zeroed family header (what strict checking requires).
func encodeDumpRequest(typ uint16, seq uint32) []byte {
	hdr := rtMsgLen
	if typ == rtmGetRule {
		hdr = fibRuleHdrLen
	}
	b := make([]byte, nlmsgHdrLen+hdr)
	binary.NativeEndian.PutUint32(b[0:4], uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:6], typ)
	binary.NativeEndian.PutUint16(b[6:8], nlmFRequest|nlmFDump)
	binary.NativeEndian.PutUint32(b[8:12], seq)
	b[nlmsgHdrLen] = afInet
	return b
}

// parseSelectorDump reads one datagram of a dump for request seq on socket
// port, whose objects are of type want (RTM_NEWRULE or RTM_NEWROUTE). It
// returns the selectors found and done when NLMSG_DONE (with no error, and
// last in its datagram) arrived. An NLMSG_ERROR inside a dump, an NLMSG_DONE
// carrying an error, an object of another type or family, and everything
// splitAnswer rejects are incomplete: a dump that is not known to be whole
// never reads as clean.
func parseSelectorDump(b []byte, seq, port uint32, want uint16) ([]routingSelector, bool, error) {
	msgs, err := splitAnswer(b, seq, port)
	if err != nil {
		return nil, false, err
	}
	var out []routingSelector
	for i, m := range msgs {
		switch m.typ {
		case nlmsgDone:
			if len(m.body) > 0 {
				code, err := nlErrno(m.body)
				if err != nil {
					return nil, false, err
				}
				if code != 0 {
					return nil, false, fmt.Errorf("%w: the dump ended with %w", errNetlinkIncomplete, syscall.Errno(-code))
				}
			}
			if i != len(msgs)-1 {
				return nil, false, incompleteAnswer("%d messages after NLMSG_DONE", len(msgs)-1-i)
			}
			return out, true, nil
		case nlmsgError:
			code, err := nlErrno(m.body)
			if err != nil {
				return nil, false, err
			}
			if code == 0 {
				return nil, false, incompleteAnswer("an acknowledgement inside a dump")
			}
			return nil, false, fmt.Errorf("%w: kernel dump error %w", errNetlinkIncomplete, syscall.Errno(-code))
		case want:
		default:
			return nil, false, incompleteAnswer("message type %d in a dump of type %d", m.typ, want)
		}
		var s routingSelector
		var ok bool
		if want == rtmNewRule {
			s, ok, err = parseRuleSelector(m.body)
		} else {
			s, ok, err = parseRouteSelector(m.body)
		}
		if err != nil {
			return nil, false, err
		}
		if ok {
			out = append(out, s)
		}
	}
	return out, false, nil
}

func parseRuleSelector(body []byte) (routingSelector, bool, error) {
	if len(body) < fibRuleHdrLen {
		return routingSelector{}, false, errRouteReplyMalformed
	}
	if body[0] != afInet {
		return routingSelector{}, false, incompleteAnswer("a family %d rule in an IPv4 rule dump", body[0])
	}
	s := routingSelector{Table: int(body[4]), Tos: int(body[3]),
		Invert: binary.NativeEndian.Uint32(body[8:12])&fibRuleInvert != 0}
	var hasMark, hasMask bool
	err := walkAttrs(body[fibRuleHdrLen:], func(typ uint16, v []byte) error {
		var err error
		var x uint32
		switch typ {
		case fraTable:
			x, err = attrValueU32(typ, v)
			s.Table = int(x)
		case fraPriority:
			x, err = attrValueU32(typ, v)
			s.Priority = int(x)
		case fraFwmark:
			s.Mark, err = attrValueU32(typ, v)
			hasMark = true
		case fraFwmask:
			s.Mask, err = attrValueU32(typ, v)
			hasMask = true
		default:
			if !ruleAttrAccountable(typ) {
				s.Attrs = append(s.Attrs, typ)
			}
		}
		return err
	})
	if err != nil {
		return routingSelector{}, false, err
	}
	switch {
	case hasMark || hasMask:
		s.Kind, s.HasMask = "fwmark rule", hasMask
		return s, true, nil
	case s.Tos != 0:
		s.Kind = "tos rule"
		return s, true, nil
	case len(s.Attrs) > 0:
		s.Kind = "rule"
		return s, true, nil
	}
	return routingSelector{}, false, nil
}

func parseRouteSelector(body []byte) (routingSelector, bool, error) {
	if len(body) < rtMsgLen {
		return routingSelector{}, false, errRouteReplyMalformed
	}
	if body[0] != afInet {
		return routingSelector{}, false, incompleteAnswer("a family %d route in an IPv4 route dump", body[0])
	}
	table := int(body[4])
	var dst [4]byte
	err := walkAttrs(body[rtMsgLen:], func(typ uint16, v []byte) error {
		switch typ {
		case rtaTable:
			x, err := attrValueU32(typ, v)
			table = int(x)
			return err
		case rtaDst:
			if len(v) != 4 {
				return fmt.Errorf("%w: RTA_DST of %d bytes", errRouteReplyMalformed, len(v))
			}
			copy(dst[:], v)
		}
		return nil
	})
	if err != nil {
		return routingSelector{}, false, err
	}
	if body[3] == 0 {
		return routingSelector{}, false, nil
	}
	s := routingSelector{Kind: "tos route", Table: table, Tos: int(body[3])}
	if body[1] <= 32 {
		s.Dst = netip.PrefixFrom(netip.AddrFrom4(dst), int(body[1]))
	}
	return s, true, nil
}
