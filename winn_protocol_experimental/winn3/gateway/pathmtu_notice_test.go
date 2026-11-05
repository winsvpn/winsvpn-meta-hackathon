package gateway

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/session"
)

// The responder's half of silent-refusal instance #3, for THIS package.
//
// ===========================================================================
// WHY THESE TESTS DO NOT READ THE CODE
// ===========================================================================
//
// The claim under test is "the shipping gateway emits the path-MTU notice". A
// test that called EncodePathMTUNotice and compared the bytes would prove the
// encoder works, which was never in doubt — the encoder had a green test on
// 2026-08-09 while this package went on passing nil, and that green is exactly
// what let the gap survive an independent review.
//
// So nothing here inspects a payload directly. Every assertion is made from the
// far end of a REAL, UNCONNECTED UDP SOCKET by a REAL session.Driver client that
// authenticated a real handshake: the client either refuses, naming both
// numbers, or it establishes and its transport messages route through the
// gateway's token index. Both outcomes are only reachable if the notice was
// genuinely on the wire, and neither is reachable by reading Config.
//
// The socket is loopback and both ends are in one process, which is honest
// about what is NOT covered: no MTU on the loopback path is exercised, and this
// says nothing about forwarding or egress. What it does cover is the whole
// admission chain — datagram in, Handle, core's tag check, WriteResponse, the
// payload, the client's decode and its refusal decision.

// udpFrontDoor is Gateway behind a real socket: one goroutine, one read loop,
// and the ONLY thing it ever writes is a Result.Reply. Every rejection leaves
// the socket silent, which is the property silence_test.go pins in-process and
// this one inherits.
type udpFrontDoor struct {
	gw   *Gateway
	conn *net.UDPConn
	addr *net.UDPAddr

	transport  atomic.Int64
	handshakes atomic.Int64
	stop       chan struct{}

	// The material a client needs to reach this door: the same admission
	// secret and gateway id the responder was built with, and its public key.
	params core.GatewayParams
	public []byte
}

// newUDPFrontDoor stands a gateway up on 127.0.0.1 with a real static key, a
// real admission secret, and the PRODUCTION binder from Gateway's own doc
// comment — the keyed source derived from the session's receive demux key — so
// that a transport message routes the way it will in production rather than
// through a harvested stand-in.
func newUDPFrontDoor(t *testing.T, pathMTU int) *udpFrontDoor {
	t.Helper()

	gwStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatalf("gateway static key: %v", err)
	}
	admission := make([]byte, core.KeySize)
	for i := range admission {
		admission[i] = byte(0xC0 + i)
	}
	params := core.GatewayParams{
		AdmissionKeys: [][]byte{admission},
		GatewayID:     []byte("winn3-gateway-pathmtu-udp"),
		TagSize:       core.DefaultTagSize,
	}
	resp, err := core.NewResponder(core.Config{Gateway: params}, gwStatic, func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}

	cfg := silentCfg()
	gw, err := New(cfg, pathMTU, resp, func(sess *core.Session) (Opener, TokenSource, error) {
		k, _ := sess.RecvDemuxKey()
		return sess, NewKeyedSource(&k), nil
	})
	if err != nil {
		t.Fatalf("New gateway at PathMTU %d: %v", pathMTU, err)
	}
	t.Cleanup(gw.Table().Close)

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	d := &udpFrontDoor{
		gw:   gw,
		conn: conn,
		addr: conn.LocalAddr().(*net.UDPAddr),
		stop: make(chan struct{}),
	}
	t.Cleanup(func() {
		close(d.stop)
		conn.Close()
	})
	go d.serve()

	// The client needs the same admission material and the same gateway public
	// key; handing them back through the struct keeps the test bodies short.
	d.params = params
	d.public = gwStatic.Public()
	return d
}

func (d *udpFrontDoor) serve() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-d.stop:
			return
		default:
		}
		if err := d.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			return
		}
		n, from, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		msg := append([]byte(nil), buf[:n]...)
		res := d.gw.Handle(msg, []byte(from.String()), time.Now())
		switch res.Kind {
		case KindTransport:
			d.transport.Add(1)
		case KindHandshake:
			d.handshakes.Add(1)
		}
		if res.Reply != nil {
			_, _ = d.conn.WriteToUDP(res.Reply, from)
		}
	}
}

// newClientAt builds a real session.Driver initiator pointed at the front door.
func (d *udpFrontDoor) newClientAt(t *testing.T, pathMTU int) (*session.Driver, *net.UDPConn) {
	t.Helper()

	cliStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatalf("client static key: %v", err)
	}
	gwPub, err := core.NewPublicKey(d.public)
	if err != nil {
		t.Fatalf("gateway public key: %v", err)
	}
	cli, err := session.NewClient(session.Config{
		Core:           core.Config{Gateway: d.params},
		Static:         cliStatic,
		GatewayStatic:  gwPub,
		Padding:        core.PadBucket,
		PathMTU:        pathMTU,
		MaxMessageSize: session.MaxMessageSizeForPath(pathMTU, session.CarrierOverheadUDPIPv6),
	})
	if err != nil {
		t.Fatalf("NewClient at PathMTU %d: %v", pathMTU, err)
	}
	conn, err := net.DialUDP("udp", nil, d.addr)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return cli, conn
}

// pumpOverUDP drives the client against the front door over the real socket
// until it refuses, or until the door has routed one of its transport
// messages, or the budget runs out. It returns the CLIENT's error, because
// "the client refused" is the assertion in one test here and the thing that
// must not happen in the others.
//
// It stops on the first ROUTED TRANSPORT MESSAGE rather than on
// StateEstablished. This front door is a dispatch library and not a session
// driver: it answers the handshake and then routes, but it never sends the
// post-quantum frames the client is waiting on, so a client that has succeeded
// completely still sits in StateInitiating. "The gateway's token index opened a
// message this client sealed" is the strongest statement reachable here, and it
// is a stronger one than the state field anyway — it cannot be true unless both
// ends derived the same keys from the same handshake.
func pumpOverUDP(t *testing.T, door *udpFrontDoor, cli *session.Driver, conn *net.UDPConn) error {
	t.Helper()
	buf := make([]byte, 65535)
	for round := 0; round < 32; round++ {
		for {
			msg, err := cli.Poll()
			if err != nil {
				return err
			}
			if msg == nil {
				break
			}
			if _, err := conn.Write(msg); err != nil {
				t.Fatalf("round %d: writing to the socket: %v", round, err)
			}
		}
		if door.transport.Load() > 0 {
			return nil
		}
		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		n, err := conn.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return nil // nothing more is coming; the caller inspects state
			}
			t.Fatalf("round %d: reading from the socket: %v", round, err)
		}
		if _, err := cli.Deliver(append([]byte(nil), buf[:n]...)); err != nil {
			return err
		}
	}
	return nil
}

// TestTheShippingGatewayEmitsThePathMTUNoticeOverARealSocket is THE GATE.
//
// Until 2026-08-10 winn3/gateway passed nil to WriteResponse and its own
// comment said what that meant: "a client talking to THIS responder gets no
// path-MTU check at all". Raising any client default while that was true would
// have re-created instance #3's fail-open regime on the one path that answers
// real clients.
//
// The proof is the REFUSAL ARRIVING at a client that never saw the gateway's
// Config: a mismatched client must end the session with ErrPathMTUMismatch, and
// the text must name the gateway's number. Nothing but a notice on the wire can
// produce that.
func TestTheShippingGatewayEmitsThePathMTUNoticeOverARealSocket(t *testing.T) {
	const gwMTU, cliMTU = 1450, 1500

	door := newUDPFrontDoor(t, gwMTU)
	cli, conn := door.newClientAt(t, cliMTU)

	err := pumpOverUDP(t, door, cli, conn)
	if err == nil {
		t.Fatalf("a client at %d established against a gateway at %d. The gateway is not "+
			"emitting the notice: this is the fail-open regime, and no client default may "+
			"move until this test is red-for-the-right-reason and then green. (client %s)",
			cliMTU, gwMTU, cli.State())
	}
	if !errors.Is(err, session.ErrPathMTUMismatch) {
		t.Fatalf("the client failed with %v, want ErrPathMTUMismatch", err)
	}

	// Loud, and loud about BOTH ends: an operator reading one number cannot
	// tell which end to change.
	msg := err.Error()
	for _, want := range []string{strconv.Itoa(gwMTU), strconv.Itoa(cliMTU)} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not name %s; it reads: %s", want, msg)
		}
	}
	if !strings.Contains(msg, "responder") || !strings.Contains(msg, "initiator") {
		t.Errorf("the refusal does not name both ends; it reads: %s", msg)
	}

	// The refusal is LOCAL. The gateway authenticated the handshake and counted
	// it, and the client tore down without telling it anything — which is the
	// protocol's habit and is deliberate.
	if got := door.handshakes.Load(); got != 1 {
		t.Errorf("the gateway completed %d handshakes, want 1; the refusal must happen "+
			"AFTER a real authenticated response, not instead of one", got)
	}
	if got := door.transport.Load(); got != 0 {
		t.Errorf("%d transport messages reached the gateway after a refusal; the client "+
			"must send nothing once it has refused", got)
	}
}

// TestAnAgreeingClientStillEstablishesAgainstTheShippingGateway is the
// OVER-FIRE CONTROL, and it is the reason the test above is not sufficient on
// its own: a gateway that refused everything would pass that one.
//
// It runs at the value the fleet default moved to on 2026-08-10 and at the two
// edges of the decision — the first path MTU outside the dead zone, and a
// measured 1500 path.
func TestAnAgreeingClientStillEstablishesAgainstTheShippingGateway(t *testing.T) {
	for _, mtu := range []int{MinPathMTUForInnerIPv6, 1450, 1500} {
		t.Run(strconv.Itoa(mtu), func(t *testing.T) {
			door := newUDPFrontDoor(t, mtu)
			cli, conn := door.newClientAt(t, mtu)

			if err := pumpOverUDP(t, door, cli, conn); err != nil {
				t.Fatalf("two ends agreeing at %d were refused: %v", mtu, err)
			}
			if err := cli.Err(); err != nil {
				t.Fatalf("the client recorded %v on an agreeing pair", err)
			}
			if cli.State() == session.StateFailed {
				t.Fatalf("the client is %s on an agreeing pair", cli.State())
			}
			// The handshake authenticated and the session is REAL: the client's
			// post-handshake traffic routed through the gateway's token index,
			// which cannot happen unless both ends derived the same keys.
			if got := door.handshakes.Load(); got != 1 {
				t.Fatalf("the gateway completed %d handshakes, want 1", got)
			}
			if got := door.transport.Load(); got == 0 {
				t.Fatal("no transport message routed through the table; the session " +
					"is not established at the core level and this control proves nothing")
			}
		})
	}
}

// TestAClientOnA1280BytePathActsOnThe1450GatewaysNotice is the exact pair the
// fleet raise is hung on, and it is the narrow regime instance #3 describes at
// its most dangerous: the client's path is the RFC 8200 floor, 1280, while the
// gateway plans at 1450.
//
// ===========================================================================
// WHY 1280 AND NOT 1500
// ===========================================================================
//
// TestTheShippingGatewayEmitsThePathMTUNoticeOverARealSocket already proves the
// wide of the mismatch (1450 vs 1500). 1280 is a materially different case: it
// is the smallest path a v3 client can be on, and it is the one where the
// fail-OPEN cost is highest. A 1450-planning gateway serving a 1280-path client
// that did NOT check would size its full-size messages at 1402 payload bytes for
// a carrier that cannot carry them, and BOTH ends would report the gate
// carrying while every full-size packet died — the black hole, established and
// loud-looking. The whole point of refusing is that the 1280 client must not
// silently accept the session and die later; it must learn the number and end
// the session loudly instead.
//
// The same gateway must then also serve a 1450 client without a hint of the
// mismatch machinery firing — that is the over-fire half, and it must hold on
// the very same door the refusal just came off, not on a fresh one.
func TestAClientOnA1280BytePathActsOnThe1450GatewaysNoticeWhileA1450ClientIsUnaffected(t *testing.T) {
	const gwMTU, cli1280MTU = 1450, session.IPv6MinimumLinkMTU

	door := newUDPFrontDoor(t, gwMTU)

	// The 1280-path client. It must receive the notice and refuse loudly —
	// BEFORE establishing, so nothing it ever seals routes through the table.
	cli, conn := door.newClientAt(t, cli1280MTU)
	err := pumpOverUDP(t, door, cli, conn)
	if err == nil {
		t.Fatalf("a client on a %d-byte path established against a gateway planning at %d. "+
			"The notice did not reach it, or it failed to act: that session is the black "+
			"hole, established and carrying while full-size packets die. (client %s)",
			cli1280MTU, gwMTU, cli.State())
	}
	if !errors.Is(err, session.ErrPathMTUMismatch) {
		t.Fatalf("the client failed with %v, want ErrPathMTUMismatch", err)
	}

	// Loud, and loud about BOTH ends: an operator holding a 1280-path client and
	// a 1450-planning gateway needs to know which number to change.
	msg := err.Error()
	for _, want := range []string{strconv.Itoa(gwMTU), strconv.Itoa(cli1280MTU)} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not name %s; it reads: %s", want, msg)
		}
	}
	if !strings.Contains(msg, "responder") || !strings.Contains(msg, "initiator") {
		t.Errorf("the refusal does not name both ends; it reads: %s", msg)
	}

	// The refusal came AFTER a real authenticated response from THIS gateway —
	// the notice is only learnable from the wire, and the wire is the socket
	// this test talks over.
	if got := door.handshakes.Load(); got != 1 {
		t.Errorf("after the 1280 refusal the gateway completed %d handshakes, want 1", got)
	}
	if got := door.transport.Load(); got != 0 {
		t.Errorf("%d transport messages reached the gateway after the 1280 refusal; the "+
			"client must send nothing once it has refused", got)
	}

	// The same door, a client already at 1450. The notice must pass through it
	// like a no-op: it agrees, so it establishes and moves a transport message
	// through the gateway's token index. Nothing in the mismatch machinery may
	// fire on an agreeing pair.
	cliAgree, connAgree := door.newClientAt(t, gwMTU)
	if err := pumpOverUDP(t, door, cliAgree, connAgree); err != nil {
		t.Fatalf("a client already at %d was refused by a %d gateway after the 1280 refusal "+
			"had been served: %v", gwMTU, gwMTU, err)
	}
	if err := cliAgree.Err(); err != nil {
		t.Fatalf("the 1450 client recorded %v on a pair that agrees", err)
	}
	if cliAgree.State() == session.StateFailed {
		t.Fatalf("the 1450 client is %s on a pair that agrees", cliAgree.State())
	}
	// Two handshakes total on the door — the 1280 refusal and the 1450 success —
	// and the 1450 client actually moved a transport message, which cannot happen
	// unless the session is real at the core level.
	if got := door.handshakes.Load(); got != 2 {
		t.Errorf("the gateway completed %d handshakes total, want 2 (the 1280 refusal "+
			"plus the 1450 session)", got)
	}
	if got := door.transport.Load(); got == 0 {
		t.Fatal("no transport message routed through the table for the 1450 client; the " +
			"agreement control proves nothing if the session is not established at the core level")
	}
}

// TestTheGatewayRefusesADeadZonePathMTUAtTheDoor.
//
// 1280-1420 is the 141-value dead zone. A gateway is the end every client must
// match, so a gateway serving a dead-zone claim takes every agreeing client
// into the zone with it — a session that resolves, bootstraps, carries and can
// never promote. New must refuse rather than serve it.
func TestTheGatewayRefusesADeadZonePathMTUAtTheDoor(t *testing.T) {
	static, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := core.NewResponder(core.Config{Gateway: core.GatewayParams{
		AdmissionKeys: [][]byte{make([]byte, core.KeySize)},
		GatewayID:     []byte("winn3-gateway-deadzone"),
		TagSize:       core.DefaultTagSize,
	}}, static, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	bind := func(sess *core.Session) (Opener, TokenSource, error) {
		k, _ := sess.RecvDemuxKey()
		return sess, NewKeyedSource(&k), nil
	}

	for _, tc := range []struct {
		mtu     int
		refused bool
	}{
		{0, true}, // no claim is impossible: refusing is the point of this change
		{1279, true},
		{1280, true}, // the low edge: RFC 8200's floor is itself in the zone
		{1420, true}, // the high edge
		{MinPathMTUForInnerIPv6, false},
		{1450, false},
		{1500, false},
	} {
		t.Run(strconv.Itoa(tc.mtu), func(t *testing.T) {
			cfg := silentCfg()
			gw, err := New(cfg, tc.mtu, resp, bind)
			if err == nil {
				t.Cleanup(gw.Table().Close)
			}
			if tc.refused && err == nil {
				t.Fatalf("a gateway at path MTU %d was accepted; it is unservable", tc.mtu)
			}
			if !tc.refused && err != nil {
				t.Fatalf("a gateway at path MTU %d was refused: %v", tc.mtu, err)
			}
			if tc.refused && !errors.Is(err, ErrConfig) {
				t.Fatalf("the refusal is %v, want ErrConfig", err)
			}
		})
	}
}

// TestTheGatewayCannotBeBuiltWithoutAPathMTUClaim is the construction guard for
// the fail-open half of silent-refusal #3, stated in the positive.
//
// Until 2026-08-10 Config.PathMTU zero meant "make no claim", and a gateway
// constructed that way emitted no notice — so a client talking to it got no
// mismatch check at all. It survived an independent review because the encoder
// had a green test while this package went on passing nil. Making zero a
// construction error is the point of this change: there is no longer a
// configuration in which a built gateway fails to state its path MTU.
//
// This test asserts the CONSTRUCT side of the guard. The compile side — that
// New now requires the argument and no Config field exists to omit — is
// proven by the signature itself and by the mutation harness that shows a
// fail-open New is caught by the dead-zone and notice tests.
func TestTheGatewayCannotBeBuiltWithoutAPathMTUClaim(t *testing.T) {
	static, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := core.NewResponder(core.Config{Gateway: core.GatewayParams{
		AdmissionKeys: [][]byte{make([]byte, core.KeySize)},
		GatewayID:     []byte("winn3-gateway-noclaim"),
		TagSize:       core.DefaultTagSize,
	}}, static, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	bind := func(sess *core.Session) (Opener, TokenSource, error) {
		k, _ := sess.RecvDemuxKey()
		return sess, NewKeyedSource(&k), nil
	}

	for _, mtu := range []int{0, -1} {
		t.Run(strconv.Itoa(mtu), func(t *testing.T) {
			gw, err := New(silentCfg(), mtu, resp, bind)
			if err == nil {
				gw.Table().Close()
				t.Fatalf("a gateway at path MTU %d was constructed; a no-claim gateway emits no "+
					"notice and gives its clients no mismatch check at all", mtu)
			}
			if !errors.Is(err, ErrConfig) {
				t.Fatalf("the refusal is %v, want ErrConfig", err)
			}
			if !strings.Contains(err.Error(), "no claim") {
				t.Errorf("the refusal does not say the gateway would make no claim; an operator "+
					"cannot tell why construction failed:\n%s", err)
			}
		})
	}
}

// buildGatewayForMTU constructs a gateway at a given path MTU on a throwaway
// responder, returning New's error. Used by the construction-guard tests at the
// two ends of the range the wire's 16-bit mtu field can carry.
func buildGatewayForMTU(t *testing.T, mtu int) (*Gateway, error) {
	t.Helper()
	static, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatalf("static key: %v", err)
	}
	resp, err := core.NewResponder(core.Config{Gateway: core.GatewayParams{
		AdmissionKeys: [][]byte{make([]byte, core.KeySize)},
		GatewayID:     []byte("winn3-gateway-noticebound"),
		TagSize:       core.DefaultTagSize,
	}}, static, func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}
	bind := func(sess *core.Session) (Opener, TokenSource, error) {
		k, _ := sess.RecvDemuxKey()
		return sess, NewKeyedSource(&k), nil
	}
	return New(silentCfg(), mtu, resp, bind)
}

// TestAGatewayAtEveryBoundaryTheNoticeCanStateIsConstructibleAndStatesIt pins
// the claim "every gateway this package can construct states a number" at every
// boundary the wire record can carry, including the ceiling.
//
// TestTheGatewayCannotBeBuiltWithoutAPathMTUClaim proves the low end (zero and
// negative). This is the boundary the range itself is rounded on: the notice's
// mtu field is a 16-bit big-endian integer, so 0xFFFF is a value that must be
// constructible AND must decode back to itself, or the guard at the high end
// would be refusing a claim the gateway could honestly make.
func TestAGatewayAtEveryBoundaryTheNoticeCanStateIsConstructibleAndStatesIt(t *testing.T) {
	for _, mtu := range []int{MinPathMTUForInnerIPv6, 1450, 1500, maxPathMTUNoticeValue} {
		t.Run(strconv.Itoa(mtu), func(t *testing.T) {
			gw, err := buildGatewayForMTU(t, mtu)
			if err != nil {
				t.Fatalf("a gateway at path MTU %d was refused: %v", mtu, err)
			}
			defer gw.Table().Close()
			if gw.notice == nil {
				t.Fatalf("the gateway at %d holds a NIL notice. A client talking to it gets no "+
					"mismatch check at all, which is the fail-open half of silent-refusal #3, "+
					"and it happened here after construction SUCCEEDED", mtu)
			}
			if got, ok := session.DecodePathMTUNotice(gw.notice); !ok || got != mtu {
				t.Fatalf("the gateway at %d states %d (ok=%v); a notice that does not say %d is "+
					"a false claim", mtu, got, ok, mtu)
			}
		})
	}
}

// TestAGatewayCannotClaimAPathMTUTheNoticeCannotState is the high-end half of
// the no-claim rule, and the one that made params.go and gateway.go disagree.
//
// Zero means "make no claim" and is refused (see
// TestTheGatewayCannotBeBuiltWithoutAPathMTUClaim). The same fail-open exists
// at the other end of the range: session.EncodePathMTUNotice returns nil —
// "no claim" — above 0xFFFF, because the wire record's mtu field is 16 bits. A
// gateway constructed at such a value would hold a nil notice and hand every
// client no mismatch check, exactly as if zero had been accepted. Until
// 2026-08-10 New accepted these values and gateway.go's "this is NEVER nil"
// was false for them.
func TestAGatewayCannotClaimAPathMTUTheNoticeCannotState(t *testing.T) {
	for _, tc := range []struct {
		mtu     int
		ceiling bool // the refusal's explanation must name the 16-bit ceiling
	}{
		{0, false},
		{-1, false},
		{maxPathMTUNoticeValue + 1, true}, // 65536: the first value the wire cannot state
		{0x7FFFFFFF, true},
	} {
		t.Run(strconv.Itoa(tc.mtu), func(t *testing.T) {
			gw, err := buildGatewayForMTU(t, tc.mtu)
			if err == nil {
				gw.Table().Close()
				t.Fatalf("a gateway at path MTU %d was constructed. EncodePathMTUNotice returns "+
					"nil for it, so this gateway emits no claim and gives its clients no "+
					"mismatch check at all", tc.mtu)
			}
			if !errors.Is(err, ErrConfig) {
				t.Fatalf("the refusal is %v, want ErrConfig", err)
			}
			if tc.ceiling && !strings.Contains(err.Error(), strconv.Itoa(maxPathMTUNoticeValue)) {
				t.Errorf("the high-end refusal does not name the notice ceiling %d; an operator "+
					"cannot tell why construction failed:\n%s", maxPathMTUNoticeValue, err)
			}
		})
	}
}
