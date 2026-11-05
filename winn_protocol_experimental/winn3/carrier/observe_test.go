package carrier

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/session"
)

// TestObservePassesTheSignalThroughUnmodified is item 5 of the brief.
//
// NeedsCarrierChange is §4.2's normative signal — the handshake budget was spent
// on this carrier — and this package's whole job with it is to hand it upward
// intact. Anything that transformed it here would be a second opinion competing
// with datapath/escalation.go's, and the two would disagree under exactly the
// conditions that make disagreement expensive.
func TestObservePassesTheSignalThroughUnmodified(t *testing.T) {
	t.Parallel()
	p, err := NewPipe(PipeConfig{Class: ClassTLS})
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer func() { _ = p.Close() }()

	for _, needsChange := range []bool{false, true} {
		for _, needsNew := range []bool{false, true} {
			r := stubReporter{
				needsChange: needsChange,
				needsNew:    needsNew,
				state:       session.StateEstablished,
			}
			sig := Observe(r, p)
			if sig.NeedsChange != needsChange {
				t.Fatalf("NeedsChange %v became %v", needsChange, sig.NeedsChange)
			}
			if sig.NeedsNewSession != needsNew {
				t.Fatalf("NeedsNewSession %v became %v", needsNew, sig.NeedsNewSession)
			}
			if sig.State != session.StateEstablished {
				t.Fatalf("state is %v", sig.State)
			}
			if sig.Class != ClassTLS {
				t.Fatalf("class is %s", sig.Class)
			}
		}
	}
}

// TestObserveReportsTheCarriersOwnFailureSeparately.
//
// A dead carrier and a session that wants a different carrier are different
// facts. The policy layer treats them differently — one is a transport that must
// be replaced, the other is a plan step that has been exhausted — so collapsing
// them into one boolean here would delete information the layer above needs.
func TestObserveReportsTheCarriersOwnFailureSeparately(t *testing.T) {
	t.Parallel()
	_, gateway, clientConn, _ := streamPair(t, ClassTCP)

	sig := Observe(stubReporter{}, gateway)
	if sig.CarrierErr != nil {
		t.Fatalf("a healthy carrier reports %v", sig.CarrierErr)
	}
	go func() { _, _ = clientConn.Conn.Write(message(SaltSize+LengthRecordOverhead, 4)) }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = gateway.Recv(ctx)

	sig = Observe(stubReporter{}, gateway)
	if !errors.Is(sig.CarrierErr, ErrStreamDesync) {
		t.Fatalf("a dead carrier reports %v", sig.CarrierErr)
	}
	if sig.NeedsChange {
		t.Fatal("a carrier failure was reported as the session's carrier-change signal")
	}
}

// TestObserveToleratesNils.
//
// Observe is called from a supervisory loop that may run before a carrier is
// attached or after a session has been dropped. Panicking there would take down
// the datapath for a diagnostic.
func TestObserveToleratesNils(t *testing.T) {
	t.Parallel()
	if sig := Observe(nil, nil); sig.Class != ClassUnknown || sig.NeedsChange {
		t.Fatalf("Observe(nil, nil) = %+v", sig)
	}
	p, err := NewPipe(PipeConfig{Class: ClassUDP})
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer func() { _ = p.Close() }()
	if sig := Observe(nil, p); sig.Class != ClassUDP {
		t.Fatalf("Observe(nil, carrier) = %+v", sig)
	}
	if sig := Observe(stubReporter{needsChange: true}, nil); !sig.NeedsChange {
		t.Fatal("Observe(reporter, nil) dropped the signal")
	}
}

// TestObserveCopiesStatsRatherThanSharingThem.
//
// A Signal handed to a supervisor that then mutated as the carrier ran would
// make a verdict computed at one instant reflect a later one.
func TestObserveCopiesStatsRatherThanSharingThem(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	a, b, err := NewPipePair(PipeConfig{Class: ClassUDP, Clock: clock})
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	defer func() { _ = a.Close(); _ = b.Close() }()

	ctx := context.Background()
	if err := a.Send(ctx, message(100, 1)); err != nil {
		t.Fatalf("send: %v", err)
	}
	sig := Observe(stubReporter{}, b)
	if sig.Stats.Delivered != 1 {
		t.Fatalf("Delivered is %d", sig.Stats.Delivered)
	}
	if err := a.Send(ctx, message(100, 2)); err != nil {
		t.Fatalf("send: %v", err)
	}
	if sig.Stats.Delivered != 1 {
		t.Fatal("the Signal's stats changed after it was taken")
	}
}

// TestThisPackageDecidesNoPolicy is item 5 held structurally.
//
// Choosing the next carrier class belongs to datapath/escalation.go and
// datapath/failover.go, which already exist and reason over a wider evidence
// base — plan validity, mobility priority, the all-UDP refusal. Two things must
// be true for that to stay true: this package must not import datapath (which
// would also invert the dependency winn3/ exists to avoid), and it must not
// grow a verdict enumeration of its own.
func TestThisPackageDecidesNoPolicy(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	files := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Clean(name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files++
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			switch {
			case strings.Contains(path, "/datapath"):
				t.Errorf("%s imports %s; policy lives there and winn3/ must not depend on it",
					name, path)
			case strings.Contains(path, "/internal/carrier"),
				strings.Contains(path, "amnezia"), strings.Contains(path, "xray"):
				t.Errorf("%s imports %s; standalone v3 carries none of that", name, path)
			}
		}
	}
	if files < 7 {
		t.Fatalf("only %d source files scanned", files)
	}
}

// TestNoExportedPathHandsOutTheSocket.
//
// The carriers own sockets; the session owns keys. Neither may reach into the
// other. A carrier method that returned its *net.UDPConn or *net.Conn would let
// a caller write to the transport behind the carrier's counters — which would
// desynchronise a stream's length sequence, and on a datagram carrier would put
// bytes on the wire that the fingerprint tests never see.
//
// This mirrors the session lane's TestNoExportedPathHandsOutTheSealer, and for
// the same reason: adding such an accessor now fails a test rather than
// depending on a reviewer noticing.
func TestNoExportedPathHandsOutTheSocket(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}
	banned := map[string]bool{
		"Conn": true, "UDPConn": true, "TCPConn": true, "PacketConn": true,
		"Listener": true, "AEAD": true,
	}
	checked := 0
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				fn, ok := n.(*ast.FuncDecl)
				if !ok || fn.Recv == nil || fn.Type.Results == nil {
					return true
				}
				if !fn.Name.IsExported() {
					return true
				}
				checked++
				for _, res := range fn.Type.Results.List {
					if sel := selectorName(res.Type); sel != "" && banned[sel] {
						t.Errorf("%s: exported method %s returns a %s",
							name, fn.Name.Name, sel)
					}
				}
				return true
			})
		}
	}
	if checked < 20 {
		t.Fatalf("only %d exported methods inspected; the walk is not covering the package", checked)
	}
}

// selectorName unwraps pointers and stars to the type's selector name.
func selectorName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return selectorName(t.X)
	case *ast.SelectorExpr:
		return t.Sel.Name
	case *ast.Ident:
		return t.Name
	}
	return ""
}

// TestReporterIsSatisfiedByTheRealDriver is the coordination point.
//
// The compile-time assertion in carrier.go already fails the build if the
// session lane narrows any of the three methods. This makes the intent visible
// in the test output too, because the failure mode of losing the signal is a
// fleet stranded on a blocked transport with no symptom at all.
func TestReporterIsSatisfiedByTheRealDriver(t *testing.T) {
	t.Parallel()
	var r Reporter = (*session.Driver)(nil)
	if r == nil {
		t.Fatal("unreachable; the assertion exists to make the dependency explicit")
	}
}

// TestPathNarrowedIsPassedThroughAndNothingElseMoves pins the second session
// signal this package carries.
//
// It matters because a narrowed path is the one failure that leaves every
// counter in this package MOTIONLESS: the writes succeed, because a DF path
// reports nothing, and small traffic flows both ways so LastDelivered stays
// fresh. A policy layer reading only carrier counters would call the link
// healthy while every full-size flow on it silently died. The fact can only come
// from the session, which gets round trips answered in two size classes, so all
// this package may do is carry it — verbatim, and without inventing it.
func TestPathNarrowedIsPassedThroughAndNothingElseMoves(t *testing.T) {
	t.Parallel()
	a, b, err := NewPipePair(PipeConfig{Class: ClassUDP})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close(); _ = b.Close() }()

	if sig := Observe(stubReporter{narrowed: true, state: session.StateEstablished}, a); !sig.PathNarrowed {
		t.Fatal("the session's narrowed verdict was dropped on the way through; a caller would " +
			"then see a healthy carrier and a tunnel that carries nothing large")
	}
	if sig := Observe(stubReporter{state: session.StateEstablished}, a); sig.PathNarrowed {
		t.Fatal("PathNarrowed was invented rather than passed through")
	}
	// A nil reporter must not manufacture a verdict either.
	if sig := Observe(nil, a); sig.PathNarrowed {
		t.Fatal("a nil reporter produced a narrowed verdict")
	}
}

// TestSetPeerIsTheOnlyThingThatMovesPeerMoves is the security property the
// rebind fix rests on.
//
// PeerMoves is the ONE counter in Stats that an unauthenticated party cannot
// move, and that is the whole reason a policy layer may read it as mobility
// evidence. Foreign is not, and never can be: an off-path attacker who found the
// five-tuple produces exactly the same Foreign climb as a rebound client, so a
// carrier that learned a peer from Foreign would let one spoofed packet redirect
// a live tunnel to the attacker.
func TestSetPeerIsTheOnlyThingThatMovesPeerMoves(t *testing.T) {
	t.Parallel()
	conn := loopbackUDP(t)
	other := loopbackUDP(t)
	c, err := NewUDP(UDPConfig{
		Conn: conn, Peer: other.LocalAddr().(*net.UDPAddr), PathMTU: DefaultPathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	// Sends, receives, foreign datagrams and errors: none of them may move it.
	msg := make([]byte, 64)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.Send(ctx, msg); err != nil {
		t.Fatalf("send: %v", err)
	}
	third := loopbackUDP(t)
	if _, err := third.WriteToUDP(msg, conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	rctx, rcancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	_, _ = c.Recv(rctx)
	rcancel()

	st := c.Stats()
	if st.PeerMoves != 0 {
		t.Fatalf("PeerMoves is %d after ordinary traffic and a foreign datagram (Foreign=%d). "+
			"If anything but an authenticated peer move can raise it, it is not evidence a "+
			"policy layer may trust and a rebind is indistinguishable from a censor again",
			st.PeerMoves, st.Foreign)
	}
	if st.Foreign == 0 {
		t.Fatal("no foreign datagram was observed; the case was not reached")
	}
}
