package carrier

import (
	"bytes"
	"context"
	"encoding/binary"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The fingerprint suite.
//
// Every test here is written against a CLASS of mistake rather than against a
// line of code, and the ones that carry a claim are shown to have teeth by being
// fed a violation and required to object. The two measured tells in the protocol
// this replaces — a fleet-wide constant at a fixed offset in every initiation,
// and a keepalive at exactly 25.000 seconds with zero jitter — are both
// available at this layer, and neither of them looks like a bug when you write
// it.

// probeLengths are the message sizes the length-leak detector runs over. They
// straddle the 255/256 byte boundary because a single-byte length prefix is the
// other naive framing, and it is only visible below 256.
var probeLengths = []int{64, 100, 255, 256, 257, 512, 1000, 1168}

// leaksLength reports how the length n is findable in a record's framing bytes,
// or "" if it is not.
//
// This is the detector, factored out so that exactly the same code runs over the
// real carrier and over a deliberately naive one. A detector that is only ever
// pointed at the passing case is not evidence.
func leaksLength(framing []byte, n int) string {
	var be, le [2]byte
	binary.BigEndian.PutUint16(be[:], uint16(n))
	binary.LittleEndian.PutUint16(le[:], uint16(n))
	switch {
	case bytes.Contains(framing, be[:]):
		return "big-endian uint16"
	case bytes.Contains(framing, le[:]):
		return "little-endian uint16"
	case n < 256 && len(framing) > 0 && framing[0] == byte(n):
		return "single leading byte"
	case n < 256 && len(framing) > 0 && framing[len(framing)-1] == byte(n):
		return "single trailing byte"
	}
	return ""
}

// TestNoCleartextLengthAppearsOnTheWire is the §4.2 rule, measured.
//
// It does not inspect the implementation. It sends messages of known lengths and
// requires that the length is not findable in the framing bytes that went out:
// not big-endian, not little-endian, not at any offset, and not as a single byte
// at either end of the record. Any of those would let a censor walk the stream
// record by record at line rate without holding a key — failure F1 rebuilt one
// layer down, and in every packet rather than only in the initiation.
func TestNoCleartextLengthAppearsOnTheWire(t *testing.T) {
	t.Parallel()
	client, gateway, clientConn, _ := streamPair(t, ClassTCP)

	for _, n := range probeLengths {
		ch := pumpSend(t, client, message(n, byte(n)))
		if got := mustRecv(t, gateway); len(got) != n {
			t.Fatalf("round trip changed length: sent %d got %d", n, len(got))
		}
		mustSendErr(t, ch)
	}

	for i, n := range probeLengths {
		w := clientConn.writeAt(i)
		if w == nil {
			t.Fatalf("no write %d recorded", i)
		}
		// Only the framing can plausibly leak the length; the message itself is
		// caller-supplied and may contain anything.
		if how := leaksLength(w[:len(w)-n], n); how != "" {
			t.Errorf("length %d is readable in the framing as a %s", n, how)
		}
	}
}

// TestCleartextLengthDetectorHasTeeth feeds the same detector the framing this
// package exists to refuse, and requires it to object to every case.
//
// Without this, TestNoCleartextLengthAppearsOnTheWire is a test that could never
// fail, and a passing invariant test that cannot fail is worse than no test: it
// turns an unverified claim into a verified-looking one. The session lane's
// nonce witness passed two of its own four mutations before it was checked this
// way.
func TestCleartextLengthDetectorHasTeeth(t *testing.T) {
	t.Parallel()
	naive := map[string]func(n int) []byte{
		"big-endian prefix": func(n int) []byte {
			var b [2]byte
			binary.BigEndian.PutUint16(b[:], uint16(n))
			return b[:]
		},
		"little-endian prefix": func(n int) []byte {
			var b [2]byte
			binary.LittleEndian.PutUint16(b[:], uint16(n))
			return b[:]
		},
		"big-endian buried in a header": func(n int) []byte {
			b := []byte{0xa5, 0x01, 0, 0, 0x77}
			binary.BigEndian.PutUint16(b[2:4], uint16(n))
			return b
		},
		"single-byte prefix": func(n int) []byte {
			return []byte{byte(n), 0x00}
		},
	}
	for name, framer := range naive {
		t.Run(name, func(t *testing.T) {
			for _, n := range probeLengths {
				framing := framer(n)
				if n >= 256 && name == "single-byte prefix" {
					continue // not expressible; the framing itself is the bug
				}
				if how := leaksLength(framing, n); how == "" {
					t.Errorf("detector missed length %d in % x", n, framing)
				}
			}
		})
	}
}

// TestSealedLengthsDifferForTheSameLength pins the other half of the property.
//
// A length that is encrypted but deterministic is barely better than a cleartext
// one: an observer who saw the sealed form of 1168 once recognises it forever,
// and full-MTU packets are the majority of a bulk flow. The nonce sequence is
// what prevents that, so it is measured rather than assumed.
func TestSealedLengthsDifferForTheSameLength(t *testing.T) {
	t.Parallel()
	client, gateway, clientConn, _ := streamPair(t, ClassTCP)

	const n = 512
	const rounds = 24
	for i := 0; i < rounds; i++ {
		ch := pumpSend(t, client, message(n, byte(i)))
		mustRecv(t, gateway)
		mustSendErr(t, ch)
	}

	seen := map[string]int{}
	for i := 0; i < rounds; i++ {
		w := clientConn.writeAt(i)
		record := w[len(w)-n-LengthRecordOverhead : len(w)-n]
		seen[string(record)]++
	}
	if len(seen) != rounds {
		t.Fatalf("sealed length repeated: %d distinct records across %d identical lengths",
			len(seen), rounds)
	}
}

// TestOneWritePerMessage is the segment-shape rule.
//
// Splitting the sealed length from the message would be functionally correct and
// would put an 18-byte segment in front of every message on every connection in
// the fleet — a constant expressed as a segment size rather than as bytes, which
// is the same failure class as the 0B 00 00 00 that characterised the previous
// protocol's entire user base.
func TestOneWritePerMessage(t *testing.T) {
	t.Parallel()
	for _, class := range []Class{ClassTCP, ClassTLS} {
		t.Run(class.String(), func(t *testing.T) {
			client, gateway, clientConn, _ := streamPair(t, class)
			const rounds = 10
			for i := 0; i < rounds; i++ {
				ch := pumpSend(t, client, message(200+i, byte(i)))
				mustRecv(t, gateway)
				mustSendErr(t, ch)
			}
			if got := clientConn.writeCount(); got != rounds {
				t.Fatalf("%d writes for %d messages; the record was split", got, rounds)
			}
		})
	}
}

// TestFirstWriteCarriesTheSaltWithTheMessage pins the salt's placement.
//
// A salt written on its own is a 16-byte first segment, fleet-wide, on the one
// packet a censor looks at hardest. Carried with the first message it is
// invisible: the initiation it rides with is padded by a uniform draw, so the
// first segment is variable-length.
func TestFirstWriteCarriesTheSaltWithTheMessage(t *testing.T) {
	t.Parallel()
	client, gateway, clientConn, _ := streamPair(t, ClassTCP)

	if got := clientConn.writeCount(); got != 0 {
		t.Fatalf("construction wrote %d times; nothing may leave before Send", got)
	}
	const n = 300
	ch := pumpSend(t, client, message(n, 7))
	mustRecv(t, gateway)
	mustSendErr(t, ch)

	if got := clientConn.writeCount(); got != 1 {
		t.Fatalf("first message took %d writes, want 1", got)
	}
	want := SaltSize + LengthRecordOverhead + n
	if got := len(clientConn.writeAt(0)); got != want {
		t.Fatalf("first write is %d bytes, want %d (salt+sealed length+message)", got, want)
	}
	// The second message must not repeat the salt.
	ch = pumpSend(t, client, message(n, 8))
	mustRecv(t, gateway)
	mustSendErr(t, ch)
	if got, want := len(clientConn.writeAt(1)), LengthRecordOverhead+n; got != want {
		t.Fatalf("second write is %d bytes, want %d; the salt was repeated", got, want)
	}
}

// TestFirstMessageSizeVariesWithTheMessage is the first-packet-shape claim
// stated as an observable.
//
// A carrier whose first write had a fixed size would be selectable from the
// passive stream alone, before any probing. Because the salt and the sealed
// length are constant-size, the ONLY thing that can vary is the message — so
// this test is really a check that the carrier adds no size normalisation of its
// own, which would flatten the variance the layer above worked to create.
func TestFirstMessageSizeVariesWithTheMessage(t *testing.T) {
	t.Parallel()
	sizes := map[int]bool{}
	for _, n := range []int{180, 210, 244, 301, 388, 436} {
		client, gateway, clientConn, _ := streamPair(t, ClassTCP)
		ch := pumpSend(t, client, message(n, byte(n)))
		mustRecv(t, gateway)
		mustSendErr(t, ch)
		sizes[len(clientConn.writeAt(0))] = true
	}
	if len(sizes) != 6 {
		t.Fatalf("six distinct initiation lengths produced %d distinct first writes; "+
			"the carrier is normalising the first packet", len(sizes))
	}
}

// TestGatewayWritesNothingBeforeItSends is the active-probing rule at the
// carrier layer.
//
// §4.3: the only way to make a gateway emit a byte is a fresh initiation that
// authenticates under its admission key. A carrier-layer greeting — a salt, a
// version, a nonce, anything — would answer an unauthenticated TCP connection
// and hand back the probe oracle the whole design closes. A prober would only
// have to connect.
func TestGatewayWritesNothingBeforeItSends(t *testing.T) {
	t.Parallel()
	_, gateway, _, gatewayConn := streamPair(t, ClassTCP)

	if got := gatewayConn.writeCount(); got != 0 {
		t.Fatalf("gateway wrote %d times on accept; that is a probe oracle", got)
	}
	// Reading, and even failing to read, must not provoke a write either.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, _ = gateway.Recv(ctx)
	if got := gatewayConn.writeCount(); got != 0 {
		t.Fatalf("gateway wrote %d times while receiving; nothing may be written unbidden", got)
	}
	if got := gatewayConn.writtenBytes(); got != 0 {
		t.Fatalf("gateway wrote %d bytes before sending anything", got)
	}
}

// TestDesyncNeverAnswersThePeer is the same rule under attack.
//
// A prober that connects and sends garbage must not be told anything. In
// particular the carrier must not write an error, a reset marker, or a
// close-with-payload, and must not write anything at all on the way down.
func TestDesyncNeverAnswersThePeer(t *testing.T) {
	t.Parallel()
	_, gateway, clientConn, gatewayConn := streamPair(t, ClassTCP)

	go func() {
		// 16 bytes that will be taken as a salt, then 18 that will not open.
		_, _ = clientConn.Conn.Write(message(SaltSize+LengthRecordOverhead, 3))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := gateway.Recv(ctx); err == nil {
		t.Fatal("garbage opened as a message")
	}
	if got := gatewayConn.writeCount(); got != 0 {
		t.Fatalf("gateway wrote %d times in response to garbage", got)
	}
}

// packageSelectors walks the package's own non-test source and reports every
// pkg.Symbol reference, as an AST rather than as text.
//
// Text greping would be simpler and wrong in both directions: it would flag a
// doc comment that merely names a symbol — this package's comments explain at
// length why session.DefaultMaxMessageSize must not be used, which a grep would
// read as using it — and it would miss a reference spelled across a line break.
func packageSelectors(t *testing.T) (map[string]map[string]bool, int) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	found := map[string]map[string]bool{}
	files := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Clean(name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files++
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if found[name] == nil {
				found[name] = map[string]bool{}
			}
			found[name][ident.Name+"."+sel.Sel.Name] = true
			return true
		})
	}
	return found, files
}

// TestCarriersHaveNoTicker is the structural half of "nothing is written
// unbidden".
//
// The behavioural tests above show that no byte leaves without a Send on the
// paths they exercise. This one holds the line against a path nobody thought to
// exercise, by reading the package's own source — the same device the core and
// the session lanes use for the same purpose. A ticker is how a metronome gets
// built by accident; there is no legitimate use for one in a carrier, because
// keepalives are PING frames inside ordinary messages and belong to the session.
func TestCarriersHaveNoTicker(t *testing.T) {
	t.Parallel()
	found, files := packageSelectors(t)
	if files < 7 {
		t.Fatalf("only %d source files scanned; the check is not covering the package", files)
	}
	banned := []string{"time.NewTicker", "time.Tick", "time.AfterFunc"}
	for name, syms := range found {
		for _, b := range banned {
			if syms[b] {
				t.Errorf("%s uses %s; a carrier has no schedule of its own", name, b)
			}
		}
	}
}

// TestPackageNeverUsesTheDefaultMessageSize is item 3 of the brief, held
// structurally.
//
// session.DefaultMaxMessageSize is 1280 − 48: correct for UDP over IPv6 and for
// nothing else. A stream carrier taking it is 64 bytes over the path at the IPv6
// minimum MTU and fragments every full-size message. The session lane says so in
// the constant's own doc comment; this test makes ignoring it a test failure
// rather than a code review.
func TestPackageNeverUsesTheDefaultMessageSize(t *testing.T) {
	t.Parallel()
	found, files := packageSelectors(t)
	if files < 7 {
		t.Fatalf("only %d source files scanned; the check is not covering the package", files)
	}
	sawForPath := false
	for name, syms := range found {
		if syms["session.DefaultMaxMessageSize"] {
			t.Errorf("%s uses session.DefaultMaxMessageSize; call MaxMessageSizeForPath", name)
		}
		if syms["session.MaxMessageSizeForPath"] {
			sawForPath = true
		}
	}
	if !sawForPath {
		t.Fatal("no file calls session.MaxMessageSizeForPath; sizing has been re-derived locally")
	}
}

// TestSourceCheckHasTeeth feeds packageSelectors a file that does the banned
// things and requires it to see them.
//
// Both structural tests above are of the shape that passes when the instrument
// is broken. A parser pointed at the wrong directory, an extension filter that
// excludes everything, a walk that never descends: each turns the check into a
// no-op that reports success forever.
func TestSourceCheckHasTeeth(t *testing.T) {
	dir := t.TempDir()
	src := `package p

import (
	"time"

	"winsvpn.local/winnprotocol/winn3/session"
)

func metronome() int {
	_ = time.NewTicker(time.Second)
	return session.DefaultMaxMessageSize
}
`
	if err := os.WriteFile(filepath.Join(dir, "bad.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	for i := 0; i < 6; i++ {
		pad := "package p\n\nvar _ = " + strings.Repeat("1", i+1) + "\n"
		if err := os.WriteFile(filepath.Join(dir, "pad"+string(rune('a'+i))+".go"),
			[]byte(pad), 0o600); err != nil {
			t.Fatalf("write pad: %v", err)
		}
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(wd) }()

	found, files := packageSelectors(t)
	if files != 7 {
		t.Fatalf("scanned %d files, want 7", files)
	}
	if !found["bad.go"]["time.NewTicker"] {
		t.Error("the ticker check would not have seen a ticker")
	}
	if !found["bad.go"]["session.DefaultMaxMessageSize"] {
		t.Error("the default-size check would not have seen the default size")
	}
}

// TestSizingIsNotReDerivedLocally is the other half.
//
// Exactly one call site may compute a message size, and it must delegate. A
// second implementation is a number that agrees today and drifts later, and the
// symptom of the drift is "large downloads stall" from somewhere nobody can
// attach a debugger.
func TestSizingIsNotReDerivedLocally(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile("sizing.go")
	if err != nil {
		t.Fatalf("read sizing.go: %v", err)
	}
	if got := bytes.Count(src, []byte("session.MaxMessageSizeForPath(")); got != 1 {
		t.Fatalf("sizing.go calls session.MaxMessageSizeForPath %d times, want exactly 1", got)
	}
	if bytes.Contains(src, []byte("pathMTU -")) || bytes.Contains(src, []byte("pathMTU-")) {
		t.Fatal("sizing.go subtracts from pathMTU itself; that arithmetic belongs to winn3/session")
	}
}

// TestUnitOpenNeverReachesABound pins the draw's support.
//
// The inverse-CDF and full-jitter constructions both map the ends of the unit
// interval onto the ends of their support, so an atom at 0 or 1 becomes an atom
// at a wall-clock value that then recurs fleet-wide at a predictable rate. Both
// extremes of the 64-bit input are checked, not a sample.
func TestUnitOpenNeverReachesABound(t *testing.T) {
	t.Parallel()
	r := &seqRand{vals: []uint64{0, 1, 1 << 11, ^uint64(0), ^uint64(0) - 1}}
	for i := 0; i < 5; i++ {
		u, err := unitOpen(r)
		if err != nil {
			t.Fatalf("draw %d: %v", i, err)
		}
		if u <= 0 || u >= 1 {
			t.Fatalf("draw %d produced %v, which is on or outside a bound", i, u)
		}
	}
}
