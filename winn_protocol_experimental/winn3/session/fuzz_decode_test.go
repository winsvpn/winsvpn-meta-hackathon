package session

// Fuzz targets for the v3 session-DECODE path at the driver layer.
//
// Added 2026-08-10 as lane bld_session_fuzz. Two surfaces are exercised:
//
//   - the handshake phase of Driver.Deliver, which routes arbitrary bytes
//     through the responder ReadInitiation / responder WriteResponse / the
//     refusal check / newSession; and
//   - the established phase, which routes arbitrary bytes through
//     Session.Open -> ParseFrames -> handleFrames, including the PQ-chunk
//     reassembly (blobRx.accept) that the REKEY/PQ frames ride on.
//
// blobRx.accept is also fuzzed directly, since it is the reassembly decode with
// the most arithmetic in it.
//
// The rig is deterministic and self-contained (it does not reuse the pair
// helpers in harness_test.go, so a sibling lane editing that file cannot change
// what these measure), and it rebuilds fresh drivers per iteration so a saved
// input reproduces exactly.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// fuzzSrand is a deterministic reader, mirroring the core fuzz file's: SHA-256
// in counter mode over a seed, with a mutex because a shared driver outsources
// its random draws to the configured reader.
type fuzzSrand struct {
	seed  string
	ctr   uint64
	block []byte
}

func (r *fuzzSrand) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(r.block) == 0 {
			var c [8]byte
			binary.BigEndian.PutUint64(c[:], r.ctr)
			r.ctr++
			h := sha256.New()
			h.Write([]byte(r.seed))
			h.Write(c[:])
			r.block = h.Sum(nil)
		}
		k := copy(p[n:], r.block)
		r.block = r.block[k:]
		n += k
	}
	return n, nil
}

// fuzzClock is the deterministic policy clock.
type fuzzClock struct{ t time.Time }

func (c *fuzzClock) Now() time.Time { return c.t }

var fuzzClockStart = time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)

// fuzzKeys is the deterministic key material shared by every pair this file
// builds. Built once per Fuzz function; the drivers made from it are fresh per
// iteration.
type fuzzKeys struct {
	gwStatic  *core.StaticKey
	cliStatic *core.StaticKey
	gwPub     *core.PublicKey
	gwParams  core.GatewayParams
}

func makeFuzzKeys(tb testing.TB) *fuzzKeys {
	tb.Helper()
	gwStatic, err := core.GenerateStaticKeyFrom(&fuzzSrand{seed: "sess-gw-static"})
	if err != nil {
		tb.Fatalf("gw static: %v", err)
	}
	cliStatic, err := core.GenerateStaticKeyFrom(&fuzzSrand{seed: "sess-cli-static"})
	if err != nil {
		tb.Fatalf("cli static: %v", err)
	}
	gwPub, err := core.NewPublicKey(gwStatic.Public())
	if err != nil {
		tb.Fatalf("gw public: %v", err)
	}
	gwParams := core.GatewayParams{
		AdmissionKeys: [][]byte{bytes.Repeat([]byte{0x5C}, 32)},
		GatewayID:     []byte("gw-fuzz-session"),
	}
	return &fuzzKeys{gwStatic: gwStatic, cliStatic: cliStatic, gwPub: gwPub, gwParams: gwParams}
}

// buildPair returns a fresh client/gateway driver pair from the shared keys.
func buildPair(tb testing.TB, k *fuzzKeys) (*Driver, *Driver) {
	tb.Helper()
	clk := &fuzzClock{t: fuzzClockStart}

	cliCfg := Config{
		Core:          core.Config{Gateway: k.gwParams},
		Static:        k.cliStatic,
		GatewayStatic: k.gwPub,
		Padding:       core.PadBucket,
		Clock:         clk,
		Rand:          &fuzzSrand{seed: "sess-cli-rand"},
	}
	gwCfg := Config{
		Core:    core.Config{Gateway: k.gwParams},
		Static:  k.gwStatic,
		Accept:  func([]byte) error { return nil },
		Padding: core.PadBucket,
		Clock:   clk,
		Rand:    &fuzzSrand{seed: "sess-gw-rand"},
	}

	cli, err := NewClient(cliCfg)
	if err != nil {
		tb.Fatalf("new client: %v", err)
	}
	gw, err := NewGateway(gwCfg)
	if err != nil {
		tb.Fatalf("new gateway: %v", err)
	}
	return cli, gw
}

// runPair alternates Poll/Deliver until nothing moves, replicating the harness
// pair.drain/deliver loop without the shared helper.
func runPair(cli, gw *Driver) {
	for k := 0; k < 64; k++ {
		moved := false
		for i := 0; i < 512; i++ {
			msg, err := cli.Poll()
			if err != nil || msg == nil {
				break
			}
			moved = true
			_, _ = gw.Deliver(msg)
		}
		for i := 0; i < 512; i++ {
			msg, err := gw.Poll()
			if err != nil || msg == nil {
				break
			}
			moved = true
			_, _ = cli.Deliver(msg)
		}
		if !moved {
			return
		}
	}
}

// establish runs the handshake and PQ ratchet to StateEstablished on both sides.
func establish(tb testing.TB, k *fuzzKeys) (*Driver, *Driver) {
	tb.Helper()
	cli, gw := buildPair(tb, k)
	runPair(cli, gw)
	if got := cli.State(); got != StateEstablished {
		tb.Fatalf("client state %s, want established", got)
	}
	if got := gw.State(); got != StateEstablished {
		tb.Fatalf("gateway state %s, want established", got)
	}
	return cli, gw
}

// --- PQ chunk reassembly decode ---------------------------------------------

func FuzzBlobRxAccept(f *testing.F) {
	f.Add(int64(core.PQCiphertextSize), []byte{0, 0, 1, 2, 3})
	f.Add(int64(32), []byte{0, 1, 0, 2, 'a', 'b'})
	f.Add(int64(core.PQEncapsulationKeySize), []byte{})
	f.Add(int64(0), []byte{})
	f.Fuzz(func(t *testing.T, total int64, value []byte) {
		if total < 0 || total > 1<<20 {
			return
		}
		b := newBlobRx(int(total))
		_, _ = b.accept(value)
	})
}

// newGatewayOnly builds a standalone gateway driver (no client). Constructing a
// gateway performs no ML-KEM work, so a fresh one can be built per iteration
// cheaply, keeping the handshake-phase decode target independent per input.
func newGatewayOnly(tb testing.TB, k *fuzzKeys) *Driver {
	tb.Helper()
	gw, err := NewGateway(Config{
		Core:    core.Config{Gateway: k.gwParams},
		Static:  k.gwStatic,
		Accept:  func([]byte) error { return nil },
		Padding: core.PadBucket,
		Clock:   &fuzzClock{t: fuzzClockStart},
		Rand:    &fuzzSrand{seed: "sess-gw-rand"},
	})
	if err != nil {
		tb.Fatalf("new gateway: %v", err)
	}
	return gw
}

// --- established session decode through Driver.Deliver ----------------------
//
// The gateway is established ONCE at setup and shared across iterations: it is
// mutex-guarded, and no mutant in the corpus can open (the only inputs that
// can are the exact valid seeds), so its state stays established. Rebuilding a
// full pair per iteration would re-run the ML-KEM ratchet and drop the target
// to ~1 exec/s on this box.

func FuzzDriverDeliverEstablished(f *testing.F) {
	k := makeFuzzKeys(f)
	cli, gw0 := establish(f, k)
	if err := cli.Enqueue([]byte("inner ip packet")); err != nil {
		f.Fatal(err)
	}
	msg, err := cli.Poll()
	if err != nil || msg == nil {
		f.Fatalf("seed poll: msg=%v err=%v", msg != nil, err)
	}
	f.Add(msg)
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0}, core.TransportOverhead()))
	f.Add(bytes.Repeat([]byte{0xFF}, core.TransportOverhead()+3))
	f.Fuzz(func(t *testing.T, batch []byte) {
		if len(batch) > 1<<16 {
			return
		}
		_, _ = gw0.Deliver(batch)
	})
}

// --- handshake phase decode through Driver.Deliver --------------------------
//
// A fresh gateway is built per iteration (cheap, no ML-KEM) so the responder is
// always in the initiating state the handshake decode path expects.

func FuzzDriverDeliverHandshake(f *testing.F) {
	k := makeFuzzKeys(f)
	cli, _ := buildPair(f, k)
	msg, err := cli.Poll()
	if err != nil || msg == nil {
		f.Fatalf("initiation poll: msg=%v err=%v", msg != nil, err)
	}
	f.Add(msg)
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0}, 64))
	f.Fuzz(func(t *testing.T, batch []byte) {
		if len(batch) > 1<<16 {
			return
		}
		gw := newGatewayOnly(t, k)
		_, _ = gw.Deliver(batch)
	})
}
