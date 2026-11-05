package session

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/winn3/core"
)

// dualKeys returns a fresh ed25519 pair plus a pqauth ML-DSA-65 signer seed and
// the verifier-able public half.
func dualKeys(t *testing.T) (priv ed25519.PrivateKey, pub ed25519.PublicKey, seed []byte, mlPub []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seed, err = pqauth.GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := pqauth.NewSigner(pqauth.MLDSA65, seed)
	if err != nil {
		t.Fatal(err)
	}
	mlPub = append([]byte(nil), signer.PublicBytes()...)
	signer.Destroy()
	return
}

func TestDualAuthRoundTripEstablishesAndVerifies(t *testing.T) {
	edPriv, edPub, mlSeed, mlPub := dualKeys(t)
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		gw.DualAuth = DualAuthConfig{Ed25519Private: edPriv, MLDSA65Seed: mlSeed}
		cli.DualAuth = DualAuthConfig{
			Expected:      true,
			Ed25519Public: edPub,
			MLDSA65Public: mlPub,
		}
	})
	p.establish()
	if p.gw.State() != StateEstablished {
		t.Fatalf("gateway state %s, want established (err %v)", p.gw.State(), p.gw.Err())
	}
	if !p.cli.dualDone {
		t.Fatal("client established without verifying the dual-signature attestation")
	}
	if !p.cli.phaseAt.IsZero() {
		t.Fatal("client kept a handshake deadline after verification succeeded")
	}
}

func TestLegacyClientAgainstDualGatewayIsUntouched(t *testing.T) {
	edPriv, _, mlSeed, _ := dualKeys(t)
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		gw.DualAuth = DualAuthConfig{Ed25519Private: edPriv, MLDSA65Seed: mlSeed}
		// cli.DualAuth stays zero-valued: a shipped client.
	})
	p.establish()
	if p.cli.dualDone {
		t.Fatal("a legacy client must never enter the dual-auth path")
	}
	// Flush everything: had the gateway emitted any dual-auth frame, the legacy
	// client would treat it as a protocol error and close.
	p.run()
	if p.cli.State() != StateEstablished {
		t.Fatalf("legacy client is %s (err %v); a dual-auth frame leaked into its session", p.cli.State(), p.cli.Err())
	}
}

func TestDualAuthWrongMLKeyFailsClosed(t *testing.T) {
	edPriv, edPub, mlSeed, _ := dualKeys(t)
	_, _, _, otherMLPub := dualKeys(t)
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		gw.DualAuth = DualAuthConfig{Ed25519Private: edPriv, MLDSA65Seed: mlSeed}
		cli.DualAuth = DualAuthConfig{
			Expected:      true,
			Ed25519Public: edPub,
			MLDSA65Public: otherMLPub, // the wrong key
		}
	})
	p.run()
	// A pre-established session cannot do an orderly CLOSE: the gate never
	// opened, so the client fails outright. Either terminal state is fail
	// closed; what must be pinned is the reason.
	if st := p.cli.State(); st != StateFailed && st != StateClosed {
		t.Fatalf("client state %s, want failed (fail closed)", st)
	}
	if got := p.cli.localReason; got != CloseDualAuthFailed {
		t.Fatalf("client close reason %v, want dual-auth-failed", got)
	}
}

func TestDualExpectedAgainstUnprovisionedGatewayWaits(t *testing.T) {
	_, edPub, _, mlPub := dualKeys(t)
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		cli.DualAuth = DualAuthConfig{
			Expected:      true,
			Ed25519Public: edPub,
			MLDSA65Public: mlPub,
		}
	})
	p.run()
	if p.cli.State() != StateInitiating {
		t.Fatalf("client state %s before the attestation, want initiating", p.cli.State())
	}
	if p.cli.Err() != nil {
		t.Fatalf("client failed early: %v", p.cli.Err())
	}
}

func TestDualAuthConfigValidation(t *testing.T) {
	_, _, seed, _ := dualKeys(t)
	_, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := (DualAuthConfig{Ed25519Private: priv2}).validate(); err == nil {
		t.Fatal("half-provisioned server keys must be refused")
	}
	if err := (DualAuthConfig{Ed25519Private: priv2, MLDSA65Seed: seed}).validate(); err != nil {
		t.Fatalf("consistent server keys rejected: %v", err)
	}
	if err := (DualAuthConfig{Expected: true}).validate(); err == nil {
		t.Fatal("Expected without either peer key must be refused")
	}
	if err := (DualAuthConfig{Expected: true, Ed25519Public: []byte{1}, MLDSA65Public: []byte{2}}).validate(); err == nil {
		t.Fatal("wrong-sized peer keys must be refused")
	}
}

// TestFastPQWithDualAuthExpectedIsRefused pins the mutual exclusion between the
// two epoch-0 policies. FastPQ opens the epoch-0 window for DATA; the dual
// attestation can only lift the gate AFTER the post-quantum ratchet, so
// combining them would serve one promise at the other's expense. The refusal
// lives in the shared normalise, which is the chokepoint of BOTH construction
// halves, and each half alone must stay accepted.
func TestFastPQWithDualAuthExpectedIsRefused(t *testing.T) {
	_, edPub, _, mlPub := dualKeys(t)
	base := func(t *testing.T) Config {
		t.Helper()
		static, err := core.GenerateStaticKey()
		if err != nil {
			t.Fatal(err)
		}
		gwStatic, err := core.GenerateStaticKey()
		if err != nil {
			t.Fatal(err)
		}
		gwPub, err := core.NewPublicKey(gwStatic.Public())
		if err != nil {
			t.Fatal(err)
		}
		return Config{
			Core:          core.Config{Gateway: gatewayParams(t)},
			Static:        static,
			GatewayStatic: gwPub,
			Accept:        func([]byte) error { return nil },
			Padding:       core.PadBucket,
		}
	}
	expected := func(c *Config) {
		c.DualAuth = DualAuthConfig{
			Expected:      true,
			Ed25519Public: edPub,
			MLDSA65Public: mlPub,
		}
	}

	t.Run("fast pq alone is accepted", func(t *testing.T) {
		cfg := base(t)
		cfg.FastPQ = true
		if _, err := NewClient(cfg); err != nil {
			t.Fatalf("FastPQ alone was refused: %v", err)
		}
	})
	t.Run("dual auth expected alone is accepted", func(t *testing.T) {
		cfg := base(t)
		expected(&cfg)
		if _, err := NewClient(cfg); err != nil {
			t.Fatalf("DualAuth.Expected alone was refused: %v", err)
		}
	})
	t.Run("the combination is refused by the client half", func(t *testing.T) {
		cfg := base(t)
		cfg.FastPQ = true
		expected(&cfg)
		if _, err := NewClient(cfg); !errors.Is(err, ErrConfig) {
			t.Fatalf("NewClient accepted FastPQ with DualAuth.Expected: %v", err)
		}
	})
	t.Run("the combination is refused by the shared normalise", func(t *testing.T) {
		// NewSharedResponder runs the same normalise with no role-specific
		// dual-auth check at all, so a pass here pins the refusal in the
		// shared validation rather than in NewGateway's Expected-is-client-
		// only guard.
		cfg := base(t)
		cfg.FastPQ = true
		expected(&cfg)
		if _, err := NewSharedResponder(cfg); !errors.Is(err, ErrConfig) {
			t.Fatalf("the shared normalise accepted FastPQ with DualAuth.Expected: %v", err)
		}
	})
}

// TestDualAuthDeadlineFailsClosedWhenTheAttestationNeverArrives pins the
// enforced half of the attestation wait: a client that expects the attestation
// waits for it against the connect's deadline (connectBy), and when the deadline passes without a verifiable
// pair of signatures the session fails closed with CloseDualAuthFailed, not
// silently, and not as a PQ failure.
func TestDualAuthDeadlineFailsClosedWhenTheAttestationNeverArrives(t *testing.T) {
	_, edPub, _, mlPub := dualKeys(t)
	p := newPair(t, func(cli, gw *Config) {
		quietConfig(cli)
		quietConfig(gw)
		cli.DualAuth = DualAuthConfig{
			Expected:      true,
			Ed25519Public: edPub,
			MLDSA65Public: mlPub,
		}
	})
	p.run()
	if p.cli.State() != StateInitiating {
		t.Fatalf("client state %s before the deadline, want initiating", p.cli.State())
	}
	if dl := p.cli.NextDeadline(); dl.IsZero() {
		t.Fatal("a client waiting on the attestation reports no deadline")
	}

	// The gateway never presents the attestation (it is unprovisioned). The
	// client must wait out its connect deadline and then fail closed with the
	// dual-auth reason.
	p.clk.Advance(2 * handshakeBudget(p.cli.cfg.Retry))
	p.run()
	if st := p.cli.State(); st != StateFailed && st != StateClosed {
		t.Fatalf("client state %s after the deadline, want failed (fail closed)", st)
	}
	if got := p.cli.LocalCloseReason(); got != CloseDualAuthFailed {
		t.Fatalf("close reason %s, want %s", got, CloseDualAuthFailed)
	}
	if err := p.cli.Err(); !errors.Is(err, ErrDualAuthFailed) {
		t.Fatalf("error is %v, want ErrDualAuthFailed", err)
	}
	if !p.cli.NeedsNewSession() {
		t.Error("a failed attestation wait did not ask for a new session")
	}
	if p.cli.NeedsCarrierChange() {
		t.Error("a failed attestation wait demanded a carrier-class change")
	}
}
