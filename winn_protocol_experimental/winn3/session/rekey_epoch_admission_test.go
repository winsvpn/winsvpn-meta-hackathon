package session

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"winsvpn.local/winnprotocol/winn3/core"
)

func TestOldEpochDataCannotRideBehindRekeyAck(t *testing.T) {
	p := establishedPair(t)
	if err := p.cli.startRekey(p.clk.Now()); err != nil {
		t.Fatal(err)
	}

	ackKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := core.AppendFrame(nil, core.FrameRekeyAck, ackKey.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	plain, err = core.AppendFrame(plain, core.FrameData, []byte("old-epoch-data"))
	if err != nil {
		t.Fatal(err)
	}

	wire, err := p.gw.sess.Seal(plain, 0)
	if err != nil {
		t.Fatal(err)
	}
	delivered, err := p.cli.Deliver(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(delivered) != 0 {
		t.Fatalf("delivered %q after a same-message rekey transition", delivered[0])
	}
}
