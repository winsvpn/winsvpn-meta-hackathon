package session

import (
	"bytes"
	"testing"

	"winsvpn.local/winnprotocol/winn3/core"
)

func TestRekeyFirstNewEpochDataDeliveryParity(t *testing.T) {
	for _, batched := range []bool{false, true} {
		name := "scalar"
		if batched {
			name = "batch"
		}
		t.Run(name, func(t *testing.T) {
			p := stage5Pair(t)
			oldEpoch := p.cli.Epoch()
			if err := p.cli.startRekey(p.clk.Now()); err != nil {
				t.Fatal(err)
			}
			init, err := p.cli.Poll()
			if err != nil || len(init) == 0 {
				t.Fatalf("rekey initiation: %v", err)
			}
			if _, err := p.gw.Deliver(init); err != nil {
				t.Fatal(err)
			}
			ack, err := p.gw.Poll()
			if err != nil || len(ack) == 0 {
				t.Fatalf("rekey acknowledgement: %v", err)
			}
			if _, err := p.cli.Deliver(ack); err != nil {
				t.Fatal(err)
			}
			if p.cli.Epoch() != oldEpoch+1 || p.gw.Epoch() != oldEpoch+1 {
				t.Fatal("peers did not reach the new epoch")
			}
			if p.gw.rekeyConfirmAt.IsZero() || p.gw.DataPlaneState() != StateRekeying {
				t.Fatal("receiver must initially await peer confirmation")
			}
			// Network ordering can put authenticated DATA ahead of the queued
			// new-epoch probe. That DATA also proves the peer completed rekey.
			payload := []byte("first new epoch packet")
			message := stage5Message(t, p.cli, core.FrameData, payload)
			before := p.gw.Stats()
			var packets [][]byte
			if batched {
				in := stage5Input(message)
				n, err := p.gw.DeliverBatch(in)
				if err != nil || n != 1 {
					t.Fatalf("batch consumed %d messages: %v", n, err)
				}
				packets = in[0].Packets
			} else {
				packets, err = p.gw.Deliver(message)
				if err != nil {
					t.Fatal(err)
				}
			}
			if len(packets) != 1 || !bytes.Equal(packets[0], payload) {
				t.Fatalf("first confirmed new-epoch packet lost: got %q", packets)
			}
			if !p.gw.rekeyConfirmAt.IsZero() || p.gw.DataPlaneState() != StateEstablished {
				t.Fatal("authenticated new-epoch data did not release confirmation hold")
			}
			after := p.gw.Stats()
			if after.MessagesReceived-before.MessagesReceived != 1 || after.BytesReceived-before.BytesReceived != uint64(len(message)) {
				t.Fatal("confirmation message accounting differs from ordinary data")
			}
		})
	}
}
