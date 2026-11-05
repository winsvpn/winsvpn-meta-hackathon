package session

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// coreHandshake produces a matched initiator/responder pair of core.Sessions
// without involving the session driver. It mirrors what gateway.Gateway.Handle
// does internally: the Responder reads the initiation and writes the response.
func coreHandshake(t *testing.T) (cliSess, gwSess *core.Session, cliStatic, gwStatic *core.StaticKey, gwPub *core.PublicKey, initiatorStatic []byte) {
	t.Helper()
	clk := newClock()
	gwStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	cliStatic, err = core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	gwPub, err = core.NewPublicKey(gwStatic.Public())
	if err != nil {
		t.Fatal(err)
	}
	gp := gatewayParams(t)
	cfgCli := core.Config{Gateway: gp, Rand: newDetRand("seam-cli"), Now: clk.Now}
	cfgGw := core.Config{Gateway: gp, Rand: newDetRand("seam-gw"), Now: clk.Now}
	ini, err := core.NewInitiator(cfgCli, cliStatic, gwPub)
	if err != nil {
		t.Fatal(err)
	}
	accept := func(b []byte) error { return nil }
	resp, err := core.NewResponder(cfgGw, gwStatic, accept)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := ini.WriteInitiation(nil, core.PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	hs, err := resp.ReadInitiation(msg)
	if err != nil {
		t.Fatal(err)
	}
	initiatorStatic = hs.InitiatorStatic()
	reply, gwS, err := hs.WriteResponse(nil, core.PadAuto)
	if err != nil {
		t.Fatal(err)
	}
	cliS, _, err := ini.ReadResponse(reply)
	if err != nil {
		t.Fatal(err)
	}
	return cliS, gwS, cliStatic, gwStatic, gwPub, initiatorStatic
}

func TestNewGatewayFromSessionAdoptsResponderSession(t *testing.T) {
	_, gwSess, _, gwStatic, _, initiatorStatic := coreHandshake(t)
	clk := newClock()
	gwCfg := Config{
		Core:   core.Config{Gateway: gatewayParams(t)},
		Static: gwStatic,
		Clock:  clk,
		Rand:   newDetRand("seam-gw2"),
	}
	gwDrv, err := NewGatewayFromSession(gwCfg, gwSess, initiatorStatic)
	if err != nil {
		t.Fatalf("NewGatewayFromSession: %v", err)
	}
	if gwDrv.State() != StateInitiating {
		t.Fatalf("adopted gateway driver state is %s, want initiating (strict-PQ)", gwDrv.State())
	}
	if got := gwDrv.PeerStatic(); !bytes.Equal(got, initiatorStatic) {
		t.Fatalf("PeerStatic mismatch")
	}
	if gwDrv.Epoch() != 0 {
		t.Fatalf("epoch is %d, want 0 before PQ", gwDrv.Epoch())
	}
	if dl := gwDrv.NextDeadline(); dl.IsZero() {
		t.Error("adopted gateway has no deadline")
	}
}

func TestNewGatewayFromSessionRejectsNilSession(t *testing.T) {
	clk := newClock()
	gwStatic, _ := core.GenerateStaticKey()
	cfg := Config{
		Core:   core.Config{Gateway: gatewayParams(t)},
		Static: gwStatic,
		Clock:  clk,
		Rand:   newDetRand("nil-test"),
	}
	if _, err := NewGatewayFromSession(cfg, nil, nil); !errors.Is(err, ErrConfig) {
		t.Fatalf("nil session returned %v, want ErrConfig", err)
	}
}

func TestNewGatewayFromSessionRejectsInitiatorRole(t *testing.T) {
	cliSess, _, _, _, _, _ := coreHandshake(t)
	clk := newClock()
	gwStatic, _ := core.GenerateStaticKey()
	cfg := Config{
		Core:   core.Config{Gateway: gatewayParams(t)},
		Static: gwStatic,
		Clock:  clk,
		Rand:   newDetRand("role-test"),
	}
	if _, err := NewGatewayFromSession(cfg, cliSess, nil); !errors.Is(err, ErrConfig) {
		t.Fatalf("initiator role returned %v, want ErrConfig", err)
	}
}

func TestNewGatewayFromSessionCopiesPeerStatic(t *testing.T) {
	_, gwSess, _, gwStatic, _, initiatorStatic := coreHandshake(t)
	clk := newClock()
	cfg := Config{
		Core:   core.Config{Gateway: gatewayParams(t)},
		Static: gwStatic,
		Clock:  clk,
		Rand:   newDetRand("copy-test"),
	}
	orig := append([]byte(nil), initiatorStatic...)
	drv, err := NewGatewayFromSession(cfg, gwSess, initiatorStatic)
	if err != nil {
		t.Fatal(err)
	}
	initiatorStatic[0] ^= 0xff
	if got := drv.PeerStatic(); !bytes.Equal(got, orig) {
		t.Fatalf("PeerStatic aliased the caller's slice")
	}
}

func TestNewFromSessionGenericAdoptsEitherRole(t *testing.T) {
	cliSess, gwSess, cliStatic, gwStatic, gwPub, initiatorStatic := coreHandshake(t)
	clk := newClock()
	cliCfg := Config{
		Core:          core.Config{Gateway: gatewayParams(t)},
		Static:        cliStatic,
		GatewayStatic: gwPub,
		Clock:         clk,
		Rand:          newDetRand("generic-cli"),
	}
	gwCfg := Config{
		Core:   core.Config{Gateway: gatewayParams(t)},
		Static: gwStatic,
		Clock:  clk,
		Rand:   newDetRand("generic-gw"),
	}
	cliDrv, err := NewFromSession(cliCfg, cliSess, nil)
	if err != nil {
		t.Fatalf("NewFromSession initiator: %v", err)
	}
	if cliDrv.State() != StateInitiating {
		t.Fatalf("initiator adopted state %s", cliDrv.State())
	}
	gwDrv, err := NewFromSession(gwCfg, gwSess, initiatorStatic)
	if err != nil {
		t.Fatalf("NewFromSession responder: %v", err)
	}
	if gwDrv.State() != StateInitiating {
		t.Fatalf("responder adopted state %s", gwDrv.State())
	}
}

func TestAdoptedPairCompletesPQRatchetAndCarriesData(t *testing.T) {
	cliSess, gwSess, cliStatic, gwStatic, gwPub, initiatorStatic := coreHandshake(t)
	clk := newClock()
	base := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	clk.t = base
	cliCfg := Config{
		Core:          core.Config{Gateway: gatewayParams(t)},
		Static:        cliStatic,
		GatewayStatic: gwPub,
		Padding:       core.PadBucket,
		Clock:         clk,
		Rand:          newDetRand("adopted-pair-cli"),
	}
	gwCfg := Config{
		Core:   core.Config{Gateway: gatewayParams(t)},
		Static: gwStatic,
		Clock:  clk,
		Rand:   newDetRand("adopted-pair-gw"),
	}
	cliDrv, err := NewFromSession(cliCfg, cliSess, nil)
	if err != nil {
		t.Fatal(err)
	}
	gwDrv, err := NewGatewayFromSession(gwCfg, gwSess, initiatorStatic)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20 && (cliDrv.State() != StateEstablished || gwDrv.State() != StateEstablished); i++ {
		for {
			msg, err := cliDrv.Poll()
			if err != nil {
				t.Fatalf("cli poll: %v", err)
			}
			if msg == nil {
				break
			}
			if _, err := gwDrv.Deliver(msg); err != nil {
				t.Fatalf("gw deliver: %v", err)
			}
		}
		for {
			msg, err := gwDrv.Poll()
			if err != nil {
				t.Fatalf("gw poll: %v", err)
			}
			if msg == nil {
				break
			}
			if _, err := cliDrv.Deliver(msg); err != nil {
				t.Fatalf("cli deliver: %v", err)
			}
		}
		clk.Advance(2 * time.Second)
	}
	if cliDrv.State() != StateEstablished || gwDrv.State() != StateEstablished {
		t.Fatalf("adopted pair did not establish: cli %s gw %s (err %v / %v) epochs %d/%d", cliDrv.State(), gwDrv.State(), cliDrv.Err(), gwDrv.Err(), cliDrv.Epoch(), gwDrv.Epoch())
	}
	if cliDrv.Epoch() != 1 || gwDrv.Epoch() != 1 {
		t.Fatalf("epochs after PQ: cli %d gw %d, want 1", cliDrv.Epoch(), gwDrv.Epoch())
	}
	payload := []byte("hello through adopted session")
	if err := cliDrv.Enqueue(payload); err != nil {
		t.Fatal(err)
	}
	var delivered [][]byte
	for i := 0; i < 4; i++ {
		msg, err := cliDrv.Poll()
		if err != nil {
			t.Fatal(err)
		}
		if msg == nil {
			break
		}
		pkts, err := gwDrv.Deliver(msg)
		if err != nil {
			t.Fatal(err)
		}
		delivered = append(delivered, pkts...)
	}
	if len(delivered) != 1 || !bytes.Equal(delivered[0], payload) {
		t.Fatalf("delivered %v", delivered)
	}
}

func TestAdoptedSessionAlreadyPQRatchetedIsEstablishedImmediately(t *testing.T) {
	cliS1, gwS1, cliStatic2, gwStatic2, gwPub2, _ := coreHandshake(t)
	_, _, _, _, _, initiatorStatic := coreHandshake(t)
	dummy := make([]byte, core.PQSharedKeySize)
	for i := range dummy {
		dummy[i] = byte(i)
	}
	if err := cliS1.MixPQ(dummy); err != nil {
		t.Fatal(err)
	}
	if err := gwS1.MixPQ(dummy); err != nil {
		t.Fatal(err)
	}
	clk2 := newClock()
	cliCfg := Config{
		Core:          core.Config{Gateway: gatewayParams(t)},
		Static:        cliStatic2,
		GatewayStatic: gwPub2,
		Clock:         clk2,
		Rand:          newDetRand("already-ratcheted-cli"),
	}
	gwCfg := Config{
		Core:   core.Config{Gateway: gatewayParams(t)},
		Static: gwStatic2,
		Clock:  clk2,
		Rand:   newDetRand("already-ratcheted-gw"),
	}
	cliAd, err := NewFromSession(cliCfg, cliS1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cliAd.State() != StateEstablished {
		t.Fatalf("cli adopted at epoch 1 state %s, want established", cliAd.State())
	}
	if cliAd.Epoch() != 1 {
		t.Fatalf("cli epoch %d, want 1", cliAd.Epoch())
	}
	gwAd, err := NewGatewayFromSession(gwCfg, gwS1, initiatorStatic)
	if err != nil {
		t.Fatal(err)
	}
	if gwAd.State() != StateEstablished {
		t.Fatalf("gw adopted at epoch 1 state %s, want established", gwAd.State())
	}
}

func TestNewFromSessionRejectsBadConfig(t *testing.T) {
	cliSess, _, _, _, _, _ := coreHandshake(t)
	clk := newClock()
	bad := Config{
		Core:   core.Config{Gateway: gatewayParams(t)},
		Static: nil,
		Clock:  clk,
		Rand:   newDetRand("bad"),
	}
	if _, err := NewFromSession(bad, cliSess, nil); !errors.Is(err, ErrConfig) {
		t.Fatalf("bad config returned %v, want ErrConfig", err)
	}
}

func TestNewFromSessionRejectsNilSession(t *testing.T) {
	cfg := Config{
		Core:   core.Config{Gateway: gatewayParams(t)},
		Static: func() *core.StaticKey { k, _ := core.GenerateStaticKey(); return k }(),
		Clock:  newClock(),
		Rand:   newDetRand("nil2"),
	}
	if _, err := NewFromSession(cfg, nil, nil); !errors.Is(err, ErrConfig) {
		t.Fatalf("nil session returned %v", err)
	}
}

func TestNewGatewayFromSessionRejectsBadConfig(t *testing.T) {
	_, gwSess, _, _, _, _ := coreHandshake(t)
	bad := Config{
		Core:   core.Config{Gateway: gatewayParams(t)},
		Static: nil,
		Clock:  newClock(),
		Rand:   newDetRand("bad-gw"),
	}
	if _, err := NewGatewayFromSession(bad, gwSess, nil); !errors.Is(err, ErrConfig) {
		t.Fatalf("bad config returned %v, want ErrConfig", err)
	}
}
