package core

import (
	"bytes"
	"errors"
	"testing"
)

// TestSessionWipeZeroisesOwnedMaterialAndRefusesFurtherUse is the contract
// Session.Wipe's comment has pointed at since it was written: RecvDemuxKey
// returns zeros, Seal/Open/OpenAt/MixPQ/Rekey return ErrWiped, and every key
// this package actually stores in Session fields is zero. A search of
// *_test.go on 2026-08-12 found no call to Session.Wipe, Initiator.Wipe or
// ResponderHandshake.Wipe and no mention of ErrWiped — the comment outran
// the suite.
//
// The exported RecvDemuxKey/ErrWiped checks alone are not enough. wipeLocked
// setting only `s.wiped = true` would satisfy those and leave the chaining
// key and both demux keys in the struct for a crash dump. The field checks
// are what make a flag-only Wipe fail.
func TestSessionWipeZeroisesOwnedMaterialAndRefusesFurtherUse(t *testing.T) {
	h := newHarness(t)
	cli, gw := h.completeHandshake(t)

	payload := []byte("pre-wipe")
	msg, err := cli.Seal(payload, 0)
	if err != nil {
		t.Fatalf("pre-wipe Seal: %v", err)
	}
	got, err := gw.Open(msg)
	if err != nil {
		t.Fatalf("pre-wipe Open: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("pre-wipe round-trip lost the payload")
	}

	keyBefore, epochBefore := gw.RecvDemuxKey()
	if keyBefore == [KeySize]byte{} {
		t.Fatal("RecvDemuxKey was all zeros before Wipe; the handshake did not install a demux key")
	}
	if epochBefore != 0 {
		t.Fatalf("fresh handshake epoch is %d, want 0", epochBefore)
	}
	if cli.sendDemux == [KeySize]byte{} || cli.ch.ck == [hashSize]byte{} {
		t.Fatal("initiator session fields were already zero before Wipe")
	}

	cli.Wipe()
	gw.Wipe()

	assertSessionWiped(t, "initiator", cli)
	assertSessionWiped(t, "responder", gw)

	if _, err := cli.Seal(payload, 0); !errors.Is(err, ErrWiped) {
		t.Fatalf("Seal after Wipe returned %v, want ErrWiped", err)
	}
	if _, err := gw.Open(msg); !errors.Is(err, ErrWiped) {
		t.Fatalf("Open after Wipe returned %v, want ErrWiped", err)
	}
	if _, err := gw.OpenAt(msg, 0); !errors.Is(err, ErrWiped) {
		t.Fatalf("OpenAt after Wipe returned %v, want ErrWiped", err)
	}

	pq := make([]byte, PQSharedKeySize)
	pq[0] = 1
	if err := cli.MixPQ(pq); !errors.Is(err, ErrWiped) {
		t.Fatalf("MixPQ after Wipe returned %v, want ErrWiped", err)
	}
	rk := make([]byte, KeySize)
	rk[0] = 1
	if err := gw.Rekey(rk); !errors.Is(err, ErrWiped) {
		t.Fatalf("Rekey after Wipe returned %v, want ErrWiped", err)
	}

	cli.Wipe()
	gw.Wipe()
	assertSessionWiped(t, "initiator after second Wipe", cli)
	assertSessionWiped(t, "responder after second Wipe", gw)
}

func assertSessionWiped(t *testing.T, who string, s *Session) {
	t.Helper()
	if !s.wiped {
		t.Fatalf("%s: wiped flag is false", who)
	}
	if s.sendAEAD != nil || s.recvAEAD != nil {
		t.Fatalf("%s: AEAD objects were not released", who)
	}
	if s.recvWindow != nil {
		t.Fatalf("%s: recvWindow was not dropped", who)
	}
	if s.sendDemux != [KeySize]byte{} || s.recvDemux != [KeySize]byte{} {
		t.Fatalf("%s: a demux key is still populated", who)
	}
	if s.sendSalt != [nonceSaltSize]byte{} || s.recvSalt != [nonceSaltSize]byte{} {
		t.Fatalf("%s: a nonce salt is still populated", who)
	}
	if s.ch.ck != [hashSize]byte{} || s.ch.h != [hashSize]byte{} {
		t.Fatalf("%s: the chaining key or transcript hash is still populated", who)
	}
	key, epoch := s.RecvDemuxKey()
	if key != [KeySize]byte{} || epoch != 0 {
		t.Fatalf("%s: RecvDemuxKey returned a non-zero key or epoch %d", who, epoch)
	}
}

func TestNilSessionWipeDoesNotPanic(t *testing.T) {
	var s *Session
	s.Wipe()
}

// TestInitiatorWipeDropsHandshakeSecrets covers the abort path: WriteInitiation
// has run, ReadResponse has not, and the caller discards the attempt.
func TestInitiatorWipeDropsHandshakeSecrets(t *testing.T) {
	h := newHarness(t)
	ini := h.initiator(t)
	if _, err := ini.WriteInitiation(nil, PadAuto); err != nil {
		t.Fatalf("WriteInitiation: %v", err)
	}
	if ini.eph == nil {
		t.Fatal("WriteInitiation left eph nil")
	}
	if ini.ch.ck == [hashSize]byte{} {
		t.Fatal("WriteInitiation left the chaining key zero")
	}
	if len(ini.sentMsg) == 0 {
		t.Fatal("WriteInitiation left sentMsg empty")
	}

	ini.Wipe()

	if !ini.wiped {
		t.Fatal("Wipe left the wiped flag false")
	}
	if ini.eph != nil {
		t.Fatal("Wipe left the handshake ephemeral reachable")
	}
	if ini.ch.ck != [hashSize]byte{} || ini.ch.h != [hashSize]byte{} {
		t.Fatal("Wipe left initiator chain material populated")
	}
	if ini.sentMsg != nil {
		t.Fatal("Wipe left sentMsg reachable")
	}

	if _, err := ini.WriteInitiation(nil, PadAuto); !errors.Is(err, ErrWiped) {
		t.Fatalf("WriteInitiation after Wipe returned %v, want ErrWiped", err)
	}
	if _, err := ini.Retransmit(); !errors.Is(err, ErrWiped) {
		t.Fatalf("Retransmit after Wipe returned %v, want ErrWiped", err)
	}
	if _, _, err := ini.ReadResponse(make([]byte, 200)); !errors.Is(err, ErrWiped) {
		t.Fatalf("ReadResponse after Wipe returned %v, want ErrWiped", err)
	}

	ini.Wipe()
}

func TestNilInitiatorWipeDoesNotPanic(t *testing.T) {
	var i *Initiator
	i.Wipe()
}

// TestResponderHandshakeWipeDropsStageKeys covers Gateway.Handle's defer
// h.Wipe() on every abort after ReadInitiation succeeded.
func TestResponderHandshakeWipeDropsStageKeys(t *testing.T) {
	h := newHarness(t)
	ini := h.initiator(t)
	msg1, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatalf("WriteInitiation: %v", err)
	}
	rh, err := h.resp.ReadInitiation(msg1)
	if err != nil {
		t.Fatalf("ReadInitiation: %v", err)
	}
	if len(rh.tagKey) == 0 || len(rh.whitenKey) == 0 {
		t.Fatal("ReadInitiation left response keys empty")
	}
	if rh.ch.ck == [hashSize]byte{} {
		t.Fatal("ReadInitiation left the chaining key zero")
	}
	if rh.replayKey == [32]byte{} {
		t.Fatal("ReadInitiation left replayKey zero")
	}

	rh.Wipe()

	if rh.tagKey != nil || rh.whitenKey != nil {
		t.Fatal("Wipe left response keys reachable")
	}
	if rh.ch.ck != [hashSize]byte{} || rh.ch.h != [hashSize]byte{} {
		t.Fatal("Wipe left responder chain material populated")
	}
	if rh.replayKey != [32]byte{} {
		t.Fatal("Wipe left replayKey populated")
	}
	if rh.peerEph != nil || rh.peerStat != nil {
		t.Fatal("Wipe left peer public keys reachable")
	}
	if rh.payload != nil {
		t.Fatal("Wipe left payload reachable")
	}

	rh.Wipe()
}

func TestNilResponderHandshakeWipeDoesNotPanic(t *testing.T) {
	var h *ResponderHandshake
	h.Wipe()
}
