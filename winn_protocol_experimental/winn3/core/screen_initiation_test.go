package core

import (
	"bytes"
	"testing"
)

// TestScreenInitiationAgreesWithReadInitiation pins the screen that an
// address-demultiplexing gateway runs before it allocates anything: it must
// admit every message ReadInitiation would answer, refuse anything that fails
// the admission tag, and report a replay exactly when IsReplayedInitiation
// does. It consumes nothing, so a screened message is still answered once.
func TestScreenInitiationAgreesWithReadInitiation(t *testing.T) {
	h := f4NewHarness(t)
	ini := h.initiator(t)
	msg, err := ini.WriteInitiation(nil, PadAuto)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 2; i++ {
		if ok, replay := h.resp.ScreenInitiation(msg); !ok || replay {
			t.Fatalf("screen %d of a fresh initiation: admissible=%v replayed=%v, want true false", i, ok, replay)
		}
	}
	if _, err := h.resp.ReadInitiation(msg); err != nil {
		t.Fatalf("a screened initiation was not answered: %v", err)
	}
	if ok, replay := h.resp.ScreenInitiation(msg); !ok || !replay {
		t.Fatalf("screen after acceptance: admissible=%v replayed=%v, want true true", ok, replay)
	}
	if got := h.resp.IsReplayedInitiation(msg); !got {
		t.Fatal("IsReplayedInitiation disagrees with ScreenInitiation after acceptance")
	}

	tampered := append([]byte(nil), msg...)
	tampered[0] ^= 0x01
	junk := [][]byte{
		{0x01},
		bytes.Repeat([]byte{0}, 128),
		bytes.Repeat([]byte{0x5a}, MaxHandshakeMessage),
		bytes.Repeat([]byte{0x5a}, MaxHandshakeMessage+1),
		tampered,
	}
	for i, j := range junk {
		if ok, replay := h.resp.ScreenInitiation(j); ok || replay {
			t.Fatalf("junk %d (%d bytes): admissible=%v replayed=%v, want false false", i, len(j), ok, replay)
		}
	}
}
