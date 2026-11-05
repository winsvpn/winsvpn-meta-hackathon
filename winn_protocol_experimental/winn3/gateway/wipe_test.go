package gateway

import "testing"

// TestKeyedSourceWipeZeroisesHMACPads covers Entry.retireAll's type-assert
// Wipe on TokenSource. No test in this package called KeyedSource.Wipe;
// retireAll would still "succeed" if Wipe were a no-op, and the demux key
// would remain in the HMAC pads until GC.
func TestKeyedSourceWipeZeroisesHMACPads(t *testing.T) {
	src := NewKeyedSource(keyFor(1))
	if src.ipad == [blockSize]byte{} || src.opad == [blockSize]byte{} {
		t.Fatal("NewKeyedSource left HMAC pads zero; Wipe would be unobservable")
	}
	live := src.TokenAt(0)
	src.Wipe()
	if src.ipad != [blockSize]byte{} || src.opad != [blockSize]byte{} {
		t.Fatal("Wipe left HMAC pads populated")
	}
	if src.TokenAt(0) == live {
		t.Fatal("TokenAt after Wipe still matches the live token")
	}
}

func TestNilKeyedSourceWipeDoesNotPanic(t *testing.T) {
	var s *KeyedSource
	s.Wipe()
}
