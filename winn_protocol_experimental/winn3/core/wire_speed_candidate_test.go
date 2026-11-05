package core

import (
	"bytes"
	"fmt"
	"io"
	"testing"
)

var wireSpeedToken [DemuxTokenSize]byte

func wireSpeedPair(b *testing.B, window int) (*Session, *Session) {
	b.Helper()
	var ch chain
	a, err := newSession(RoleInitiator, ch, DefaultTokenWindow)
	if err != nil {
		b.Fatal(err)
	}
	z, err := newSession(RoleResponder, ch, window)
	if err != nil {
		b.Fatal(err)
	}
	return a, z
}

func wireSpeedRate(b *testing.B) {
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds()/1e6, "Mpps")
}

func TestAstraPRFCompatibility(t *testing.T) {
	for k := 0; k < 8; k++ {
		var key [KeySize]byte
		for i := range key {
			key[i] = byte(i + k*31)
		}
		p := newDemuxPRF(&key)
		for c := uint64(0); c < 10000; c++ {
			if p.token(c) != demuxToken(&key, c) {
				t.Fatalf("token differs at %d", c)
			}
		}
		for _, c := range []uint64{1 << 32, 1 << 63, ^uint64(0)} {
			if p.token(c) != demuxToken(&key, c) {
				t.Fatal("boundary token differs")
			}
		}
	}
}

func TestAstraIntoOwnershipAndReplay(t *testing.T) {
	var ch chain
	a, _ := newSession(RoleInitiator, ch, DefaultTokenWindow)
	legacy, _ := newSession(RoleInitiator, ch, DefaultTokenWindow)
	z, _ := newSession(RoleResponder, ch, DefaultTokenWindow)
	payload := bytes.Repeat([]byte{0x69}, 1200)
	if _, e := a.SealInto(make([]byte, 10), payload, 1400); e != io.ErrShortBuffer {
		t.Fatalf("short buffer: %v", e)
	}
	if a.SendCounter() != 0 {
		t.Fatal("short buffer consumed nonce")
	}
	dst := bytes.Repeat([]byte{0xa5}, 1500)
	for i := 0; i < 3000; i++ {
		msg, e := a.SealInto(dst[:0], payload, 1400)
		if e != nil {
			t.Fatal(e)
		}
		want, e := legacy.Seal(payload, 1400)
		if e != nil || !bytes.Equal(msg, want) {
			t.Fatal("wire mismatch or dirty padding")
		}
		bad := append([]byte(nil), msg...)
		bad[len(bad)-1] ^= 1
		if _, e = z.OpenInto(make([]byte, 1500), bad); e == nil {
			t.Fatal("accepted bad tag")
		}
		original := append([]byte(nil), msg...)
		out, e := z.OpenInto(msg[DemuxTokenSize:DemuxTokenSize], msg)
		if e != nil || !bytes.Equal(out, payload) {
			t.Fatalf("in-place open: %v", e)
		}
		if cap(out) != len(out) {
			t.Fatal("payload view exposes padding")
		}
		if _, e = z.Open(original); e == nil {
			t.Fatal("replay accepted")
		}
	}
	a.Wipe()
	if _, e := a.SealInto(dst, payload, 0); e != ErrWiped {
		t.Fatal("seal after wipe", e)
	}
}

func BenchmarkAstraIntoRoundTrip(b *testing.B) {
	for _, n := range []int{64, 512, 1200, 1400} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			a, z := wireSpeedPair(b, DefaultTokenWindow)
			p := make([]byte, n)
			dst := make([]byte, n+TransportOverhead())
			b.ReportAllocs()
			b.SetBytes(int64(n))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m, e := a.SealInto(dst[:0], p, 0)
				if e != nil {
					b.Fatal(e)
				}
				out, e := z.OpenInto(m[DemuxTokenSize:DemuxTokenSize], m)
				if e != nil || len(out) != n {
					b.Fatalf("open %v", e)
				}
			}
			wireSpeedRate(b)
		})
	}
}

func BenchmarkAstraCachedDemux(b *testing.B) {
	var key [KeySize]byte
	p := newDemuxPRF(&key)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wireSpeedToken = p.token(uint64(i))
	}
	wireSpeedRate(b)
}

func BenchmarkAstraOriginalDemux(b *testing.B) {
	var key [KeySize]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wireSpeedToken = demuxToken(&key, uint64(i))
	}
	wireSpeedRate(b)
}
