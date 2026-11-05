package main

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
)

// benchIsolation attaches the OI-5 rule to tbl for the benchmarks in
// forward_isolation_bench_test.go. On the tree before the fix this file is
// replaced by a no-op of the same name, so the benchmark code is identical
// before and after. The pool and the local set match a production gateway:
// one /24 pool, the inner address, one WAN address.
func benchIsolation(b *testing.B, tbl *forwardTable) {
	b.Helper()
	pool, inner, wan := "10.64.90.0/24", "10.64.90.1", "203.0.113.90"
	if tbl.registry != nil {
		pool, inner = "10.10.0.0/24", "10.10.0.1"
	}
	iso, err := newForwardIsolationWith(netip.MustParsePrefix(pool), netip.MustParseAddr(inner), func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP(inner), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP(wan), Mask: net.CIDRMask(32, 32)},
			&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		}, nil
	})
	if err != nil {
		b.Fatal(err)
	}
	tbl.isolation = iso
}

// BenchmarkForwardIsolationRefuses measures the rule alone, for the accepted
// internet destination (every compare runs and the local set is scanned) and
// for the two refusals that end earliest and latest.
func BenchmarkForwardIsolationRefuses(b *testing.B) {
	tbl := newForwardTable()
	benchIsolation(b, tbl)
	iso := tbl.isolation
	word := func(s string) uint32 {
		a := netip.MustParseAddr(s).As4()
		return binary.BigEndian.Uint32(a[:])
	}
	src := word("10.64.90.2")
	for _, c := range []struct {
		name string
		dst  uint32
		want bool
	}{
		{"accepted public", word("8.8.8.8"), false},
		{"refused pool", word("10.64.90.3"), true},
		{"refused wan", word("203.0.113.90"), true},
	} {
		b.Run(c.name, func(b *testing.B) {
			if iso.refuses(src, c.dst) != c.want {
				b.Fatalf("refuses(%#x) != %v", c.dst, c.want)
			}
			b.ReportAllocs()
			b.ResetTimer()
			var refused int
			for i := 0; i < b.N; i++ {
				if iso.refuses(src, c.dst) {
					refused++
				}
			}
			if (refused > 0) != c.want {
				b.Fatal("the benchmark loop measured the wrong verdict")
			}
		})
	}
}
