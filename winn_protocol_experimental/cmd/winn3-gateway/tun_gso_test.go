package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// gsoTestSegment builds one IPv4/TCP packet with valid IP and TCP checksums,
// as a phone's TCP stack would have sent it.
func gsoTestSegment(seq uint32, id uint16, flags byte, payload []byte, opts []byte) []byte {
	thl := 20 + len(opts)
	p := make([]byte, 20+thl+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	binary.BigEndian.PutUint16(p[4:6], id)
	binary.BigEndian.PutUint16(p[6:8], ipv4FlagDF)
	p[8] = 64
	p[9] = 6
	copy(p[12:16], []byte{10, 10, 0, 7})
	copy(p[16:20], []byte{203, 0, 113, 9})
	binary.BigEndian.PutUint16(p[10:12], ^foldChecksum(onesSum(p[:20], 0)))
	binary.BigEndian.PutUint16(p[20:22], 40123)
	binary.BigEndian.PutUint16(p[22:24], 443)
	binary.BigEndian.PutUint32(p[24:28], seq)
	binary.BigEndian.PutUint32(p[28:32], 0x01020304)
	p[32] = byte(thl/4) << 4
	p[33] = flags
	binary.BigEndian.PutUint16(p[34:36], 4096)
	copy(p[40:], opts)
	copy(p[20+thl:], payload)
	tcp := p[20:]
	sum := onesSum(p[12:20], 0) + 6 + uint32(len(tcp))
	binary.BigEndian.PutUint16(tcp[16:18], ^foldChecksum(onesSum(tcp, sum)))
	return p
}

// kernelSegment emulates what Linux does with a TCPV4 GSO skb whose checksum
// is CHECKSUM_PARTIAL (inet_gso_segment, tcp_gso_segment, then the checksum
// completion at a device without checksum offload): split the payload by
// gso_size, copy the headers, set each IPv4 total length, increment the IP ID
// from the first, recompute the IP checksum, advance the TCP sequence, clear
// PSH on all but the last segment, rebase the partial TCP checksum from the
// super packet's length to each segment's (the kernel's delta arithmetic),
// and complete it over the segment. It uses the super packet's own checksum
// field, so a wrong pseudo-header seed in buildGSO is caught here.
func kernelSegment(t *testing.T, frame []byte) [][]byte {
	t.Helper()
	if frame[0] != vnetHdrFNeedsCsum || frame[1] != vnetHdrGSOTCPv4 {
		t.Fatalf("virtio header flags %d gso_type %d", frame[0], frame[1])
	}
	hdrLen := int(binary.NativeEndian.Uint16(frame[2:4]))
	mss := int(binary.NativeEndian.Uint16(frame[4:6]))
	if cs, co := binary.NativeEndian.Uint16(frame[6:8]), binary.NativeEndian.Uint16(frame[8:10]); cs != 20 || co != 16 {
		t.Fatalf("csum_start %d csum_offset %d", cs, co)
	}
	super := frame[vnetHdrLen:]
	if int(binary.BigEndian.Uint16(super[2:4])) != len(super) {
		t.Fatal("super packet total length is wrong")
	}
	if foldChecksum(onesSum(super[:20], 0)) != 0xffff {
		t.Fatal("super packet IPv4 header checksum is wrong")
	}
	seed := uint32(binary.BigEndian.Uint16(super[36:38]))
	superTCPLen := uint32(len(super) - 20)
	payload := super[hdrLen:]
	var out [][]byte
	seq := binary.BigEndian.Uint32(super[24:28])
	id := binary.BigEndian.Uint16(super[4:6])
	for off := 0; off < len(payload); off += mss {
		end := min(off+mss, len(payload))
		seg := make([]byte, hdrLen+end-off)
		copy(seg, super[:hdrLen])
		copy(seg[hdrLen:], payload[off:end])
		binary.BigEndian.PutUint16(seg[2:4], uint16(len(seg)))
		binary.BigEndian.PutUint16(seg[4:6], id)
		seg[10], seg[11] = 0, 0
		binary.BigEndian.PutUint16(seg[10:12], ^foldChecksum(onesSum(seg[:20], 0)))
		binary.BigEndian.PutUint32(seg[24:28], seq)
		if end < len(payload) {
			seg[33] &^= tcpFlagPSH
		}
		// Rebase the partial sum: subtract the super length, add this one.
		segTCPLen := uint32(len(seg) - 20)
		rebased := foldChecksum(seed + (^superTCPLen & 0xffff) + segTCPLen)
		binary.BigEndian.PutUint16(seg[36:38], rebased)
		binary.BigEndian.PutUint16(seg[36:38], ^foldChecksum(onesSum(seg[20:], 0)))
		out = append(out, seg)
		seq += uint32(end - off)
		id++
	}
	return out
}

func gsoTestRun(n, mss, lastPayload int, opts []byte) [][]byte {
	var pkts [][]byte
	seq := uint32(1_000_000)
	for i := 0; i < n; i++ {
		size, flags := mss, byte(tcpFlagACK)
		if i == n-1 {
			size, flags = lastPayload, tcpFlagACK|tcpFlagPSH
		}
		payload := bytes.Repeat([]byte{byte(i + 1)}, size)
		pkts = append(pkts, gsoTestSegment(seq, uint16(4000+i), flags, payload, opts))
		seq += uint32(size)
	}
	return pkts
}

// A bulk run coalesces into one frame, and the kernel's segmentation of that
// frame gives back every original packet byte for byte, checksums included.
func TestGSOCoalescedRunSegmentsBackToTheOriginals(t *testing.T) {
	ts := []byte{1, 1, 8, 10, 0, 0, 0, 7, 0, 0, 0, 9} // NOP NOP timestamps
	for _, tc := range []struct {
		name         string
		n, mss, last int
		opts         []byte
	}{
		{"16 full segments, short last", 16, 1321, 700, ts},
		{"2 segments", 2, 1321, 1321, ts},
		{"no options, 49 segments", 49, 1333, 1333, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkts := gsoTestRun(tc.n, tc.mss, tc.last, tc.opts)
			if run := gsoRun(pkts); run != tc.n {
				t.Fatalf("gsoRun = %d, want %d", run, tc.n)
			}
			buf := make([]byte, vnetHdrLen+gsoMaxIPTotal)
			segs := kernelSegment(t, buildGSO(pkts, buf))
			if len(segs) != len(pkts) {
				t.Fatalf("segmented into %d, want %d", len(segs), len(pkts))
			}
			for i := range pkts {
				if !bytes.Equal(segs[i], pkts[i]) {
					t.Fatalf("segment %d differs from the original packet:\n got %x\nwant %x", i, segs[i][:44], pkts[i][:44])
				}
			}
		})
	}
}

// Every packet that must not be merged ends the run, so it is written alone
// and the original order is kept.
func TestGSORunStopsAtEveryUnmergeablePacket(t *testing.T) {
	base := func() [][]byte { return gsoTestRun(4, 1321, 1321, nil) }
	cases := map[string]func(p [][]byte){
		"sequence gap":        func(p [][]byte) { binary.BigEndian.PutUint32(p[2][24:28], 1) },
		"different port":      func(p [][]byte) { p[2][22] ^= 1 },
		"different ack":       func(p [][]byte) { p[2][31] ^= 1 },
		"different window":    func(p [][]byte) { p[2][35] ^= 1 },
		"IP ID not +1":        func(p [][]byte) { p[2][5] ^= 0x40 },
		"SYN flag":            func(p [][]byte) { p[2][33] |= 0x02 },
		"FIN flag":            func(p [][]byte) { p[2][33] |= 0x01 },
		"different TTL":       func(p [][]byte) { p[2][8]-- },
		"different TOS":       func(p [][]byte) { p[2][1] = 0x02 },
		"fragment":            func(p [][]byte) { binary.BigEndian.PutUint16(p[2][6:8], ipv4FlagMF) },
		"UDP":                 func(p [][]byte) { p[2][9] = 17 },
		"IP options":          func(p [][]byte) { p[2][0] = 0x46 },
		"larger than the MSS": func(p [][]byte) { p[2] = append(p[2], 0); binary.BigEndian.PutUint16(p[2][2:4], uint16(len(p[2]))) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := base()
			mutate(p)
			if run := gsoRun(p); run != 2 {
				t.Fatalf("gsoRun = %d, want 2 (stop before the changed packet)", run)
			}
		})
	}
	t.Run("PSH ends the run after itself", func(t *testing.T) {
		p := base()
		p[1][33] = tcpFlagACK | tcpFlagPSH
		if run := gsoRun(p); run != 2 {
			t.Fatalf("gsoRun = %d, want 2", run)
		}
	})
	t.Run("a first packet with PSH or no payload is written alone", func(t *testing.T) {
		p := base()
		p[0][33] = tcpFlagACK | tcpFlagPSH
		if gsoRun(p) != 1 {
			t.Fatal("PSH first packet was merged")
		}
		ack := gsoTestSegment(5, 1, tcpFlagACK, nil, nil)
		if gsoRun([][]byte{ack, ack}) != 1 {
			t.Fatal("pure ACKs were merged")
		}
	})
	t.Run("the 64 KiB IP limit", func(t *testing.T) {
		p := gsoTestRun(60, 1321, 1321, nil)
		run := gsoRun(p)
		if total := 40 + run*1321; total > gsoMaxIPTotal || run < 2 {
			t.Fatalf("run %d makes a %d-byte IP packet", run, total)
		}
		if 40+(run+1)*1321 <= gsoMaxIPTotal {
			t.Fatalf("run %d stopped before the limit", run)
		}
	})
}
