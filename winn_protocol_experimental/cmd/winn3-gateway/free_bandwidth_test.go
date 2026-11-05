package main

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFreeBandwidthEnvelopeBothDirections(t *testing.T) {
	const rate = 12500000
	burst := freeBandwidthBurstBytes(100)
	start := time.Unix(1000, 0)
	p := &peerBandwidth{}
	for _, b := range []*byteBucket{&p.up, &p.down} {
		b.rate, b.burst, b.credit, b.last = rate, burst, float64(burst), start
	}
	for direction, bucket := range []*byteBucket{&p.up, &p.down} {
		accepted := 0
		for step := 0; step <= 20000; step++ {
			now := start.Add(time.Duration(step) * 100 * time.Microsecond)
			for attempt := 0; attempt < 10; attempt++ {
				if bucket.allowAt(1373, now) {
					accepted += 1373
				}
			}
			bound := int(int64(now.Sub(start))*rate/int64(time.Second)) + burst
			if accepted > bound {
				t.Fatalf("direction %d: %d bytes exceeds %d at %s", direction, accepted, bound, now.Sub(start))
			}
		}
		if accepted < 2*rate {
			t.Fatalf("direction %d: limiter wasted capacity: %d", direction, accepted)
		}
	}
}

func TestFreeBandwidthBurstIsOneHundredMillisecondsOfTheRate(t *testing.T) {
	for _, tc := range []struct{ mbps, want int }{{1, 12500}, {100, 1250000}, {100000, 67108864}} {
		if got := freeBandwidthBurstBytes(tc.mbps); got != tc.want {
			t.Fatalf("freeBandwidthBurstBytes(%d) = %d, want %d", tc.mbps, got, tc.want)
		}
	}
}

func TestFreeBandwidthBurstAndClockRegression(t *testing.T) {
	burst := freeBandwidthBurstBytes(100)
	start := time.Unix(1000, 0)
	b := byteBucket{rate: 12500000, burst: burst, credit: float64(burst), last: start}
	if !b.allowAt(burst, start) || b.allowAt(1, start) {
		t.Fatal("initial burst was not exactly bounded")
	}
	if b.allowAt(1, start.Add(-time.Hour)) || b.allowAt(burst+1, start.Add(time.Hour)) {
		t.Fatal("clock regression or oversize packet minted credit")
	}
	if b.allowAt(0, start) || b.allowAt(-1, start) {
		t.Fatal("invalid size accepted")
	}
}

// withTier names a tier on every entry of a registry body whose entries carry
// none, which is how the hub writes a paid peer: the word is optional and
// absence means premium.
func withTier(body, tier string) string {
	return strings.ReplaceAll(body, `{"static_public"`, `{"tier":"`+tier+`","static_public"`)
}

func freeAuthority(t *testing.T) *authorityFixture {
	t.Helper()
	f := newAuthorityFixture(t, 0)
	f.body = withTier(f.body, "free")
	replaceAuthority(t, f.registry.path, f.body)
	if err := f.registry.reload(); err != nil {
		t.Fatal(err)
	}
	return f
}

func freezeBandwidth(p *peerBandwidth) {
	for _, b := range []*byteBucket{&p.up, &p.down} {
		b.mu.Lock()
		b.last = time.Now().Add(time.Hour)
		b.mu.Unlock()
	}
}

func TestFreeBandwidthForwardingBothDirections(t *testing.T) {
	f := freeAuthority(t)
	binding, ok := f.registry.policyForPeer(f.key)
	if !ok || binding.bandwidth == nil {
		t.Fatal("free authenticated key lacks a budget")
	}
	freezeBandwidth(binding.bandwidth)
	burst := freeBandwidthBurstBytes(100)
	pkt := ipv4Packet(t, f.addr.String(), "8.8.8.8")
	before := len(f.writer.written)
	for i := 0; i < burst/len(pkt)+100; i++ {
		if n, err := f.device.WritePacket(pkt); n != len(pkt) || err != nil {
			t.Fatalf("policing tore down the session: %d %v", n, err)
		}
	}
	if got := (len(f.writer.written) - before) * len(pkt); got > burst || got < burst-len(pkt) {
		t.Fatalf("upload admitted %d bytes", got)
	}
	accepted := 0
	for i := 0; i < burst/len(pkt)+100; i++ {
		if _, ok := f.table.lookupPacket(f.addr, len(pkt)); ok {
			accepted += len(pkt)
		}
	}
	if accepted > burst || accepted < burst-len(pkt) {
		t.Fatalf("download admitted %d bytes", accepted)
	}
}

func TestFreeBandwidthReconnectRetainsCredit(t *testing.T) {
	f := freeAuthority(t)
	before, _ := f.registry.policyForPeer(f.key)
	freezeBandwidth(before.bandwidth)
	if !before.bandwidth.allow(freeBandwidthBurstBytes(100), false) {
		t.Fatal("could not consume upload burst")
	}
	loop := f.newPeerLoop(t)
	dev := newGatewayForwardDevice(f.writer, f.table, 1400, f.registry)
	dev.bind(loop)
	t.Cleanup(func() { _ = dev.Close() })
	after, _ := f.registry.policyForPeer(f.key)
	if after.bandwidth != before.bandwidth {
		t.Fatal("handshake reload reset the per-key bucket")
	}
	count := len(f.writer.written)
	pkt := ipv4Packet(t, f.addr.String(), "8.8.8.8")
	if _, err := dev.WritePacket(pkt); err != nil || len(f.writer.written) != count {
		t.Fatal("reconnect bypassed upload policing")
	}
	if dev.allowSourcePacket(f.addr, len(pkt), false) {
		t.Fatal("resolver bypassed the exhausted upload budget")
	}
	if !dev.allowSourcePacket(f.addr, len(pkt), true) {
		t.Fatal("upload exhausted the independent download budget")
	}
}

func TestFreeBandwidthPaidAndDisabledUnaffected(t *testing.T) {
	f := newAuthorityFixture(t, 0)
	binding, ok := f.registry.policyForPeer(f.key)
	if !ok || binding.bandwidth != nil {
		t.Fatal("premium peer acquired a limiter")
	}
	pkt := ipv4Packet(t, f.addr.String(), "8.8.8.8")
	before := len(f.writer.written)
	for i := 0; i < 10000; i++ {
		if _, err := f.device.WritePacket(pkt); err != nil {
			t.Fatal(err)
		}
		if _, ok := f.table.lookupPacket(f.addr, len(pkt)); !ok {
			t.Fatal("paid download was policed")
		}
	}
	if len(f.writer.written)-before != 10000 {
		t.Fatal("paid upload was policed")
	}
	body := withTier(f.body, "free")
	r, err := newPeerRegistryWithRate(writeRegistry(t, body), f.registry.prefix, 0)
	if err != nil {
		t.Fatal(err)
	}
	disabled, ok := r.policyForPeer(f.key)
	if !ok || disabled.bandwidth != nil || newPeerBandwidth(0) != nil {
		t.Fatal("explicit zero did not disable policing")
	}
	for _, invalid := range []int{-1, 100001} {
		if _, err := newPeerRegistryWithRate(r.path, r.prefix, invalid); err == nil {
			t.Fatal("invalid rate accepted")
		}
	}
}

func TestFreeBandwidthTierCannotBeForged(t *testing.T) {
	f := freeAuthority(t)
	unknown, _ := registryKey(0x91)
	if err := f.registry.authorize(unknown); err == nil {
		t.Fatal("unregistered client key forged admission")
	}
	for _, tier := range []string{`"paid"`, `"Free"`, `""`, `true`, `null`, `100`} {
		body := strings.ReplaceAll(f.body, `"tier":"free"`, `"tier":`+tier)
		if _, err := newPeerRegistry(writeRegistry(t, body), f.registry.prefix); err == nil {
			t.Fatalf("accepted forged tier %s", tier)
		}
	}
	// The word is optional: an entry that omits it is premium, admitted and
	// uncapped, which is the hub's document from before the field existed.
	missing := strings.ReplaceAll(f.body, `"tier":"free",`, "")
	withoutTier, err := newPeerRegistry(writeRegistry(t, missing), f.registry.prefix)
	if err != nil {
		t.Fatalf("omitted tier refused: %v", err)
	}
	binding, ok := withoutTier.policyForPeer(f.key)
	if !ok || binding.bandwidth != nil {
		t.Fatal("omitted tier did not answer premium")
	}
	// Only the one registry version exists. A second version would be a
	// second decoder surface, and an older gateway refuses it whole.
	versioned := strings.Replace(f.body, `"version":1`, `"version":2`, 1)
	if _, err := newPeerRegistry(writeRegistry(t, versioned), f.registry.prefix); err == nil {
		t.Fatal("accepted a version 2 document")
	}
}

func TestFreeBandwidthServerSwitchStillLimited(t *testing.T) {
	f := freeAuthority(t)
	body := strings.ReplaceAll(f.body, "10.10.0.2", "10.10.0.3")
	r, err := newPeerRegistry(writeRegistry(t, body), f.registry.prefix)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := r.policyForPeer(f.key)
	if !ok || p.addr.String() != "10.10.0.3" || p.bandwidth == nil {
		t.Fatal("destination gateway lost the plan on server switch")
	}
	freezeBandwidth(p.bandwidth)
	for _, down := range []bool{false, true} {
		if !p.bandwidth.allow(freeBandwidthBurstBytes(100), down) || p.bandwidth.allow(1, down) {
			t.Fatal("destination gateway did not enforce its bounded burst")
		}
	}
}

func TestFreeBandwidthDifferentKeysIndependent(t *testing.T) {
	first, encodedFirst := registryKey(1)
	second, encodedSecond := registryKey(2)
	body := fmt.Sprintf(`{"version":1,"peers":[{"tier":"free","static_public":%q,"inner_v4":"10.10.0.2","not_after":0},{"tier":"free","static_public":%q,"inner_v4":"10.10.0.3","not_after":0}]}`, encodedFirst, encodedSecond)
	r, err := newPeerRegistry(writeRegistry(t, body), netip.MustParsePrefix("10.10.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	a, okA := r.policyForPeer(first)
	b, okB := r.policyForPeer(second)
	if !okA || !okB || a.bandwidth == nil || b.bandwidth == nil || a.bandwidth == b.bandwidth {
		t.Fatal("two free devices share a bucket")
	}
	freezeBandwidth(a.bandwidth)
	freezeBandwidth(b.bandwidth)
	for _, down := range []bool{false, true} {
		if !a.bandwidth.allow(freeBandwidthBurstBytes(100), down) || a.bandwidth.allow(1, down) {
			t.Fatal("first key was not independently capped")
		}
		if !b.bandwidth.allow(freeBandwidthBurstBytes(100), down) || b.bandwidth.allow(1, down) {
			t.Fatal("exhausting the first free key affected the second")
		}
	}
}

func TestFreeBandwidthConcurrentDirections(t *testing.T) {
	p := newPeerBandwidth(100)
	freezeBandwidth(p)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(down bool) {
			defer wg.Done()
			for n := 0; n < 1000; n++ {
				p.allow(1373, down)
			}
		}(i%2 == 0)
	}
	wg.Wait()
	if p.up.credit < 0 || p.down.credit < 0 {
		t.Fatal("concurrent sends borrowed future credit")
	}
}

func TestFreeBandwidthDNSOnlySessionBothDirections(t *testing.T) {
	f := freeAuthority(t)
	table := newForwardTable()
	dev := newGatewayForwardDevice(f.writer, table, 1400, f.registry)
	dev.bind(f.newPeerLoop(t))
	res := newGatewayResolver(netip.MustParseAddr("10.10.0.1"), netip.MustParseAddrPort("127.0.0.1:1"), time.Second, 1)
	dns := newResolverDevice(dev, res, 1400)
	t.Cleanup(func() { _ = dns.Close() })
	binding, _ := f.registry.policyForPeer(f.key)
	freezeBandwidth(binding.bandwidth)
	if !binding.bandwidth.allow(freeBandwidthBurstBytes(100), false) {
		t.Fatal("could not exhaust upload budget")
	}
	query := udpPacket(t, f.addr, res.ours, 1234, dnsPort, dnsQueryBytes(9))
	if n, err := dns.WritePacket(query); n != len(query) || err != nil {
		t.Fatalf("DNS policing changed the device contract: %d %v", n, err)
	}
	if table.Stats().FreeDroppedUp != 1 || dev.owned.IsValid() || table.Stats().Size != 0 {
		t.Fatal("DNS-only upload escaped policing or learned a forwarding address")
	}
	q := dnsQuery{client: f.addr, clientPort: 1234}
	reply := res.buildReply(q, dnsQueryBytes(9))
	oversize := append(bytes.Clone(reply), 0)
	binding.bandwidth.down.mu.Lock()
	binding.bandwidth.down.credit = float64(len(reply))
	binding.bandwidth.down.mu.Unlock()
	if dns.queueReply(q, oversize) != replyQueued || dns.queueReply(q, reply) != replyQueued {
		t.Fatal("could not queue DNS replies")
	}
	buf := make([]byte, 1400)
	n, err := dns.ReadPacket(buf)
	if err != nil || !bytes.Equal(buf[:n], reply) || table.Stats().FreeDroppedDown != 1 {
		t.Fatalf("DNS-only download escaped policing: %d %v %+v", n, err, table.Stats())
	}
}

func TestFreeBandwidthDropCountersDistinguishAuthority(t *testing.T) {
	f := freeAuthority(t)
	binding, _ := f.registry.policyForPeer(f.key)
	freezeBandwidth(binding.bandwidth)
	if !binding.bandwidth.allow(freeBandwidthBurstBytes(100), true) {
		t.Fatal("could not exhaust download budget")
	}
	if _, ok, capped := f.table.lookupPacketDecision(f.addr, 20); ok || !capped {
		t.Fatal("cap refusal classified as unknown destination")
	}
	if _, ok, capped := f.table.lookupPacketDecision(netip.MustParseAddr("10.10.0.99"), 20); ok || capped {
		t.Fatal("unknown destination classified as policing")
	}
	if f.table.Stats().FreeDroppedDown != 1 {
		t.Fatal("cap drop counter missing")
	}
}

func TestFreeBandwidthFeatureProbe(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"-mode", "features"}, &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "peer-registry-tier\n" {
		t.Fatalf("unexpected features: %q", out.String())
	}
}

var freecapBenchmarkSink bool

func BenchmarkFreecapAuthorization(b *testing.B) {
	for _, name := range []string{"paid", "paid-cap-off", "free"} {
		b.Run(name, func(b *testing.B) {
			tier, rate := "", 100
			switch name {
			case "free":
				tier = `"tier":"free",`
			case "paid-cap-off":
				rate = 0
			}
			key, encoded := registryKey(0x92)
			body := fmt.Sprintf(`{"version":1,"peers":[{%s"static_public":%q,"inner_v4":"10.10.0.2","not_after":0}]}`, tier, encoded)
			path := filepath.Join(b.TempDir(), "peers.json")
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				b.Fatal(err)
			}
			r, err := newPeerRegistryWithRate(path, netip.MustParsePrefix("10.10.0.0/24"), rate)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				binding, ok := r.policyForPeer(key)
				freecapBenchmarkSink = ok && binding.bandwidth.allow(1373, i%2 != 0)
			}
		})
	}
}
