package carrier

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"
)

// awgInnerDatagramTrace is a representative AmneziaWG datagram-length trace for
// one short session: handshake initiation and response, a cookie-sized reply,
// keepalives, and transport datagrams carrying everything from a bare TCP ACK
// to a full-size inner packet.
//
// The exact lengths do not matter. What matters is that they are *distinct*:
// with padding off, every one of them appears on the wire as itself plus the
// 16-byte envelope header, so an observer who can count bytes reads the inner
// datagram length exactly.
var awgInnerDatagramTrace = []int{
	148, 92, 64, 32, 32, 60, 88, 128, 214, 342,
	576, 830, 1100, 1200, 1350, 1350, 96, 32,
}

const (
	traceMaxInnerDatagram = 1350
	traceMaxOuterDatagram = traceMaxInnerDatagram + envelopeHeaderSize
)

// TestDefaultEnvelopeConfigDoesNotLeakInnerLengths is the regression test for
// the review's second high finding: length padding was off unless a caller
// explicitly asked for it, so the default configuration leaked inner datagram
// lengths one-to-one.
//
// The configuration below says nothing about padding. That is the point: a
// carrier built from a configuration that never mentions padding must still
// pad. Leaking exact lengths has to be something somebody wrote down.
func TestDefaultEnvelopeConfigDoesNotLeakInnerLengths(t *testing.T) {
	observed := writeTraceThroughEnvelope(t, EnvelopeConfig{
		MaxInnerDatagram: traceMaxInnerDatagram,
		MaxOuterDatagram: traceMaxOuterDatagram,
	})
	assertTraceIsPadded(t, observed)
}

// TestZeroValueCarrierDialersPadLengths pins the same property one layer up.
//
// datapath.OpenWithCarrier takes a caller-constructed dialer, so a host that
// builds an H3Dialer or H2Dialer and never mentions padding decides the wire
// behaviour of every user it serves. The zero value has to be the safe one.
func TestZeroValueCarrierDialersPadLengths(t *testing.T) {
	for name, config := range map[string]EnvelopeConfig{
		"h3": (&H3Dialer{}).envelopeConfig(
			traceMaxInnerDatagram, traceMaxOuterDatagram,
		),
		"h2": (&H2Dialer{}).envelopeConfig(
			traceMaxInnerDatagram, traceMaxOuterDatagram,
		),
	} {
		t.Run(name, func(t *testing.T) {
			assertTraceIsPadded(t, writeTraceThroughEnvelope(t, config))
		})
	}
}

// TestExplicitlyDisabledPaddingStillLeaks documents, rather than defends, the
// remaining opt-out. -privacy-profile=standard still puts true lengths on the
// wire; it now takes an explicit flag to get there. If that opt-out is ever
// removed this test is the one to delete.
func TestExplicitlyDisabledPaddingStillLeaks(t *testing.T) {
	observed := writeTraceThroughEnvelope(t, EnvelopeConfig{
		MaxInnerDatagram:     traceMaxInnerDatagram,
		MaxOuterDatagram:     traceMaxOuterDatagram,
		DisableLengthPadding: true,
	})
	for index, size := range observed {
		if want := awgInnerDatagramTrace[index] + envelopeHeaderSize; size != want {
			t.Fatalf(
				"datagram %d wire size = %d, want the unpadded %d",
				index, size, want,
			)
		}
	}
}

// TestPaddedSizeFallsThroughToMaximum pins the fall-through that makes padding
// mean anything for bulk traffic. The shipped MaxOuterDatagram is 1366, so
// every bucket from 1400 up is out of range and a full-size datagram matches no
// bucket at all. Returning the true length there would have left exactly the
// datagrams that carry payload unpadded.
func TestPaddedSizeFallsThroughToMaximum(t *testing.T) {
	buckets := defaultPaddingBuckets()
	if got := paddedSize(1300, buckets, traceMaxOuterDatagram); got != traceMaxOuterDatagram {
		t.Fatalf(
			"paddedSize(1300) = %d, want the %d maximum rather than the true length",
			got, traceMaxOuterDatagram,
		)
	}
	if got := paddedSize(200, buckets, traceMaxOuterDatagram); got != 256 {
		t.Fatalf("paddedSize(200) = %d, want the 256 bucket", got)
	}
	// A minimum above the maximum has no padded representation and must be
	// reported as itself so the caller's own size check rejects it.
	if got := paddedSize(2000, buckets, traceMaxOuterDatagram); got != 2000 {
		t.Fatalf("paddedSize(2000) = %d, want the unpaddable length itself", got)
	}
}

// TestBothDirectionsShareOnePaddingLadder guards the asymmetry that would undo
// the defence: padding the client's datagrams while the gateway's replies keep
// their true lengths leaves the leak intact in the other direction.
func TestBothDirectionsShareOnePaddingLadder(t *testing.T) {
	for _, inner := range awgInnerDatagramTrace {
		minimum := inner + envelopeHeaderSize
		client := paddedSize(
			minimum, defaultPaddingBuckets(), traceMaxOuterDatagram,
		)
		server := privacyBucket(minimum, traceMaxOuterDatagram)
		if client != server {
			t.Fatalf(
				"inner %d: client pads to %d, gateway pads to %d",
				inner, client, server,
			)
		}
	}
}

// TestMTUProbeIsNotADistinctSizeClassByDefault ties the two high findings
// together. Path-MTU discovery has to put a full-size datagram on the wire at
// setup; what it must not do is make that datagram a size an observer sees
// nowhere else. With padding on by default, the discovery datagram is exactly
// the size a full-size data datagram already uses.
//
// This does not make discovery invisible. It removes the size discriminator; a
// setup-time exchange is still there to be counted.
func TestMTUProbeIsNotADistinctSizeClassByDefault(t *testing.T) {
	clientRaw, serverRaw := memoryPacketPair()
	client, err := newEnvelopePacketConn(clientRaw, EnvelopeConfig{
		MaxInnerDatagram: traceMaxInnerDatagram,
		MaxOuterDatagram: traceMaxOuterDatagram,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer serverRaw.Close()

	var (
		arrivalsMu sync.Mutex
		probeSizes []int
		dataSizes  []int
	)
	go func() {
		buffer := make([]byte, AbsoluteMaxCarrierEnvelope+1)
		for {
			count, _, readErr := serverRaw.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			frame, decodeErr := decodeEnvelope(
				buffer[:count], traceMaxInnerDatagram,
			)
			if decodeErr != nil {
				continue
			}
			arrivalsMu.Lock()
			switch frame.kind {
			case envelopeProbe:
				probeSizes = append(probeSizes, count)
			case envelopeData:
				dataSizes = append(dataSizes, count)
			}
			arrivalsMu.Unlock()
			if frame.kind != envelopeProbe {
				continue
			}
			ack, encodeErr := encodeEnvelope(
				envelopeProbeAck, frame.sequence, nil, count,
			)
			if encodeErr != nil {
				continue
			}
			_, _ = serverRaw.WriteTo(ack, nil)
			clear(ack)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := client.ProbeMTU(ctx); err != nil {
		t.Fatal(err)
	}
	// A full-size datagram and a small one, so the comparison covers both ends
	// of the ladder.
	for _, length := range []int{traceMaxInnerDatagram, 84} {
		if _, err := client.WriteTo(
			bytes.Repeat([]byte{0x5a}, length), nil,
		); err != nil {
			t.Fatal(err)
		}
	}
	// The data writes are synchronous through the memory pair, but the server
	// goroutine records them; wait for both to land.
	deadline := time.Now().Add(time.Second)
	for {
		arrivalsMu.Lock()
		landed := len(dataSizes)
		arrivalsMu.Unlock()
		if landed >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}

	arrivalsMu.Lock()
	probes := append([]int(nil), probeSizes...)
	data := append([]int(nil), dataSizes...)
	arrivalsMu.Unlock()

	if len(probes) == 0 || len(data) < 2 {
		t.Fatalf("observed %d probes and %d data datagrams", len(probes), len(data))
	}
	if count := len(probes); count > mtuProbeTransmissions {
		t.Fatalf(
			"discovery sent %d datagrams, want at most %d",
			count, mtuProbeTransmissions,
		)
	}
	allowed := allowedWireSizes()
	for _, size := range probes {
		if !slices.Contains(allowed, size) {
			t.Fatalf(
				"discovery datagram size %d is not a size ordinary data "+
					"occupies: allowed %v",
				size, allowed,
			)
		}
		if size != data[0] {
			t.Fatalf(
				"discovery datagram is %d bytes but a full-size data "+
					"datagram is %d: discovery has a size of its own",
				size, data[0],
			)
		}
	}
}

func writeTraceThroughEnvelope(t *testing.T, config EnvelopeConfig) []int {
	t.Helper()
	raw := newRecordingDeadlinePacketConn()
	connection, err := newEnvelopePacketConn(raw, config)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	for _, length := range awgInnerDatagramTrace {
		payload := bytes.Repeat([]byte{0x5a}, length)
		if count, err := connection.WriteTo(payload, nil); err != nil ||
			count != length {
			t.Fatalf("write of %d bytes = %d, %v", length, count, err)
		}
	}
	return raw.Sizes()
}

func assertTraceIsPadded(t *testing.T, observed []int) {
	t.Helper()
	if len(observed) != len(awgInnerDatagramTrace) {
		t.Fatalf(
			"observed %d datagrams, want %d",
			len(observed), len(awgInnerDatagramTrace),
		)
	}
	allowed := allowedWireSizes()
	for index, size := range observed {
		if !slices.Contains(allowed, size) {
			t.Fatalf(
				"datagram %d (inner %d) went out at %d, which is not a "+
					"padding bucket: allowed %v",
				index, awgInnerDatagramTrace[index], size, allowed,
			)
		}
	}
	distinctInner := len(distinct(awgInnerDatagramTrace))
	distinctOuter := len(distinct(observed))
	t.Log(wireSizeReport(observed))
	if distinctOuter >= distinctInner {
		t.Fatalf(
			"observer sees %d distinct wire sizes for %d distinct inner "+
				"lengths: padding is not collapsing anything",
			distinctOuter, distinctInner,
		)
	}
	// The property that actually matters is that the map from wire size back to
	// inner length is not one-to-one. Counting distinct values is a proxy; this
	// checks it directly.
	byWireSize := make(map[int]map[int]struct{})
	for index, size := range observed {
		if byWireSize[size] == nil {
			byWireSize[size] = make(map[int]struct{})
		}
		byWireSize[size][awgInnerDatagramTrace[index]] = struct{}{}
	}
	ambiguous := 0
	for _, inners := range byWireSize {
		if len(inners) > 1 {
			ambiguous++
		}
	}
	if ambiguous == 0 {
		t.Fatal(
			"every wire size maps back to exactly one inner length: an " +
				"observer still reads inner datagram lengths one-to-one",
		)
	}
}

// allowedWireSizes is the ladder a padded datagram may legally occupy: the
// configured buckets that fit inside the carrier limit, plus the limit itself
// for datagrams no bucket covers.
func allowedWireSizes() []int {
	allowed := []int{traceMaxOuterDatagram}
	for _, bucket := range defaultPaddingBuckets() {
		if bucket <= traceMaxOuterDatagram {
			allowed = append(allowed, bucket)
		}
	}
	slices.Sort(allowed)
	return slices.Compact(allowed)
}

func distinct(values []int) []int {
	unique := append([]int(nil), values...)
	slices.Sort(unique)
	return slices.Compact(unique)
}

// wireSizeReport is the before/after measurement quoted in the review response:
// what an observer counting bytes actually sees, and what the padding costs.
func wireSizeReport(observed []int) string {
	var report bytes.Buffer
	innerTotal, outerTotal := 0, 0
	for index, size := range observed {
		innerTotal += awgInnerDatagramTrace[index]
		outerTotal += size
	}
	unpaddedTotal := innerTotal + envelopeHeaderSize*len(awgInnerDatagramTrace)
	fmt.Fprintf(
		&report,
		"\n  inner lengths (%d distinct): %v"+
			"\n  wire sizes    (%d distinct): %v"+
			"\n  bytes on the wire: %d padded vs %d unpadded (%.1f%% overhead)",
		len(distinct(awgInnerDatagramTrace)), distinct(awgInnerDatagramTrace),
		len(distinct(observed)), distinct(observed),
		outerTotal, unpaddedTotal,
		100*float64(outerTotal-unpaddedTotal)/float64(unpaddedTotal),
	)
	return report.String()
}
