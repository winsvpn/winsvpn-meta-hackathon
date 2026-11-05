package datapath

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// awgFillerByte fills the prefix padding and the message body of every
// synthetic frame below. Real AmneziaWG prefix padding is rand.Read output; a
// fixed byte is used here so a failure is reproducible, and 0xAA specifically
// because the word it forms, 0xAAAAAAAA, is not a header value in any profile
// under test. A filler that collided with one would make a case pass or fail
// for a reason its name does not mention.
const awgFillerByte = 0xAA

// awgPrefixPaddedFrame builds an AmneziaWG-shaped frame: prefix bytes of
// filler, then the little-endian header word, then filler out to size. This is
// the layout upstream produces — rand.Read over buf[:padding], then the header
// serialised at buf[padding:].
//
// A size smaller than prefix+4 truncates, which is deliberate: that is exactly
// the short-datagram case the bounds check has to survive, and building it this
// way keeps the boundary cases in the table honest about what they truncate.
func awgPrefixPaddedFrame(prefix int, word uint32, size int) []byte {
	full := prefix + 4
	if size > full {
		full = size
	}
	frame := make([]byte, full)
	for index := range frame {
		frame[index] = awgFillerByte
	}
	binary.LittleEndian.PutUint32(frame[prefix:prefix+4], word)
	if size < len(frame) {
		return frame[:size]
	}
	return frame
}

// awgWordAt places one header word at one offset.
type awgWordAt struct {
	offset int
	word   uint32
}

// awgFrameWithWordsAt is the adversarial builder: a frame carrying several
// header words at several offsets at once, so a case can assert which one the
// classifier is required to honour.
func awgFrameWithWordsAt(size int, words ...awgWordAt) []byte {
	frame := make([]byte, size)
	for index := range frame {
		frame[index] = awgFillerByte
	}
	for _, placed := range words {
		binary.LittleEndian.PutUint32(
			frame[placed.offset:placed.offset+4], placed.word,
		)
	}
	return frame
}

// The profiles under test.
//
// shippingProfile carries the values lib/main.dart actually ships — H1..H4 of
// 11, 22, 33, 44 and S1=16, S2=80, S3=16, S4=0 — because that is the exact
// configuration the device A/B ran under and the one no handshake could be
// classified beneath.
//
// obfuscatedProfile carries the same padding with header values in the shape a
// signed deployment produces: large, arbitrary, and nothing like 1..4.
//
// zeroedProfile is the same header values with every padding size zero, the
// second arm of the device A/B.
var (
	shippingProfile = AWGHeaderTypes{
		H1: AwgHeaderSpec{Start: 11, End: 11}, H2: AwgHeaderSpec{Start: 22, End: 22}, H3: AwgHeaderSpec{Start: 33, End: 33}, H4: AwgHeaderSpec{Start: 44, End: 44},
		S1: 16, S2: 80, S3: 16, S4: 0,
	}
	obfuscatedProfile = AWGHeaderTypes{
		H1: AwgHeaderSpec{Start: 0x51F3A2C4, End: 0x51F3A2C4}, H2: AwgHeaderSpec{Start: 0x1B77E90D, End: 0x1B77E90D}, H3: AwgHeaderSpec{Start: 0x9C40B215, End: 0x9C40B215}, H4: AwgHeaderSpec{Start: 0x2E8D6F31, End: 0x2E8D6F31},
		S1: 16, S2: 80, S3: 16, S4: 0,
	}
	zeroedProfile = AWGHeaderTypes{
		H1: AwgHeaderSpec{Start: 0x51F3A2C4, End: 0x51F3A2C4}, H2: AwgHeaderSpec{Start: 0x1B77E90D, End: 0x1B77E90D}, H3: AwgHeaderSpec{Start: 0x9C40B215, End: 0x9C40B215}, H4: AwgHeaderSpec{Start: 0x2E8D6F31, End: 0x2E8D6F31},
	}
	// paddedTransportProfile is the shipping profile with the transport prefix
	// TURNED ON, which nothing in the field runs: lib/main.dart ships S4=0.
	// Every case built on it is unit evidence about the classifier and is NOT
	// evidence about any device. S4=24 is chosen to differ from S1, S2 and S3
	// so that a case cannot pass by reading the right word at the wrong class's
	// offset.
	paddedTransportProfile = AWGHeaderTypes{
		H1: AwgHeaderSpec{Start: 11, End: 11}, H2: AwgHeaderSpec{Start: 22, End: 22}, H3: AwgHeaderSpec{Start: 33, End: 33}, H4: AwgHeaderSpec{Start: 44, End: 44},
		S1: 16, S2: 80, S3: 16, S4: 24,
	}
)

// awgKeepaliveFrame builds the official AmneziaWG Go v3 transport keepalive:
// prefix bytes, H4 at that prefix offset, and exactly 32 transport bytes.
func awgKeepaliveFrame(prefix int, word uint32) []byte {
	return awgPrefixPaddedFrame(prefix, word, prefix+awgKeepaliveBytes)
}

// TestClassifyReadsEachClassAtItsOwnPaddedOffset is the unit-level statement of
// the defect and of the fix. Every case names the property it pins; a case that
// changes verdict is a contract change, not a test that needs adjusting.
func TestClassifyReadsEachClassAtItsOwnPaddedOffset(t *testing.T) {
	cases := []struct {
		name     string
		types    AWGHeaderTypes
		datagram []byte
		want     AWGClass
	}{
		// The shipping profile: S1=16, S2=80. Every one of these returned
		// ClassUnknown before the padded offsets were read, which is why
		// tx_handshake_initiations, rx_handshake_responses and
		// handshake_response_observed could never fire on a healthy tunnel.
		{
			name:  "shipping profile classifies a handshake initiation behind its 16-byte prefix",
			types: shippingProfile,
			// 148 is the WireGuard initiation, 16 the prefix in front of it.
			datagram: awgPrefixPaddedFrame(16, shippingProfile.H1.Start, 164),
			want:     ClassHandshakeInitiation,
		},
		{
			name:     "shipping profile classifies a handshake response behind its 80-byte prefix",
			types:    shippingProfile,
			datagram: awgPrefixPaddedFrame(80, shippingProfile.H2.Start, 172),
			want:     ClassHandshakeResponse,
		},
		{
			name:     "shipping profile classifies a cookie reply behind its 16-byte prefix",
			types:    shippingProfile,
			datagram: awgPrefixPaddedFrame(16, shippingProfile.H3.Start, 80),
			want:     ClassCookieReply,
		},
		{
			name:  "shipping profile classifies unpadded transport data at offset zero",
			types: shippingProfile,
			// S4 is 0, so transport data is exactly where it always was. This
			// is the counter that stayed correct on the same tunnel and hid
			// the defect.
			datagram: awgPrefixPaddedFrame(0, shippingProfile.H4.Start, 200),
			want:     ClassTransportData,
		},
		{
			name:     "obfuscated header values classify behind the same prefixes",
			types:    obfuscatedProfile,
			datagram: awgPrefixPaddedFrame(80, obfuscatedProfile.H2.Start, 172),
			want:     ClassHandshakeResponse,
		},

		// Transport must win. This is the property a route-promotion gate
		// depends on, so it is asserted against a datagram built specifically
		// to break it: transport data whose body also carries H1 at the
		// initiation offset and H2 at the response offset.
		{
			name:  "a transport datagram carrying handshake words at the padded offsets is still transport",
			types: shippingProfile,
			datagram: awgFrameWithWordsAt(200,
				awgWordAt{offset: 0, word: shippingProfile.H4.Start},
				awgWordAt{offset: 16, word: shippingProfile.H1.Start},
				awgWordAt{offset: 80, word: shippingProfile.H2.Start},
			),
			want: ClassTransportData,
		},
		{
			name:  "a transport datagram carrying a cookie word at the cookie offset is still transport",
			types: shippingProfile,
			datagram: awgFrameWithWordsAt(200,
				awgWordAt{offset: 0, word: shippingProfile.H4.Start},
				awgWordAt{offset: 16, word: shippingProfile.H3.Start},
			),
			want: ClassTransportData,
		},
		{
			name: "a double match between two padded classes resolves by the documented order",
			// A profile whose cookie replies are unpadded but whose
			// initiations are not. A datagram carrying H3 at offset 0 and H1
			// at offset S1 satisfies both classes at once; the classifier
			// tests initiation before cookie reply, so initiation wins.
			//
			// This case was found by FuzzClassify rather than written from
			// first principles, and it is pinned because the order is a
			// decision: transport is tested first so that it can never lose a
			// double match, and the remaining three are then fixed in
			// initiation, response, cookie order. Nothing about that order is
			// load-bearing for a counter — no counter reads ClassCookieReply —
			// but leaving it unstated would make a future reordering look free.
			types: AWGHeaderTypes{
				H1: AwgHeaderSpec{Start: 0x51F3A2C4, End: 0x51F3A2C4}, H2: AwgHeaderSpec{Start: 0x1B77E90D, End: 0x1B77E90D}, H3: AwgHeaderSpec{Start: 0x9C40B215, End: 0x9C40B215},
				H4: AwgHeaderSpec{Start: 0x2E8D6F31, End: 0x2E8D6F31}, S1: 16, S2: 80, S3: 0, S4: 0,
			},
			datagram: awgFrameWithWordsAt(164,
				awgWordAt{offset: 0, word: 0x9C40B215},
				awgWordAt{offset: 16, word: 0x51F3A2C4},
			),
			want: ClassHandshakeInitiation,
		},
		{
			name:  "the documented collision resolves to transport, not to the handshake",
			types: shippingProfile,
			// A real initiation whose random 16-byte prefix happens to start
			// with H4. Upstream padding is unauthenticated random, so this has
			// probability about 2^-32 rather than zero. The precedence is
			// pinned here so that it is a decision on the record rather than
			// an accident of statement order.
			datagram: awgFrameWithWordsAt(164,
				awgWordAt{offset: 0, word: shippingProfile.H4.Start},
				awgWordAt{offset: 16, word: shippingProfile.H1.Start},
			),
			want: ClassTransportData,
		},

		// Zeroed padding: the other arm of the device A/B, and the proof that
		// the padded offsets are genuinely gated on a nonzero size.
		{
			name:     "zeroed padding classifies a handshake initiation at offset zero",
			types:    zeroedProfile,
			datagram: awgPrefixPaddedFrame(0, zeroedProfile.H1.Start, 148),
			want:     ClassHandshakeInitiation,
		},
		{
			name:     "zeroed padding classifies a handshake response at offset zero",
			types:    zeroedProfile,
			datagram: awgPrefixPaddedFrame(0, zeroedProfile.H2.Start, 92),
			want:     ClassHandshakeResponse,
		},
		{
			name:     "zeroed padding classifies a cookie reply at offset zero",
			types:    zeroedProfile,
			datagram: awgPrefixPaddedFrame(0, zeroedProfile.H3.Start, 64),
			want:     ClassCookieReply,
		},
		{
			name:     "zeroed padding classifies transport data at offset zero",
			types:    zeroedProfile,
			datagram: awgPrefixPaddedFrame(0, zeroedProfile.H4.Start, 200),
			want:     ClassTransportData,
		},
		{
			name:  "zeroed padding ignores a header word sitting at the shipping offset",
			types: zeroedProfile,
			// An unpadded deployment must not start matching bytes 16 deep
			// just because some other deployment pads there.
			datagram: awgPrefixPaddedFrame(16, zeroedProfile.H1.Start, 164),
			want:     ClassUnknown,
		},

		// Plain WireGuard, unchanged in every respect.
		{
			name:     "wireguard defaults classify type 1 as a handshake initiation",
			types:    wireGuardDefaultHeaderTypes,
			datagram: awgPrefixPaddedFrame(0, 1, 148),
			want:     ClassHandshakeInitiation,
		},
		{
			name:     "wireguard defaults classify type 2 as a handshake response",
			types:    wireGuardDefaultHeaderTypes,
			datagram: awgPrefixPaddedFrame(0, 2, 92),
			want:     ClassHandshakeResponse,
		},
		{
			name:     "wireguard defaults classify type 3 as a cookie reply",
			types:    wireGuardDefaultHeaderTypes,
			datagram: awgPrefixPaddedFrame(0, 3, 64),
			want:     ClassCookieReply,
		},
		{
			name:     "wireguard defaults classify type 4 as transport data",
			types:    wireGuardDefaultHeaderTypes,
			datagram: awgPrefixPaddedFrame(0, 4, 200),
			want:     ClassTransportData,
		},
		{
			name:     "wireguard defaults ignore a header word at a padded offset",
			types:    wireGuardDefaultHeaderTypes,
			datagram: awgPrefixPaddedFrame(16, 1, 164),
			want:     ClassUnknown,
		},

		// Junk. AmneziaWG sends Jc of these per handshake and they must stay
		// unclassified under every profile.
		{
			name:     "a junk packet matching nothing is unknown under the shipping profile",
			types:    shippingProfile,
			datagram: awgFrameWithWordsAt(120),
			want:     ClassUnknown,
		},
		{
			name:     "a junk packet matching nothing is unknown under wireguard defaults",
			types:    wireGuardDefaultHeaderTypes,
			datagram: awgFrameWithWordsAt(120),
			want:     ClassUnknown,
		},

		// Short datagrams, at every boundary that exists. None of these may
		// panic and none may index outside the slice.
		{
			name:     "a nil datagram is unknown",
			types:    shippingProfile,
			datagram: nil,
			want:     ClassUnknown,
		},
		{
			name:     "an empty datagram is unknown",
			types:    shippingProfile,
			datagram: []byte{},
			want:     ClassUnknown,
		},
		{
			name:     "one byte is unknown",
			types:    shippingProfile,
			datagram: []byte{awgFillerByte},
			want:     ClassUnknown,
		},
		{
			name:     "three bytes are unknown",
			types:    shippingProfile,
			datagram: []byte{awgFillerByte, awgFillerByte, awgFillerByte},
			want:     ClassUnknown,
		},
		{
			name:  "three bytes of a transport header word are unknown",
			types: shippingProfile,
			// One byte short of the offset-zero boundary.
			datagram: awgPrefixPaddedFrame(0, shippingProfile.H4.Start, 3),
			want:     ClassUnknown,
		},
		{
			name:  "exactly four bytes of a transport header word classify",
			types: shippingProfile,
			// The offset-zero boundary itself.
			datagram: awgPrefixPaddedFrame(0, shippingProfile.H4.Start, 4),
			want:     ClassTransportData,
		},
		{
			name:  "one byte short of s1 plus four is unknown",
			types: shippingProfile,
			// 19 bytes: the full 16-byte prefix and three bytes of H1.
			datagram: awgPrefixPaddedFrame(16, shippingProfile.H1.Start, 19),
			want:     ClassUnknown,
		},
		{
			name:     "exactly s1 plus four classifies as a handshake initiation",
			types:    shippingProfile,
			datagram: awgPrefixPaddedFrame(16, shippingProfile.H1.Start, 20),
			want:     ClassHandshakeInitiation,
		},
		{
			name:     "one byte short of s2 plus four is unknown",
			types:    shippingProfile,
			datagram: awgPrefixPaddedFrame(80, shippingProfile.H2.Start, 83),
			want:     ClassUnknown,
		},
		{
			name:     "exactly s2 plus four classifies as a handshake response",
			types:    shippingProfile,
			datagram: awgPrefixPaddedFrame(80, shippingProfile.H2.Start, 84),
			want:     ClassHandshakeResponse,
		},
		{
			name:  "a datagram shorter than s2 but long enough for s1 still classifies at s1",
			types: shippingProfile,
			// 20 bytes cannot reach the response offset at all. The response
			// test must decline rather than index, and the initiation test
			// must still succeed.
			datagram: awgPrefixPaddedFrame(16, shippingProfile.H1.Start, 20),
			want:     ClassHandshakeInitiation,
		},

		// Nonzero S4. Official AmneziaWG Go v3 pads every transport message,
		// including keepalives, so both transport shapes put H4 at S4.
		{
			name:  "a padded transport datagram classifies behind its s4 prefix",
			types: paddedTransportProfile,
			datagram: awgPrefixPaddedFrame(
				24, paddedTransportProfile.H4.Start, 200,
			),
			want: ClassTransportData,
		},
		{
			name:  "a padded keepalive classifies under a nonzero s4",
			types: paddedTransportProfile,
			datagram: awgKeepaliveFrame(
				int(paddedTransportProfile.S4),
				paddedTransportProfile.H4.Start,
			),
			want: ClassTransportData,
		},
		{
			name:  "a keepalive carrying an initiation word at s1 is still transport",
			types: paddedTransportProfile,
			// Transport runs before handshake classification, so a keepalive
			// whose random prefix happens to hold H1 at S1 cannot be stolen.
			datagram: awgFrameWithWordsAt(24+awgKeepaliveBytes,
				awgWordAt{offset: 16, word: paddedTransportProfile.H1.Start},
				awgWordAt{offset: 24, word: paddedTransportProfile.H4.Start},
			),
			want: ClassTransportData,
		},
		{
			name:  "an unpadded 32-byte h4 frame is rejected under nonzero s4",
			types: paddedTransportProfile,
			datagram: awgPrefixPaddedFrame(
				0, paddedTransportProfile.H4.Start, awgKeepaliveBytes,
			),
			want: ClassUnknown,
		},
		{
			name:  "a padded transport datagram one byte over the padded keepalive length reads at s4",
			types: paddedTransportProfile,
			datagram: awgPrefixPaddedFrame(
				24, paddedTransportProfile.H4.Start, 24+awgKeepaliveBytes+1,
			),
			want: ClassTransportData,
		},
		{
			name:  "a padded handshake response still classifies under a nonzero s4",
			types: paddedTransportProfile,
			// Turning S4 on must not disturb the other three classes.
			datagram: awgPrefixPaddedFrame(
				80, paddedTransportProfile.H2.Start, 172,
			),
			want: ClassHandshakeResponse,
		},
		{
			name:  "a padded transport datagram carrying handshake words at their offsets is still transport",
			types: paddedTransportProfile,
			datagram: awgFrameWithWordsAt(200,
				awgWordAt{offset: 24, word: paddedTransportProfile.H4.Start},
				awgWordAt{offset: 16, word: paddedTransportProfile.H1.Start},
				awgWordAt{offset: 80, word: paddedTransportProfile.H2.Start},
			),
			want: ClassTransportData,
		},
		{
			name:  "one byte short of s4 plus four is unknown",
			types: paddedTransportProfile,
			// 27 bytes: the full 24-byte prefix and three bytes of H4.
			datagram: awgPrefixPaddedFrame(24, paddedTransportProfile.H4.Start, 27),
			want:     ClassUnknown,
		},
		{
			name:     "exactly s4 plus four classifies as transport data",
			types:    paddedTransportProfile,
			datagram: awgPrefixPaddedFrame(24, paddedTransportProfile.H4.Start, 28),
			want:     ClassTransportData,
		},
		{
			name:  "a nonzero s4 does not start matching transport at offset zero",
			types: paddedTransportProfile,
			// The mirror of the zeroed-padding case above: a padded deployment
			// must never read transport at offset 0, or a junk packet starting
			// with H4 would be counted as a transport datagram.
			datagram: awgPrefixPaddedFrame(
				0, paddedTransportProfile.H4.Start, 200,
			),
			want: ClassUnknown,
		},
		{
			name:  "the shipping profile classifies a keepalive at offset zero",
			types: shippingProfile,
			// S4=0, so this is the behaviour that must not have changed: a
			// 32-byte transport message was ClassTransportData before
			// keepalives were named and still is.
			datagram: awgKeepaliveFrame(0, shippingProfile.H4.Start),
			want:     ClassTransportData,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := testCase.types.classify(testCase.datagram)
			if got != testCase.want {
				t.Fatalf("classify(%d bytes) = %v, want %v",
					len(testCase.datagram), got, testCase.want)
			}
		})
	}
}

// offsetZeroOnly is the classifier exactly as it was before the padded offsets
// existed. It is reproduced here rather than called through classify so that a
// future edit to classify cannot silently redefine what "unchanged" means. It
// is the reference both the table test below and FuzzClassify hold unpadded
// profiles to.
func offsetZeroOnly(types AWGHeaderTypes, datagram []byte) AWGClass {
	if len(datagram) < 4 {
		return ClassUnknown
	}
	switch binary.LittleEndian.Uint32(datagram[:4]) {
	case types.H1.Start:
		return ClassHandshakeInitiation
	case types.H2.Start:
		return ClassHandshakeResponse
	case types.H3.Start:
		return ClassCookieReply
	case types.H4.Start:
		return ClassTransportData
	default:
		return ClassUnknown
	}
}

// TestUnpaddedProfilesClassifyIdenticallyToTheOffsetZeroRule proves the
// no-regression property mechanically rather than by inspection: for every
// possible header word, a profile with no padding must reach exactly the
// verdict the original offset-zero-only classifier reached. The word space is
// walked at the four configured values and at a sample of non-matching ones,
// which is the whole of the classifier's behaviour on a 4-byte input.
func TestUnpaddedProfilesClassifyIdenticallyToTheOffsetZeroRule(t *testing.T) {
	profiles := map[string]AWGHeaderTypes{
		"wireguard defaults": wireGuardDefaultHeaderTypes,
		"zeroed padding":     zeroedProfile,
	}
	for name, types := range profiles {
		t.Run(name, func(t *testing.T) {
			words := []uint32{
				types.H1.Start, types.H2.Start, types.H3.Start, types.H4.Start,
				0, 1, 2, 3, 4, 5, 0xAAAAAAAA, 0xFFFFFFFF, 0x80000000,
			}
			for _, word := range words {
				for _, size := range []int{0, 1, 3, 4, 5, 32, 148, 200} {
					datagram := awgPrefixPaddedFrame(0, word, size)
					want := offsetZeroOnly(types, datagram)
					if got := types.classify(datagram); got != want {
						t.Fatalf(
							"word %#08x at %d bytes: classify = %v, "+
								"offset-zero-only rule = %v",
							word, size, got, want,
						)
					}
				}
			}
		})
	}
}

// TestEngineCountersFireUnderTheShippingObfuscationProfile is the unit-level
// reproduction of the device A/B recorded on Status.HandshakeResponseObserved.
// It drives real datagrams through a real socket under S1=16, S2=80 — the
// configuration under which the device reported 0 / 0 / false while completing
// a genuine handshake — and requires 1 / 1 / true.
//
// This is unit evidence, not device evidence. It proves the classifier and the
// counters agree about padded frames; it does not re-run the on-device A/B.
func TestEngineCountersFireUnderTheShippingObfuscationProfile(t *testing.T) {
	gateway := newLoopbackGateway(t)
	config := testConfig(gateway.LocalAddr())
	headers := shippingProfile
	config.AWGHeaders = &headers

	engine, err := OpenWithPacketConn(config, newCarrierSocket(t))
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	if status := engine.Status(); status.AWGPrefixPaddingS1 != 16 ||
		status.AWGPrefixPaddingS2 != 80 {
		t.Fatalf("status reports padding s1=%d s2=%d, want 16 and 80",
			status.AWGPrefixPaddingS1, status.AWGPrefixPaddingS2)
	}

	// A padded handshake initiation out: 16 random bytes then the H1 word.
	initiation := awgPrefixPaddedFrame(16, headers.H1.Start, 164)
	if _, err := engine.WriteInbound(initiation); err != nil {
		t.Fatalf("WriteInbound padded initiation: %v", err)
	}
	if got := engine.Status().TxHandshakeInitiations; got != 1 {
		t.Fatalf("tx_handshake_initiations = %d, want 1; a padded handshake "+
			"initiation was not classified", got)
	}

	buffer := make([]byte, 2048)
	_ = gateway.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, from, err := gateway.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("gateway read: %v", err)
	}

	// A padded handshake response in: 80 random bytes then the H2 word.
	response := awgPrefixPaddedFrame(80, headers.H2.Start, 172)
	if _, err := gateway.WriteToUDP(response, from); err != nil {
		t.Fatalf("gateway padded response: %v", err)
	}
	if _, err := engine.ReadOutboundTimeout(buffer, 5*time.Second); err != nil {
		t.Fatalf("ReadOutbound padded response: %v", err)
	}

	status := engine.Status()
	if status.RxHandshakeResponses != 1 {
		t.Fatalf("rx_handshake_responses = %d, want 1", status.RxHandshakeResponses)
	}
	if !status.HandshakeResponseObserved {
		t.Fatal("handshake_response_observed is false after a padded handshake " +
			"response; this is the defect the padded offsets exist to fix")
	}
	// The counters that were already correct must stay correct: neither padded
	// handshake may be counted as transport.
	if status.TxTransportDatagrams != 0 || status.RxTransportDatagrams != 0 {
		t.Fatalf("a padded handshake moved a transport counter: tx=%d rx=%d",
			status.TxTransportDatagrams, status.RxTransportDatagrams)
	}
	if status.TransportObservedBothWays {
		t.Fatal("transport_observed_both_ways is true on handshakes alone")
	}

	// And transport data, which is unpadded, still classifies and still feeds
	// the transfer-proven signal.
	if _, err := engine.WriteInbound(
		awgPrefixPaddedFrame(0, headers.H4.Start, 200),
	); err != nil {
		t.Fatalf("WriteInbound transport: %v", err)
	}
	if _, err := gateway.WriteToUDP(
		awgPrefixPaddedFrame(0, headers.H4.Start, 300), from,
	); err != nil {
		t.Fatalf("gateway transport: %v", err)
	}
	if _, err := engine.ReadOutboundTimeout(buffer, 5*time.Second); err != nil {
		t.Fatalf("ReadOutbound transport: %v", err)
	}
	if status := engine.Status(); !status.TransportObservedBothWays {
		t.Fatal("transport_observed_both_ways is false after payload-carrying " +
			"transport datagrams in both directions under the shipping profile")
	}
}

// TestStatusReportsThePaddingItIsActuallyUsing pins the two status fields a
// host reads to tell "the gateway is silent" apart from "s1/s2 were never
// supplied", which is the confusion the defect produced.
func TestStatusReportsThePaddingItIsActuallyUsing(t *testing.T) {
	gateway := newLoopbackGateway(t)
	engine, err := OpenWithPacketConn(
		testConfig(gateway.LocalAddr()), newCarrierSocket(t),
	)
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	var decoded map[string]any
	if err := json.Unmarshal([]byte(engine.StatusJSON()), &decoded); err != nil {
		t.Fatalf("StatusJSON is not valid JSON: %v", err)
	}
	for _, key := range []string{
		"awg_prefix_padding_s1", "awg_prefix_padding_s2",
	} {
		if _, present := decoded[key]; !present {
			t.Errorf("status JSON is missing %q", key)
		}
	}
	// A configuration that supplied no table falls back to unpadded WireGuard,
	// and must say so rather than report someone else's padding.
	status := engine.Status()
	if status.AWGPrefixPaddingS1 != 0 || status.AWGPrefixPaddingS2 != 0 {
		t.Fatalf("fallback reports padding s1=%d s2=%d, want zeros",
			status.AWGPrefixPaddingS1, status.AWGPrefixPaddingS2)
	}
}

// TestParseConfigAcceptsTheShippingPaddingSizes walks the JSON parse path with
// the exact obfuscation profile lib/main.dart writes, because the fix is only
// real if the values survive the wire format a host actually sends.
func TestParseConfigAcceptsTheShippingPaddingSizes(t *testing.T) {
	blob := []byte(`{"contract":"` + ContractVersion +
		`","payload":"` + PayloadAWGDatagram +
		`","carrier":"` + CarrierDirectAWG +
		`","gateway_endpoint":"203.0.113.9:51820",` +
		`"awg_header_types":{"h1":11,"h2":22,"h3":33,"h4":44,` +
		`"s1":16,"s2":80,"s3":16,"s4":0}}`)
	config, err := ParseConfig(blob)
	if err != nil {
		t.Fatalf("the shipping obfuscation profile was refused: %v", err)
	}
	if config.AWGHeaders == nil {
		t.Fatal("awg_header_types did not survive the parse")
	}
	if got := *config.AWGHeaders; got.S1 != 16 || got.S2 != 80 || got.S3 != 16 {
		t.Fatalf("padding sizes = s1:%d s2:%d s3:%d, want 16, 80 and 16",
			got.S1, got.S2, got.S3)
	}
	types, configured := config.headerTypes()
	if !configured {
		t.Fatal("headerTypes reported a fallback for a supplied table")
	}
	if types.classify(
		awgPrefixPaddedFrame(80, 22, 172),
	) != ClassHandshakeResponse {
		t.Fatal("a table parsed from JSON does not classify a padded response")
	}
}

// TestParseConfigOmittingPaddingKeepsTheUnpaddedProfile is the compatibility
// case: every configuration written before s1..s4 existed must keep parsing,
// and must keep describing the unpadded deployment it was written for.
func TestParseConfigOmittingPaddingKeepsTheUnpaddedProfile(t *testing.T) {
	blob := []byte(`{"contract":"` + ContractVersion +
		`","payload":"` + PayloadAWGDatagram +
		`","carrier":"` + CarrierDirectAWG +
		`","gateway_endpoint":"203.0.113.9:51820",` +
		`"awg_header_types":{"h1":11,"h2":22,"h3":33,"h4":44}}`)
	config, err := ParseConfig(blob)
	if err != nil {
		t.Fatalf("a configuration without padding sizes was refused: %v", err)
	}
	types, _ := config.headerTypes()
	if types.S1 != 0 || types.S2 != 0 || types.S3 != 0 || types.S4 != 0 {
		t.Fatalf("omitted padding sizes did not default to zero: %+v", types)
	}
	if types.classify(awgPrefixPaddedFrame(0, 11, 148)) !=
		ClassHandshakeInitiation {
		t.Fatal("an unpadded table stopped classifying an unpadded initiation")
	}
}

// TestParseConfigAcceptsTransportPadding replaces the refusal that stood here
// while transport keepalive behavior was unknown. Official AmneziaWG Go v3
// pads every transport packet, so a nonzero s4 must parse and survive into a
// table that classifies both transport shapes at s4.
func TestParseConfigAcceptsTransportPadding(t *testing.T) {
	blob := []byte(`{"contract":"` + ContractVersion +
		`","payload":"` + PayloadAWGDatagram +
		`","carrier":"` + CarrierDirectAWG +
		`","gateway_endpoint":"203.0.113.9:51820",` +
		`"awg_header_types":{"h1":11,"h2":22,"h3":33,"h4":44,` +
		`"s1":16,"s2":80,"s3":16,"s4":24}}`)
	config, err := ParseConfig(blob)
	if err != nil {
		t.Fatalf("a nonzero s4 was refused: %v", err)
	}
	if config.AWGHeaders == nil {
		t.Fatal("awg_header_types did not survive the parse")
	}
	if got := config.AWGHeaders.S4; got != 24 {
		t.Fatalf("s4 = %d, want 24", got)
	}
	types, configured := config.headerTypes()
	if !configured {
		t.Fatal("headerTypes reported a fallback for a supplied table")
	}

	// A padded payload datagram reads at s4.
	if got := types.classify(
		awgPrefixPaddedFrame(24, 44, 200),
	); got != ClassTransportData {
		t.Fatalf("a padded transport datagram classified as %v", got)
	}
	// A padded keepalive reads at s4 and is transport.
	if got := types.classify(awgKeepaliveFrame(24, 44)); got != ClassTransportData {
		t.Fatalf("a keepalive under s4=24 classified as %v; it would have "+
			"silently undercounted the transport datagram counters", got)
	}
	// A retired-fork 32-byte offset-zero shape is invalid when s4 is nonzero.
	if got := types.classify(awgKeepaliveFrame(0, 44)); got != ClassUnknown {
		t.Fatalf("an unpadded keepalive under s4=24 classified as %v, want unknown", got)
	}
	// And the keepalive is not payload, which is the invariant the gate rests
	// on.
	if types.carriesTransportPayload(awgKeepaliveFrame(24, 44)) {
		t.Fatal("a keepalive was counted as payload-carrying under s4=24")
	}
}

// TestTransportPayloadThresholdSeparatesKeepalivesFromPayload is the direct
// statement of the invariant a route-promotion gate depends on: a keepalive may
// never move the payload counters, whatever s4 is and whichever peer generation
// produced it.
func TestTransportPayloadThresholdSeparatesKeepalivesFromPayload(t *testing.T) {
	cases := []struct {
		name   string
		types  AWGHeaderTypes
		length int
		want   bool
	}{
		// S4=0: the shipping profile, and the behaviour that must be unchanged.
		{
			name:   "shipping profile: a 32-byte keepalive is not payload",
			types:  shippingProfile,
			length: awgKeepaliveBytes,
			want:   false,
		},
		{
			name:   "shipping profile: one byte over the keepalive is payload",
			types:  shippingProfile,
			length: awgKeepaliveBytes + 1,
			want:   true,
		},
		{
			name:   "shipping profile: a short datagram is not payload",
			types:  shippingProfile,
			length: 4,
			want:   false,
		},

		// S4=24. The official padded keepalive lands exactly on the raised
		// threshold and is not payload.
		{
			name:   "padded profile: an invalid unpadded transport frame is not payload",
			types:  paddedTransportProfile,
			length: awgKeepaliveBytes,
			want:   false,
		},
		{
			name:  "padded profile: a padded keepalive is not payload",
			types: paddedTransportProfile,
			// s4 + 32 is the official v3 keepalive length.
			length: 24 + awgKeepaliveBytes,
			want:   false,
		},
		{
			name:   "padded profile: one byte past the padded keepalive is payload",
			types:  paddedTransportProfile,
			length: 24 + awgKeepaliveBytes + 1,
			want:   true,
		},
		{
			name:  "padded profile: a real minimum payload datagram is payload",
			types: paddedTransportProfile,
			// s4 + 16 header + 16 tag + one 16-byte block of padded plaintext.
			length: 24 + awgKeepaliveBytes + 16,
			want:   true,
		},
		{
			name:   "padded profile: a datagram between 32 and s4+32 is not payload",
			types:  paddedTransportProfile,
			length: 40,
			want:   false,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			datagram := make([]byte, testCase.length)
			got := testCase.types.carriesTransportPayload(datagram)
			if got != testCase.want {
				t.Fatalf("carriesTransportPayload(%d bytes) = %v, want %v",
					testCase.length, got, testCase.want)
			}
		})
	}
}

// TestParseConfigRefusesTransportPaddingThatLeavesNoPayloadRoom closes the
// silent trap a nonzero s4 newly creates: an s4 large enough that no datagram
// the engine would accept could ever clear the payload threshold, leaving
// transport_observed_both_ways permanently false on a healthy tunnel.
func TestParseConfigRefusesTransportPaddingThatLeavesNoPayloadRoom(t *testing.T) {
	// max_datagram 100, s4 68: 68+4 fits the header word, so the older rule is
	// satisfied, but 68+32 == 100 leaves no length above the threshold.
	blob := []byte(`{"contract":"` + ContractVersion +
		`","payload":"` + PayloadAWGDatagram +
		`","carrier":"` + CarrierDirectAWG +
		`","gateway_endpoint":"203.0.113.9:51820","max_datagram":100,` +
		`"awg_header_types":{"h1":11,"h2":22,"h3":33,"h4":44,"s4":68}}`)
	_, err := ParseConfig(blob)
	if err == nil {
		t.Fatal("an s4 leaving no room for a payload datagram was accepted; " +
			"transport_observed_both_ways could never become true")
	}
	if !strings.Contains(err.Error(), "payload-carrying") {
		t.Fatalf("error %q does not explain the constraint", err)
	}

	// One byte smaller is the boundary and must be accepted: 67+32 == 99 < 100,
	// so a 100-byte datagram clears the threshold.
	fits := []byte(`{"contract":"` + ContractVersion +
		`","payload":"` + PayloadAWGDatagram +
		`","carrier":"` + CarrierDirectAWG +
		`","gateway_endpoint":"203.0.113.9:51820","max_datagram":100,` +
		`"awg_header_types":{"h1":11,"h2":22,"h3":33,"h4":44,"s4":67}}`)
	if _, err := ParseConfig(fits); err != nil {
		t.Fatalf("an s4 that exactly leaves payload room was refused: %v", err)
	}

	// And the rule must not have started refusing unpadded profiles: s4=0 with
	// the smallest legal max_datagram is untouched by it.
	unpadded := []byte(`{"contract":"` + ContractVersion +
		`","payload":"` + PayloadAWGDatagram +
		`","carrier":"` + CarrierDirectAWG +
		`","gateway_endpoint":"203.0.113.9:51820","max_datagram":32,` +
		`"awg_header_types":{"h1":11,"h2":22,"h3":33,"h4":44}}`)
	if _, err := ParseConfig(unpadded); err != nil {
		t.Fatalf("an unpadded profile was refused by the s4 payload rule: %v",
			err)
	}
}

// TestParseConfigRefusesPaddingThatCannotFit closes the other silent-trap
// route: a padding size so large that the class it describes could never be
// classified inside any datagram this engine would accept.
func TestParseConfigRefusesPaddingThatCannotFit(t *testing.T) {
	blob := []byte(`{"contract":"` + ContractVersion +
		`","payload":"` + PayloadAWGDatagram +
		`","carrier":"` + CarrierDirectAWG +
		`","gateway_endpoint":"203.0.113.9:51820","max_datagram":1350,` +
		`"awg_header_types":{"h1":11,"h2":22,"h3":33,"h4":44,"s2":1347}}`)
	_, err := ParseConfig(blob)
	if err == nil {
		t.Fatal("a padding size larger than max_datagram was accepted")
	}
	if !strings.Contains(err.Error(), "no room") {
		t.Fatalf("error %q does not explain the constraint", err)
	}

	// One byte smaller is the boundary and must be accepted: 1346 + 4 == 1350.
	fits := []byte(`{"contract":"` + ContractVersion +
		`","payload":"` + PayloadAWGDatagram +
		`","carrier":"` + CarrierDirectAWG +
		`","gateway_endpoint":"203.0.113.9:51820","max_datagram":1350,` +
		`"awg_header_types":{"h1":11,"h2":22,"h3":33,"h4":44,"s2":1346}}`)
	if _, err := ParseConfig(fits); err != nil {
		t.Fatalf("a padding size that exactly fits was refused: %v", err)
	}
}

// TestParseConfigAllowsEqualPaddingSizes states the reasoned NON-rule: unlike
// the header values, equal padding sizes are legal, and the profile that ships
// has S1 and S3 both 16.
func TestParseConfigAllowsEqualPaddingSizes(t *testing.T) {
	blob := []byte(`{"contract":"` + ContractVersion +
		`","payload":"` + PayloadAWGDatagram +
		`","carrier":"` + CarrierDirectAWG +
		`","gateway_endpoint":"203.0.113.9:51820",` +
		`"awg_header_types":{"h1":11,"h2":22,"h3":33,"h4":44,` +
		`"s1":16,"s2":16,"s3":16}}`)
	config, err := ParseConfig(blob)
	if err != nil {
		t.Fatalf("equal padding sizes were refused: %v", err)
	}
	types, _ := config.headerTypes()
	// Sharing an offset is unambiguous because the header values differ.
	for _, expectation := range []struct {
		word uint32
		want AWGClass
	}{
		{types.H1.Start, ClassHandshakeInitiation},
		{types.H2.Start, ClassHandshakeResponse},
		{types.H3.Start, ClassCookieReply},
	} {
		got := types.classify(awgPrefixPaddedFrame(16, expectation.word, 164))
		if got != expectation.want {
			t.Fatalf("word %d at a shared offset classified as %v, want %v",
				expectation.word, got, expectation.want)
		}
	}
}

// TestEngineCountersSeparateKeepalivesFromPayloadUnderTransportPadding is the
// engine-level statement of the whole change, on the path a host actually
// takes. It replaces a test that pinned the old refusal at Open.
//
// Two things are proven together, because the danger is that fixing one breaks
// the other: a padded keepalive under a nonzero s4 must be COUNTED as transport
// data, and it
// must NOT be counted as payload (which would let a route-promotion gate
// promote on a tunnel carrying no user data).
//
// This is unit evidence. The shipping profile sets s4=0, so no device has ever
// run this configuration.
func TestEngineCountersSeparateKeepalivesFromPayloadUnderTransportPadding(
	t *testing.T,
) {
	gateway := newLoopbackGateway(t)
	config := testConfig(gateway.LocalAddr())
	headers := paddedTransportProfile
	config.AWGHeaders = &headers

	engine, err := OpenWithPacketConn(config, newCarrierSocket(t))
	if err != nil {
		t.Fatalf("OpenWithPacketConn refused a nonzero s4: %v", err)
	}
	defer func() { _ = engine.Close() }()

	buffer := make([]byte, 2048)

	// A keepalive in each direction. S4 prefix, then 32 transport bytes.
	if _, err := engine.WriteInbound(
		awgKeepaliveFrame(int(headers.S4), headers.H4.Start),
	); err != nil {
		t.Fatalf("WriteInbound keepalive: %v", err)
	}
	_ = gateway.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, from, err := gateway.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("gateway read: %v", err)
	}
	if _, err := gateway.WriteToUDP(
		awgKeepaliveFrame(int(headers.S4), headers.H4.Start), from,
	); err != nil {
		t.Fatalf("gateway keepalive: %v", err)
	}
	if _, err := engine.ReadOutboundTimeout(buffer, 5*time.Second); err != nil {
		t.Fatalf("ReadOutbound keepalive: %v", err)
	}

	status := engine.Status()
	if status.TxTransportDatagrams != 1 || status.RxTransportDatagrams != 1 {
		t.Fatalf("keepalives under s4=%d did not move the transport counters: "+
			"tx=%d rx=%d; this is the silent undercount the offset-zero "+
			"keepalive test exists to prevent",
			headers.S4, status.TxTransportDatagrams,
			status.RxTransportDatagrams)
	}
	if status.TxTransportPayloadDatagram != 0 ||
		status.RxTransportPayloadDatagram != 0 {
		t.Fatalf("a keepalive moved a PAYLOAD counter: tx=%d rx=%d; a "+
			"route-promotion gate would promote on a tunnel carrying no user "+
			"data", status.TxTransportPayloadDatagram,
			status.RxTransportPayloadDatagram)
	}
	if status.TransportObservedBothWays {
		t.Fatal("transport_observed_both_ways is true on keepalives alone")
	}

	// Now padded payload datagrams, which must move both counters and flip the
	// gate field.
	if _, err := engine.WriteInbound(
		awgPrefixPaddedFrame(int(headers.S4), headers.H4.Start, 200),
	); err != nil {
		t.Fatalf("WriteInbound padded transport: %v", err)
	}
	if _, err := gateway.WriteToUDP(
		awgPrefixPaddedFrame(int(headers.S4), headers.H4.Start, 300), from,
	); err != nil {
		t.Fatalf("gateway padded transport: %v", err)
	}
	if _, err := engine.ReadOutboundTimeout(buffer, 5*time.Second); err != nil {
		t.Fatalf("ReadOutbound padded transport: %v", err)
	}

	status = engine.Status()
	if status.TxTransportDatagrams != 2 || status.RxTransportDatagrams != 2 {
		t.Fatalf("padded transport datagrams were not classified: tx=%d rx=%d",
			status.TxTransportDatagrams, status.RxTransportDatagrams)
	}
	if status.TxTransportPayloadDatagram != 1 ||
		status.RxTransportPayloadDatagram != 1 {
		t.Fatalf("padded payload datagrams did not move the payload counters: "+
			"tx=%d rx=%d", status.TxTransportPayloadDatagram,
			status.RxTransportPayloadDatagram)
	}
	if !status.TransportObservedBothWays {
		t.Fatal("transport_observed_both_ways is false after payload-carrying " +
			"transport datagrams crossed in both directions under a nonzero s4")
	}
}
