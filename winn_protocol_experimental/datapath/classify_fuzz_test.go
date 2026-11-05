package datapath

import (
	"encoding/binary"
	"testing"
)

// FuzzClassify drives the AmneziaWG header-type classifier with a datagram the
// network peer controls completely and an obfuscation profile the operator
// controls completely.
//
// Memory safety is the first reason this target exists. classify indexes at
// caller-supplied offsets that can exceed the datagram length in every
// direction, and it is reached from Engine.pump on bytes that arrived from a
// UDP socket before anything has authenticated them — the gateway-sender filter
// checks an address, which an off-path sender can spoof. This project is in the
// middle of disclosing a remote panic in a dependency caused by exactly this
// shape of missing bounds check, so the classifier gets a fuzzer rather than an
// argument that it looks correct.
//
// The invariants below are the second reason. They assert the two properties
// the fix is built on — transport data always wins, and padding never changes a
// verdict an unpadded profile already reached — across the whole input space
// rather than at the table-driven examples.
func FuzzClassify(fuzzer *testing.F) {
	// The shipping profile, the values it ships with, and the frames the
	// device A/B actually exchanged.
	fuzzer.Add(
		awgPrefixPaddedFrame(16, 11, 164),
		uint32(11), uint32(22), uint32(33), uint32(44),
		uint16(16), uint16(80), uint16(16), uint16(0),
	)
	fuzzer.Add(
		awgPrefixPaddedFrame(80, 22, 172),
		uint32(11), uint32(22), uint32(33), uint32(44),
		uint16(16), uint16(80), uint16(16), uint16(0),
	)
	// Plain WireGuard, unpadded.
	fuzzer.Add(
		awgPrefixPaddedFrame(0, 4, 200),
		uint32(1), uint32(2), uint32(3), uint32(4),
		uint16(0), uint16(0), uint16(0), uint16(0),
	)
	// Empty, and every length below the first boundary.
	fuzzer.Add(
		[]byte{},
		uint32(11), uint32(22), uint32(33), uint32(44),
		uint16(16), uint16(80), uint16(16), uint16(0),
	)
	fuzzer.Add(
		[]byte{0xAA, 0xAA, 0xAA},
		uint32(11), uint32(22), uint32(33), uint32(44),
		uint16(16), uint16(80), uint16(16), uint16(0),
	)
	// Offsets far past the end of the datagram, at the top of the uint16 range
	// the UAPI accepts, against a datagram far too short to hold them.
	fuzzer.Add(
		[]byte{0xAA, 0xAA, 0xAA, 0xAA, 0xAA},
		uint32(11), uint32(22), uint32(33), uint32(44),
		uint16(65535), uint16(65535), uint16(65535), uint16(65535),
	)
	// A datagram exactly one byte short of a maximal offset's word, and one
	// exactly long enough to hold it. 65535+4 is the point where a uint16
	// offset overflows if the arithmetic is done in the wrong width, so both
	// sides of that boundary are seeded rather than left to be rediscovered.
	fuzzer.Add(
		make([]byte, 65538),
		uint32(11), uint32(22), uint32(33), uint32(44),
		uint16(65535), uint16(0), uint16(0), uint16(0),
	)
	maximal := make([]byte, 65539)
	binary.LittleEndian.PutUint32(maximal[65535:], 11)
	fuzzer.Add(
		maximal,
		uint32(11), uint32(22), uint32(33), uint32(44),
		uint16(65535), uint16(0), uint16(0), uint16(0),
	)

	// Nonzero s4. Official AmneziaWG Go v3 puts every transport header at s4,
	// including keepalives. These seeds pin both the legal padded shape and the
	// rejected retired-fork offset-zero shape.
	//
	// A padded payload datagram.
	fuzzer.Add(
		awgPrefixPaddedFrame(24, 44, 200),
		uint32(11), uint32(22), uint32(33), uint32(44),
		uint16(16), uint16(80), uint16(16), uint16(24),
	)
	// The legal padded keepalive at the keepalive-versus-payload boundary.
	fuzzer.Add(
		awgKeepaliveFrame(24, 44),
		uint32(11), uint32(22), uint32(33), uint32(44),
		uint16(16), uint16(80), uint16(16), uint16(24),
	)
	// The retired-fork unpadded 32-byte H4 shape must not be accepted when s4
	// is nonzero.
	fuzzer.Add(
		awgKeepaliveFrame(0, 44),
		uint32(11), uint32(22), uint32(33), uint32(44),
		uint16(16), uint16(80), uint16(16), uint16(24),
	)
	// One byte either side of the raised payload threshold, s4+32.
	fuzzer.Add(
		awgPrefixPaddedFrame(24, 44, 24+awgKeepaliveBytes),
		uint32(11), uint32(22), uint32(33), uint32(44),
		uint16(16), uint16(80), uint16(16), uint16(24),
	)
	fuzzer.Add(
		awgPrefixPaddedFrame(24, 44, 24+awgKeepaliveBytes+1),
		uint32(11), uint32(22), uint32(33), uint32(44),
		uint16(16), uint16(80), uint16(16), uint16(24),
	)
	// A padded keepalive whose random prefix carries a handshake word, so
	// transport precedence is exercised rather than assumed.
	fuzzer.Add(
		awgFrameWithWordsAt(24+awgKeepaliveBytes,
			awgWordAt{offset: 16, word: 11},
			awgWordAt{offset: 24, word: 44},
		),
		uint32(11), uint32(22), uint32(33), uint32(44),
		uint16(16), uint16(80), uint16(16), uint16(24),
	)
	// s4 equal to the transport keepalive size, so offset and unprefixed length
	// coincide and any confusion between them shows up.
	fuzzer.Add(
		awgKeepaliveFrame(awgKeepaliveBytes, 44),
		uint32(11), uint32(22), uint32(33), uint32(44),
		uint16(0), uint16(0), uint16(0), uint16(awgKeepaliveBytes),
	)

	fuzzer.Fuzz(func(
		t *testing.T,
		datagram []byte,
		h1, h2, h3, h4 uint32,
		s1, s2, s3, s4 uint16,
	) {
		types := AWGHeaderTypes{
			H1: AwgHeaderSpec{Start: h1, End: h1}, H2: AwgHeaderSpec{Start: h2, End: h2}, H3: AwgHeaderSpec{Start: h3, End: h3}, H4: AwgHeaderSpec{Start: h4, End: h4},
			S1: s1, S2: s2, S3: s3, S4: s4,
		}

		// Memory safety and a closed result domain. Reaching here at all means
		// no index panicked at any offset.
		class := types.classify(datagram)
		switch class {
		case ClassUnknown, ClassHandshakeInitiation, ClassHandshakeResponse,
			ClassCookieReply, ClassTransportData:
		default:
			t.Fatalf("classify returned %d, which is not an AWGClass", class)
		}

		// The classifier holds no state, so a second call on identical input
		// must reach an identical verdict.
		if second := types.classify(datagram); second != class {
			t.Fatalf("classify is not deterministic: %v then %v", class, second)
		}

		// Nothing shorter than a header word can ever be classified, whatever
		// the offsets say.
		if len(datagram) < 4 && class != ClassUnknown {
			t.Fatalf("a %d-byte datagram classified as %v",
				len(datagram), class)
		}

		// A verdict is never returned without the bytes to support it: the
		// datagram must be long enough to hold a header word at one of the
		// offsets that class is permitted to carry it at, and that word must be
		// the class's configured value.
		//
		// Every class has exactly one legal offset. Transport headers, including
		// keepalives, are at s4.
		//
		// The offset is widened to int BEFORE any arithmetic. Doing the
		// addition in uint16 wraps at 65535 and turns a slice expression into
		// an out-of-range index — this fuzz target caught exactly that bug in
		// this assertion, which is the same shape of defect the bounds check in
		// headerWordAt exists to prevent one layer down.
		if class != ClassUnknown {
			want, _ := wordOfClass(types, class)
			supported := false
			for _, offset := range legalOffsetsOfClass(
				types, class, len(datagram),
			) {
				if word, ok := headerWordAt(datagram, offset); ok &&
					word == want {
					supported = true
					break
				}
			}
			if !supported {
				t.Fatalf("classify returned %v for a %d-byte datagram that "+
					"carries %#08x at none of that class's legal offsets %v",
					class, len(datagram), want,
					legalOffsetsOfClass(types, class, len(datagram)))
			}
		}

		// The rest of the invariants describe a well-formed profile. A profile
		// with repeated header values is refused by Config.normalize before it
		// can reach an engine, and its verdicts legitimately depend on the
		// order of the tests, so it is not held to them.
		if !types.distinct() {
			return
		}

		// Transport data always wins. A datagram carrying H4 at offset S4 is
		// transport, whatever else it carries at whatever other offset. This is
		// the guarantee the route-promotion gate rests on.
		if word, ok := headerWordAt(datagram, int(s4)); ok && word == h4 {
			if class != ClassTransportData {
				t.Fatalf("a datagram carrying h4 at offset s4=%d classified "+
					"as %v, not as transport data", s4, class)
			}
		}

		// A PADDED KEEPALIVE IS NEVER LOST. It arrives at s4+32 bytes with H4
		// at s4. Classifying it as anything but transport data would undercount
		// tx_transport_datagrams and rx_transport_datagrams on a healthy
		// tunnel.
		if len(datagram) == int(s4)+awgKeepaliveBytes {
			if word, ok := headerWordAt(datagram, int(s4)); ok && word == h4 {
				if class != ClassTransportData {
					t.Fatalf("a %d-byte keepalive carrying h4 at offset s4=%d "+
						"classified as %v under s4=%d, not as transport data",
						len(datagram), s4, class, s4)
				}
			}
		}

		// The retired-fork offset-zero compatibility arm must stay removed. An
		// unpadded 32-byte H4 frame is not transport when s4 is nonzero and the
		// datagram does not independently carry a legal H4 word at s4.
		if s4 > 0 && len(datagram) == awgKeepaliveBytes {
			offsetZeroWord, offsetZeroOK := headerWordAt(datagram, 0)
			s4Word, s4OK := headerWordAt(datagram, int(s4))
			if offsetZeroOK && offsetZeroWord == h4 &&
				(!s4OK || s4Word != h4) && class == ClassTransportData {
				t.Fatalf("an unpadded 32-byte h4 frame classified as transport under s4=%d", s4)
			}
		}

		// A KEEPALIVE IS NEVER PAYLOAD, under any profile. This is the
		// invariant the route-promotion gate rests on: a keepalive counted as
		// payload would let a gate promote a route on a tunnel that has carried
		// no user data. Asserted for every s4 rather than only where a
		// keepalive would classify, because the threshold is what must hold.
		if len(datagram) == int(s4)+awgKeepaliveBytes &&
			types.carriesTransportPayload(datagram) {
			t.Fatalf("carriesTransportPayload answered true for a %d-byte "+
				"keepalive under s4=%d", len(datagram), s4)
		}

		// Nothing below the padded empty-transport length is payload either. A
		// datagram no longer than s4+awgKeepaliveBytes cannot hold a padded
		// transport header, a tag AND a byte of user data.
		if len(datagram) <= int(s4)+awgKeepaliveBytes &&
			types.carriesTransportPayload(datagram) {
			t.Fatalf("carriesTransportPayload answered true for a %d-byte "+
				"datagram under s4=%d, which cannot carry user data",
				len(datagram), s4)
		}

		// carriesTransportPayload holds no state either.
		if second := types.carriesTransportPayload(datagram); second !=
			types.carriesTransportPayload(datagram) {
			t.Fatalf("carriesTransportPayload is not deterministic: %v", second)
		}

		// The no-regression property, which is the whole of requirement one: a
		// deployment with NO prefix padding must reach exactly the verdict the
		// original offset-zero-only classifier reached, for every datagram.
		//
		// It is asserted on a wholly unpadded profile rather than on a mixed
		// one. Once any size is nonzero the profile describes a padded
		// deployment, and which class wins a coincidental double match there is
		// the documented precedence, not a regression — an earlier and stricter
		// version of this invariant conflated the two and this target rejected
		// it, which is the behaviour a fuzz target is for.
		unpadded := types
		unpadded.S1, unpadded.S2, unpadded.S3, unpadded.S4 = 0, 0, 0, 0
		unpaddedWant := offsetZeroOnly(unpadded, datagram)
		if got := unpadded.classify(datagram); got != unpaddedWant {
			t.Fatalf("an unpadded profile classified a %d-byte datagram as %v, "+
				"but the offset-zero-only rule says %v",
				len(datagram), got, unpaddedWant)
		}

		// ClassUnknown must mean nothing matched anywhere. If the classifier
		// declined, then no class may have its own header word sitting at its
		// own offset — otherwise a real message is being dropped on the floor,
		// which is the exact failure the padded offsets exist to end.
		if class == ClassUnknown {
			for _, candidate := range []AWGClass{
				ClassTransportData, ClassHandshakeInitiation,
				ClassHandshakeResponse, ClassCookieReply,
			} {
				want, _ := wordOfClass(types, candidate)
				for _, offset := range legalOffsetsOfClass(
					types, candidate, len(datagram),
				) {
					if word, ok := headerWordAt(
						datagram, offset,
					); ok && word == want {
						t.Fatalf("classify declined a %d-byte datagram whose "+
							"word at offset %d is %#08x, which is %v",
							len(datagram), offset, word, candidate)
					}
				}
			}
		}
	})
}

// legalOffsetsOfClass returns every offset at which a datagram is permitted to
// carry the class's header word.
//
// Official AmneziaWG Go v3 pads every message class, including transport
// keepalives, so each class has exactly one legal offset.
func legalOffsetsOfClass(
	types AWGHeaderTypes, class AWGClass, _ int,
) []int {
	switch class {
	case ClassHandshakeInitiation:
		return []int{int(types.S1)}
	case ClassHandshakeResponse:
		return []int{int(types.S2)}
	case ClassCookieReply:
		return []int{int(types.S3)}
	case ClassTransportData:
		return []int{int(types.S4)}
	case ClassUnknown:
		return nil
	}
	return nil
}

// wordOfClass returns the configured header value for a classified message.
func wordOfClass(types AWGHeaderTypes, class AWGClass) (uint32, bool) {
	switch class {
	case ClassHandshakeInitiation:
		return types.H1.Start, true
	case ClassHandshakeResponse:
		return types.H2.Start, true
	case ClassCookieReply:
		return types.H3.Start, true
	case ClassTransportData:
		return types.H4.Start, true
	case ClassUnknown:
		return 0, false
	}
	return 0, false
}
