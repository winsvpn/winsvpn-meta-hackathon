package carrier

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func FuzzReadFrame(fuzzer *testing.F) {
	fuzzer.Add([]byte{0, 3, 'a', 'b', 'c'}, 1350)
	fuzzer.Add([]byte{0, 0}, 1350)
	fuzzer.Add([]byte{0xff, 0xff}, 1350)
	fuzzer.Fuzz(func(t *testing.T, data []byte, maximum int) {
		if maximum < 1 || maximum > AbsoluteMaxDatagram {
			maximum = DefaultMaxDatagram
		}
		packet, err := readFrame(bytes.NewReader(data), maximum)
		if err != nil {
			return
		}
		if len(packet) < 1 || len(packet) > maximum || len(data) < 2 {
			t.Fatalf("invalid accepted frame length %d", len(packet))
		}
		if int(binary.BigEndian.Uint16(data[:2])) != len(packet) {
			t.Fatal("accepted frame length does not match prefix")
		}
	})
}

func FuzzDecodeEnvelope(fuzzer *testing.F) {
	seed, err := encodeEnvelope(envelopeData, 1, []byte("awg"), envelopeHeaderSize+3)
	if err != nil {
		fuzzer.Fatal(err)
	}
	fuzzer.Add(seed, DefaultMaxDatagram)
	fuzzer.Add([]byte("WCF2"), DefaultMaxDatagram)
	fuzzer.Fuzz(func(t *testing.T, data []byte, maximum int) {
		if maximum < 576 || maximum > AbsoluteMaxDatagram {
			maximum = DefaultMaxDatagram
		}
		frame, err := decodeEnvelope(data, maximum)
		if err != nil {
			return
		}
		if frame.sequence == 0 {
			t.Fatal("accepted an envelope with sequence zero")
		}
		if frame.kind == envelopeData &&
			(len(frame.payload) == 0 || len(frame.payload) > maximum) {
			t.Fatal("accepted an invalid data envelope")
		}
	})
}

func BenchmarkH2FrameCodec(benchmark *testing.B) {
	payload := bytes.Repeat([]byte{0x5a}, DefaultMaxDatagram)
	var framed bytes.Buffer
	if err := writeFrame(&framed, payload, DefaultMaxDatagram); err != nil {
		benchmark.Fatal(err)
	}
	data := append([]byte(nil), framed.Bytes()...)
	buffer := make([]byte, DefaultMaxDatagram)
	benchmark.SetBytes(int64(len(payload)))
	benchmark.ReportAllocs()
	benchmark.ResetTimer()
	for index := 0; index < benchmark.N; index++ {
		count, err := readFrameInto(bytes.NewReader(data), buffer, DefaultMaxDatagram)
		if err != nil {
			benchmark.Fatal(err)
		}
		if count != len(payload) {
			benchmark.Fatal("frame length changed")
		}
	}
}
