// WNN3 framing conformance self-test, from the relay module's side.
//
// The relay owns the Wintun adapter and moves RAW INNER IP PACKETS over a UDP
// seam; it does not itself speak the framed pipe protocol in
// windows/runner/winn_frame.h -- that framing lives between the privileged host
// (winn3_supervisor.cpp) and cmd/winn-datapath. But this module is the natural
// home for a self-test that must run on a Windows host with no engine present,
// and the framing is the one byte-level contract every side of the seam shares.
//
// The `--selftest` flag wires main_windows.go to run this BEFORE anything else:
// before binding the seam, before touching the adapter, and critically before
// the `runningAsLocalSystem` guard, so an unprivileged `winsvpnwinn3engine.exe
// --selftest` is a valid way to prove the binary's framing conformance. This
// file carries no build tag on purpose, so the same checks also compile and run
// on the development host, which is the only place they can be exercised
// without a Windows machine.
//
// It is a faithful Go reflection of the C++ contract in winn_frame.h and of the
// golden expectations in winn_frame_selftest.h. The golden vector is byte-for-
// byte the one both the C++ self-test and the independent fixture
// (winn_framing_fixture) assert, so a drift here is caught against those, not
// merely against itself.

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// WNN3 frame layout, mirrored from windows/runner/winn_frame.h.
const (
	frameMagic       = uint32(0x334E4E57) // 'W' 'N' 'N' '3' little-endian
	frameVersion     = uint16(1)
	frameHeaderBytes = 16
	maxFramePayload  = uint32(65535)
	maxReaderBuffer  = frameHeaderBytes + int(maxFramePayload)
)

const (
	opCreate         uint16 = 0x0001
	opCreateAck      uint16 = 0x0002
	opInbound        uint16 = 0x0010
	opOutbound       uint16 = 0x0011
	opStatusRequest  uint16 = 0x0020
	opStatusResponse uint16 = 0x0021
	opClose          uint16 = 0x0030
	opCloseAck       uint16 = 0x0031
	opError          uint16 = 0x00F0
)

func isHostToEngineOp(op uint16) bool {
	return op == opCreate || op == opInbound || op == opStatusRequest || op == opClose
}

func isEngineToHostOp(op uint16) bool {
	return op == opCreateAck || op == opOutbound || op == opStatusResponse ||
		op == opCloseAck || op == opError
}

func isKnownOp(op uint16) bool {
	return isHostToEngineOp(op) || isEngineToHostOp(op)
}

// encodeFrame serialises one frame, mirroring EncodeFrame in winn_frame.h. It
// accepts any KNOWN opcode in either direction (the C++ encoder does too); the
// direction enforcement belongs to the reader.
func encodeFrame(op uint16, payload []byte) ([]byte, error) {
	if uint32(len(payload)) > maxFramePayload || !isKnownOp(op) {
		return nil, errors.New("winn frame: refused to encode")
	}
	out := make([]byte, 0, frameHeaderBytes+len(payload))
	var scratch [frameHeaderBytes]byte
	binary.LittleEndian.PutUint32(scratch[0:4], frameMagic)
	binary.LittleEndian.PutUint16(scratch[4:6], frameVersion)
	binary.LittleEndian.PutUint16(scratch[6:8], op)
	binary.LittleEndian.PutUint32(scratch[8:12], uint32(len(payload)))
	binary.LittleEndian.PutUint32(scratch[12:16], 0)
	out = append(out, scratch[:]...)
	out = append(out, payload...)
	return out, nil
}

type decodeStatus int

const (
	statusFrame decodeStatus = iota
	statusNeedMore
	statusInvalid
)

type frameReader struct {
	acceptEngineToHost bool
	buffer             []byte
}

func (r *frameReader) append(bytes []byte) {
	if len(bytes) == 0 {
		return
	}
	r.buffer = append(r.buffer, bytes...)
}

func (r *frameReader) buffered() int { return len(r.buffer) }

// next pops one frame if a complete, valid one is buffered. It mirrors
// FrameReader::Next in winn_frame.h, including the choice to return invalid
// (fatal) rather than resynchronising, because a length confusion must never
// become an attacker-chosen frame boundary.
func (r *frameReader) next(op *uint16, payload *[]byte) decodeStatus {
	if len(r.buffer) > maxReaderBuffer {
		return statusInvalid
	}
	if len(r.buffer) < frameHeaderBytes {
		return statusNeedMore
	}
	b := r.buffer
	if binary.LittleEndian.Uint32(b[0:4]) != frameMagic ||
		binary.LittleEndian.Uint16(b[4:6]) != frameVersion ||
		binary.LittleEndian.Uint32(b[12:16]) != 0 {
		return statusInvalid
	}
	opcode := binary.LittleEndian.Uint16(b[6:8])
	length := binary.LittleEndian.Uint32(b[8:12])
	if length > maxFramePayload || !isKnownOp(opcode) {
		return statusInvalid
	}
	directionOK := isEngineToHostOp(opcode)
	if !r.acceptEngineToHost {
		directionOK = isHostToEngineOp(opcode)
	}
	if !directionOK {
		return statusInvalid
	}
	if (opcode == opStatusRequest || opcode == opClose || opcode == opCloseAck) && length != 0 {
		return statusInvalid
	}
	if (opcode == opInbound || opcode == opOutbound) && length == 0 {
		return statusInvalid
	}
	total := frameHeaderBytes + int(length)
	if len(r.buffer) < total {
		return statusNeedMore
	}
	*op = opcode
	*payload = append((*payload)[:0], b[frameHeaderBytes:total]...)
	r.buffer = r.buffer[total:]
	return statusFrame
}

// The golden host->engine frame: kCreate carrying "hi". Byte-for-byte the
// vector in CheckGoldenEncoding in windows/runner/winn_frame_selftest.h.
var goldenCreateFrame = []byte{
	0x57, 0x4E, 0x4E, 0x33, // magic 'W' 'N' 'N' '3'
	0x01, 0x00, // version 1
	0x01, 0x00, // opcode kCreate
	0x02, 0x00, 0x00, 0x00, // length 2
	0x00, 0x00, 0x00, 0x00, // reserved
	0x68, 0x69, // "hi"
}

func checkGoldenEncoding() error {
	encoded, err := encodeFrame(opCreate, []byte("hi"))
	if err != nil {
		return err
	}
	if !bytes.Equal(encoded, goldenCreateFrame) {
		return fmt.Errorf("golden: encoded create frame drifted")
	}
	return nil
}

func checkRoundTrip() error {
	packetA := []byte{0x45, 0x00, 0x00, 0x28, 0xAB, 0xCD}
	packetB := bytes.Repeat([]byte{0x5A}, 1420)
	var stream []byte
	for _, p := range [][]byte{packetA, packetB} {
		enc, err := encodeFrame(opOutbound, p)
		if err != nil {
			return fmt.Errorf("roundtrip: encode outbound: %v", err)
		}
		stream = append(stream, enc...)
	}
	status, err := encodeFrame(opStatusResponse, []byte(`{"up":true}`))
	if err != nil {
		return fmt.Errorf("roundtrip: encode status: %v", err)
	}
	stream = append(stream, status...)

	// Feed the stream ONE BYTE AT A TIME. A reader that only works on whole
	// frames passes a naive test and then corrupts traffic on a real pipe.
	reader := &frameReader{acceptEngineToHost: true}
	var ops []uint16
	var payloads [][]byte
	for i := 0; i < len(stream); i++ {
		reader.append(stream[i : i+1])
		for {
			var op uint16
			var payload []byte
			st := reader.next(&op, &payload)
			if st == statusInvalid {
				return fmt.Errorf("roundtrip: reader rejected a valid stream at byte %d", i)
			}
			if st == statusNeedMore {
				break
			}
			ops = append(ops, op)
			payloads = append(payloads, payload)
		}
	}
	if len(ops) != 3 {
		return fmt.Errorf("roundtrip: expected 3 frames, got %d", len(ops))
	}
	if ops[0] != opOutbound || !bytes.Equal(payloads[0], packetA) ||
		ops[1] != opOutbound || !bytes.Equal(payloads[1], packetB) ||
		ops[2] != opStatusResponse {
		return fmt.Errorf("roundtrip: frame contents drifted")
	}
	if reader.buffered() != 0 {
		return fmt.Errorf("roundtrip: reader retained trailing bytes")
	}
	return nil
}

func checkRejections() error {
	base, err := encodeFrame(opOutbound, []byte{0x01, 0x02, 0x03, 0x04})
	if err != nil {
		return err
	}

	mustReject := func(name string, raw []byte) error {
		reader := &frameReader{acceptEngineToHost: true}
		reader.append(raw)
		var op uint16
		var payload []byte
		if reader.next(&op, &payload) != statusInvalid {
			return fmt.Errorf("rejection: reader accepted %s", name)
		}
		return nil
	}

	badMagic := append([]byte{}, base...)
	badMagic[0] = 0x58
	if err := mustReject("bad magic", badMagic); err != nil {
		return err
	}

	badVersion := append([]byte{}, base...)
	badVersion[4] = 99
	if err := mustReject("bad version", badVersion); err != nil {
		return err
	}

	badReserved := append([]byte{}, base...)
	badReserved[12] = 1
	if err := mustReject("nonzero reserved", badReserved); err != nil {
		return err
	}

	unknownOp := append([]byte{}, base...)
	unknownOp[6] = 0x77
	unknownOp[7] = 0x77
	if err := mustReject("unknown opcode", unknownOp); err != nil {
		return err
	}

	// A host reader must refuse a host->engine opcode (kInbound).
	rawInbound, err := encodeFrame(opInbound, []byte{0x45, 0x00})
	if err != nil {
		return err
	}
	if err := mustReject("wrong direction", rawInbound); err != nil {
		return err
	}

	oversize := append([]byte{}, base...)
	binary.LittleEndian.PutUint32(oversize[8:12], maxFramePayload+1)
	if err := mustReject("oversize length", oversize); err != nil {
		return err
	}

	emptyPacket, err := encodeFrame(opOutbound, nil)
	if err != nil {
		return err
	}
	if err := mustReject("empty packet", emptyPacket); err != nil {
		return err
	}

	closeAckWithPayload, err := encodeFrame(opCloseAck, []byte("x"))
	if err != nil {
		return err
	}
	if err := mustReject("payload on close ack", closeAckWithPayload); err != nil {
		return err
	}

	if _, err := encodeFrame(opInbound, make([]byte, maxFramePayload+1)); err == nil {
		return fmt.Errorf("rejection: encodeFrame accepted an oversize payload")
	}
	if _, err := encodeFrame(0x4242, []byte("x")); err == nil {
		return fmt.Errorf("rejection: encodeFrame accepted an unknown opcode")
	}
	return nil
}

// runSelfTest runs every framing check and reports conformance. It is the
// function the `--selftest` flag invokes before the relay starts.
func runSelfTest() error {
	if err := checkGoldenEncoding(); err != nil {
		return err
	}
	if err := checkRoundTrip(); err != nil {
		return err
	}
	if err := checkRejections(); err != nil {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "impl: go (windows/winn3_engine relay)\n")
	fmt.Fprintf(&b, "vector: golden-create %x\n", goldenCreateFrame)
	fmt.Fprintf(&b, "checks: golden-encoding round-trip rejections\n")
	fmt.Fprint(&b, "WNN3 FRAMING CONFORMANCE: PASS\n")
	fmt.Print(b.String())
	return nil
}
