// WNN3 framing conformance, from the second implementation's side.
//
// This is the half of tools/verify_winn_framing_conformance.sh that runs here.
// The other half compiles windows/runner/winn_frame_selftest.h, which is
// header-only and platform-free precisely so both halves can run on a machine
// with no Windows.
//
// It deliberately exercises the SHIPPED framing functions, readFrame and
// writer.write, rather than a test-only re-encoder. A conformance fixture that
// checks a copy of its own layout code proves nothing about the code it ships.
//
// It also PRINTS the bytes it produces rather than only asserting them. Two
// implementations that each assert their own hardcoded vector can still drift
// together if someone updates both constants; two implementations that each
// print what they actually produce, compared by a third party, cannot.

package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

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

// encodeForSelfTest runs the real writer over a buffer.
func encodeForSelfTest(op uint16, payload []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := &writer{out: bufio.NewWriter(&buf)}
	if err := w.write(op, payload); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// checkGoldenDecode feeds the C++ encoder's exact output to the real decoder.
// This is the direction that matters most: the host encodes kCreate, and an
// engine has to decode it. A layout disagreement shows up here as a hard
// rejection rather than as a session that half works.
func checkGoldenDecode() error {
	r := bufio.NewReader(bytes.NewReader(goldenCreateFrame))
	f, err := readFrame(r)
	if err != nil {
		return fmt.Errorf("golden decode: real readFrame rejected the C++ vector: %w", err)
	}
	if f.opcode != opCreate {
		return fmt.Errorf("golden decode: opcode drifted: got 0x%04X want 0x%04X", f.opcode, opCreate)
	}
	if string(f.payload) != "hi" {
		return fmt.Errorf("golden decode: payload drifted: got %q want %q", string(f.payload), "hi")
	}
	return nil
}

// checkGoldenEncode is the reverse direction: the fixture emits a kCreateAck
// that the C++ reader must accept. Same layout, same length field, opcode from
// the engine->host half of the space.
func checkGoldenEncode() ([]byte, error) {
	encoded, err := encodeForSelfTest(opCreateAck, []byte("hi"))
	if err != nil {
		return nil, fmt.Errorf("golden encode: real writer rejected a valid createack: %w", err)
	}
	want := append([]byte{}, goldenCreateFrame...)
	want[6] = 0x02 // opcode kCreateAck; every other byte is identical
	if !bytes.Equal(encoded, want) {
		return nil, fmt.Errorf("golden encode: drifted\n  got  %s\n  want %s",
			hex.EncodeToString(encoded), hex.EncodeToString(want))
	}
	return encoded, nil
}

// checkRejections mirrors CheckRejections on the C++ side. Each of these is a
// way a confused or hostile peer could try to move the frame boundary.
func checkRejections() error {
	if _, err := encodeForSelfTest(opInbound, make([]byte, maxFramePayload+1)); err == nil {
		return errors.New("rejection: writer accepted an oversize payload")
	}
	// The direction guard: this fixture must never be able to emit a
	// host->engine opcode, which is also why checkGoldenDecode exists instead
	// of an encode-side golden for kCreate.
	if _, err := encodeForSelfTest(opCreate, []byte("x")); err == nil {
		return errors.New("rejection: writer emitted a host-bound opcode")
	}
	if _, err := encodeForSelfTest(0x4242, []byte("x")); err == nil {
		return errors.New("rejection: writer accepted an unknown opcode")
	}

	corrupt := func(mutate func([]byte)) error {
		bad := append([]byte{}, goldenCreateFrame...)
		mutate(bad)
		_, err := readFrame(bufio.NewReader(bytes.NewReader(bad)))
		return err
	}
	if err := corrupt(func(b []byte) { b[0] = 0x58 }); err == nil {
		return errors.New("rejection: readFrame accepted a bad magic")
	}
	if err := corrupt(func(b []byte) { b[4] = 0x02 }); err == nil {
		return errors.New("rejection: readFrame accepted a bad version")
	}
	// A non-zero reserved word is how a future framing revision would announce
	// itself. Accepting it silently is how this layer would start guessing.
	if err := corrupt(func(b []byte) { b[12] = 0x01 }); err == nil {
		return errors.New("rejection: readFrame accepted a non-zero reserved word")
	}
	if err := corrupt(func(b []byte) { b[6] = 0x42; b[7] = 0x42 }); err == nil {
		return errors.New("rejection: readFrame accepted an unknown opcode")
	}
	return nil
}

// goldenCase is one frame both implementations must encode byte-identically.
// Every opcode here is engine->host so it passes the real writer.direction
// guard, and the payload bytes are the exact ones the C++ half encodes, so the
// shell diff proves the two encoders agree on the wire layout for all of them.
type goldenCase struct {
	name      string
	op        uint16
	payload   []byte
	isCarrier bool
}

// The ten golden frames, mirrored in the C++ half of
// tools/verify_winn_framing_conformance.sh. frame-10 is the carrier: one full
// tunnel-sized IP payload, all 0x5A, which it checks independently for magic,
// version, a 16-byte header and a length field that matches the payload.
var goldenFrames = []goldenCase{
	{name: "frame-01", op: opCreateAck, payload: []byte("hi")},
	{name: "frame-02", op: opOutbound, payload: []byte{0x45, 0x00, 0x00, 0x28, 0xAB, 0xCD}},
	{name: "frame-03", op: opStatusResponse, payload: []byte(`{"up":true}`)},
	{name: "frame-04", op: opCloseAck, payload: []byte{}},
	{name: "frame-05", op: opError, payload: []byte("boom")},
	{name: "frame-06", op: opOutbound, payload: []byte{0x45, 0x00, 0x00, 0x28, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00}},
	{name: "frame-07", op: opCreateAck, payload: []byte(`{"handle":1}`)},
	{name: "frame-08", op: opStatusResponse, payload: []byte(`{}`)},
	{name: "frame-09", op: opError, payload: []byte("auth failed")},
	{name: "frame-10", op: opOutbound, payload: bytes.Repeat([]byte{0x5A}, 1420), isCarrier: true},
}

// checkGoldenFrames encodes every golden frame with the REAL shipped writer (the
// carrier encoder) and prints it raw so the shell can diff it against the C++
// half. frame-10 also gets an independent structural guard, so a header defect
// fails here naming the field and cannot hide behind a total-same-bytes diff.
func checkGoldenFrames() ([]string, error) {
	var lines []string
	for _, g := range goldenFrames {
		enc, err := encodeForSelfTest(g.op, g.payload)
		if err != nil {
			return nil, fmt.Errorf("%s: real writer rejected a valid frame: %w", g.name, err)
		}
		if g.isCarrier {
			if len(enc) != frameHeaderBytes+len(g.payload) {
				return nil, fmt.Errorf("frame-10: header is not 16 bytes (total %d, payload %d)", len(enc), len(g.payload))
			}
			if got := binary.LittleEndian.Uint32(enc[0:4]); got != frameMagic {
				return nil, fmt.Errorf("frame-10: magic drifted: got 0x%08X want 0x%08X", got, frameMagic)
			}
			if got := binary.LittleEndian.Uint16(enc[4:6]); got != frameVersion {
				return nil, fmt.Errorf("frame-10: version drifted: got %d want %d", got, frameVersion)
			}
			if declared := binary.LittleEndian.Uint32(enc[8:12]); int(declared) != len(g.payload) {
				return nil, fmt.Errorf("frame-10: length field %d does not match carrier payload %d", declared, len(g.payload))
			}
		}
		lines = append(lines, fmt.Sprintf("vector: %s %s", g.name, hex.EncodeToString(enc)))
	}
	return lines, nil
}

// runSelfTest reports conformance on stdout in a form the shell runner compares
// against the C++ half. The `vector:` lines are the contract between them.
func runSelfTest() error {
	if err := checkGoldenDecode(); err != nil {
		return err
	}
	if _, err := checkGoldenEncode(); err != nil {
		return err
	}
	if err := checkRejections(); err != nil {
		return err
	}
	vectorLines, err := checkGoldenFrames()
	if err != nil {
		return err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "impl: go (%s, second independent implementation)\n", "winn_framing_fixture")
	for _, line := range vectorLines {
		fmt.Fprintln(&b, line)
	}
	fmt.Fprintf(&b, "checks: golden-decode golden-encode rejections\n")
	fmt.Fprint(&b, "WNN3 FRAMING CONFORMANCE: PASS\n")
	fmt.Print(b.String())
	return nil
}
