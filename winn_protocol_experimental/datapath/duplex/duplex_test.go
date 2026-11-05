package duplex

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/datapath"
)

// TestGoldenFrameBytes pins the exact bytes this encoder produces.
//
// These vectors were computed from windows/runner/winn_frame.h by hand and
// then confirmed against that header's own EncodeFrame (see the lane report).
// They exist so that a change to this Go encoder which drifts from the
// normative C++ layout fails here, loudly, instead of at a tunnel that silently
// carries nothing.
func TestGoldenFrameBytes(t *testing.T) {
	cases := []struct {
		name    string
		opcode  Opcode
		payload []byte
		golden  string
	}{
		{
			name:    "inbound with two payload bytes",
			opcode:  OpInbound,
			payload: []byte("AB"),
			golden:  "574e4e33010010000200000000000000" + "4142",
		},
		{
			name:   "close carries no payload",
			opcode: OpClose,
			golden: "574e4e33010030000000000000000000",
		},
		{
			name:   "close-ack carries no payload",
			opcode: OpCloseAck,
			golden: "574e4e33010031000000000000000000",
		},
		{
			name:    "error carries utf-8 text",
			opcode:  OpError,
			payload: []byte("x"),
			golden:  "574e4e330100f0000100000000000000" + "78",
		},
		{
			name:    "create carries the configuration",
			opcode:  OpCreate,
			payload: []byte("{}"),
			golden:  "574e4e33010001000200000000000000" + "7b7d",
		},
		{
			name:    "status-response carries json",
			opcode:  OpStatusResponse,
			payload: []byte("{}"),
			golden:  "574e4e33010021000200000000000000" + "7b7d",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			var stream bytes.Buffer
			if err := NewWriter(&stream).Write(item.opcode, item.payload); err != nil {
				t.Fatalf("write: %v", err)
			}
			if got := hex.EncodeToString(stream.Bytes()); got != item.golden {
				t.Fatalf("frame bytes = %s, want %s", got, item.golden)
			}
		})
	}
}

// TestWireConstantsMatchTheNormativeHeader guards the four numbers that must
// never diverge from windows/runner/winn_frame.h.
func TestWireConstantsMatchTheNormativeHeader(t *testing.T) {
	if Magic != 0x334E4E57 {
		t.Fatalf("Magic = 0x%08x, want 0x334E4E57", Magic)
	}
	if Version != 1 {
		t.Fatalf("Version = %d, want 1", Version)
	}
	if HeaderSize != 16 {
		t.Fatalf("HeaderSize = %d, want 16", HeaderSize)
	}
	if MaxPayload != 65535 {
		t.Fatalf("MaxPayload = %d, want 65535", MaxPayload)
	}
	// The magic really does read as "WNN3" on the wire.
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], Magic)
	if string(encoded[:]) != "WNN3" {
		t.Fatalf("magic bytes = %q, want \"WNN3\"", encoded[:])
	}
	opcodes := map[Opcode]uint16{
		OpCreate: 0x0001, OpCreateAck: 0x0002,
		OpInbound: 0x0010, OpOutbound: 0x0011,
		OpStatusRequest: 0x0020, OpStatusResponse: 0x0021,
		OpClose: 0x0030, OpCloseAck: 0x0031,
		OpError: 0x00F0,
	}
	for opcode, want := range opcodes {
		if uint16(opcode) != want {
			t.Fatalf("%s = 0x%04x, want 0x%04x", opcode, uint16(opcode), want)
		}
	}
}

func TestFrameRoundTrip(t *testing.T) {
	var stream bytes.Buffer
	writer := NewWriter(&stream)
	// Host-to-engine frames, so the reader under test is an engine-side one.
	cases := []struct {
		opcode  Opcode
		payload []byte
	}{
		{OpCreate, []byte(`{"a":1}`)},
		{OpInbound, bytes.Repeat([]byte("d"), 1500)},
		{OpInbound, bytes.Repeat([]byte("m"), MaxPayload)},
		{OpStatusRequest, nil},
		{OpClose, []byte{}},
	}
	for _, item := range cases {
		if err := writer.Write(item.opcode, item.payload); err != nil {
			t.Fatalf("write %s: %v", item.opcode, err)
		}
	}
	reader := NewReader(&stream, false)
	for _, item := range cases {
		opcode, payload, err := reader.Read()
		if err != nil {
			t.Fatalf("read %s: %v", item.opcode, err)
		}
		if opcode != item.opcode {
			t.Fatalf("opcode = %s, want %s", opcode, item.opcode)
		}
		if len(payload) != len(item.payload) ||
			(len(payload) > 0 && !bytes.Equal(payload, item.payload)) {
			t.Fatalf("%s payload length = %d, want %d",
				opcode, len(payload), len(item.payload))
		}
	}
	if _, _, err := reader.Read(); !errors.Is(err, io.EOF) {
		t.Fatalf("read past end = %v, want io.EOF", err)
	}
}

// frame builds a raw header so the reader's validation can be tested against
// bytes no conforming writer would ever produce.
func frame(magic uint32, version uint16, opcode Opcode, length, reserved uint32) []byte {
	header := make([]byte, HeaderSize)
	binary.LittleEndian.PutUint32(header[0:4], magic)
	binary.LittleEndian.PutUint16(header[4:6], version)
	binary.LittleEndian.PutUint16(header[6:8], uint16(opcode))
	binary.LittleEndian.PutUint32(header[8:12], length)
	binary.LittleEndian.PutUint32(header[12:16], reserved)
	return header
}

func TestReaderRejectsMalformedHeaders(t *testing.T) {
	cases := []struct {
		name   string
		stream []byte
	}{
		{"wrong magic", frame(0xDEADBEEF, Version, OpInbound, 1, 0)},
		{"wrong version", frame(Magic, 2, OpInbound, 1, 0)},
		{"nonzero reserved", frame(Magic, Version, OpInbound, 1, 1)},
		{"unknown opcode", frame(Magic, Version, Opcode(0x0999), 1, 0)},
		{"oversize length", frame(Magic, Version, OpInbound, MaxPayload+1, 0)},
		{"payload on close", frame(Magic, Version, OpClose, 4, 0)},
		{"payload on status request", frame(Magic, Version, OpStatusRequest, 4, 0)},
		{"empty inbound", frame(Magic, Version, OpInbound, 0, 0)},
		{"wrong direction", frame(Magic, Version, OpOutbound, 1, 0)},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			_, _, err := NewReader(bytes.NewReader(item.stream), false).Read()
			if err == nil {
				t.Fatal("a malformed header was accepted")
			}
			if !errors.Is(err, ErrInvalidFrame) &&
				!errors.Is(err, ErrPayloadTooLarge) {
				t.Fatalf("error = %v, want a tear-down error", err)
			}
		})
	}
}

// TestReaderNeverResynchronises is the property the reference header is
// emphatic about: after a bad frame the stream is dead, and a valid frame
// sitting behind the bad one must NOT be returned.
func TestReaderNeverResynchronises(t *testing.T) {
	var stream bytes.Buffer
	stream.Write(frame(0xDEADBEEF, Version, OpInbound, 0, 0))
	good := &bytes.Buffer{}
	if err := NewWriter(good).Write(OpStatusRequest, nil); err != nil {
		t.Fatalf("write good frame: %v", err)
	}
	stream.Write(good.Bytes())

	reader := NewReader(bytes.NewReader(stream.Bytes()), false)
	if _, _, err := reader.Read(); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("first read = %v, want ErrInvalidFrame", err)
	}
	// The caller must stop here. If it did not, it would now be reading from a
	// stream position an attacker chose, so assert the reader offers no help:
	// the next read must not hand back the well-formed frame as if nothing
	// happened.
	opcode, _, err := reader.Read()
	if err == nil && opcode == OpStatusRequest {
		t.Fatal("reader resynchronised onto the following frame")
	}
}

func TestDirectionFilterIsPerRole(t *testing.T) {
	var stream bytes.Buffer
	if err := NewWriter(&stream).Write(OpOutbound, []byte("d")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// A host-side reader accepts it.
	if opcode, _, err := NewReader(
		bytes.NewReader(stream.Bytes()), true,
	).Read(); err != nil || opcode != OpOutbound {
		t.Fatalf("host reader: opcode=%s err=%v", opcode, err)
	}
	// An engine-side reader refuses it.
	if _, _, err := NewReader(
		bytes.NewReader(stream.Bytes()), false,
	).Read(); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("engine reader accepted an engine-to-host frame: %v", err)
	}
}

func TestReaderReportsTruncatedPayload(t *testing.T) {
	stream := append(frame(Magic, Version, OpInbound, 8, 0), 'a', 'b')
	_, _, err := NewReader(bytes.NewReader(stream), false).Read()
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("error = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestWriterRefusesFramesADecoderWouldReject(t *testing.T) {
	writer := NewWriter(io.Discard)
	if err := writer.Write(OpInbound, make([]byte, MaxPayload+1)); !errors.Is(
		err, ErrPayloadTooLarge,
	) {
		t.Fatalf("oversize = %v, want ErrPayloadTooLarge", err)
	}
	if err := writer.Write(OpClose, []byte("x")); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("payload on close = %v, want ErrInvalidFrame", err)
	}
	if err := writer.Write(OpInbound, nil); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("empty inbound = %v, want ErrInvalidFrame", err)
	}
	if err := writer.Write(Opcode(0x0999), nil); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("unknown opcode = %v, want ErrInvalidFrame", err)
	}
}

// harness drives one Serve conversation over in-memory pipes against a real
// loopback UDP gateway, which is what makes this an end-to-end datapath test
// rather than a codec test.
type harness struct {
	t       *testing.T
	reader  *Reader
	writer  *Writer
	raw     io.Writer
	gateway *net.UDPConn
	served  chan error
}

// writeRaw bypasses the Writer so a test can put bytes on the wire that no
// conforming encoder would produce.
func (h *harness) writeRaw(bytes []byte) (int, error) { return h.raw.Write(bytes) }

func newHarness(t *testing.T) *harness {
	t.Helper()
	gateway, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1), Port: 0,
	})
	if err != nil {
		t.Fatalf("listen gateway: %v", err)
	}
	t.Cleanup(func() { _ = gateway.Close() })

	hostReader, engineWriter := io.Pipe()
	engineReader, hostWriter := io.Pipe()
	served := make(chan error, 1)
	go func() {
		served <- Serve(engineReader, engineWriter, func(blob []byte) (*datapath.Engine, error) {
			config, parseErr := datapath.ParseConfig(blob)
			if parseErr != nil {
				return nil, parseErr
			}
			socket, listenErr := net.ListenUDP("udp4", &net.UDPAddr{
				IP: net.IPv4(127, 0, 0, 1), Port: 0,
			})
			if listenErr != nil {
				return nil, listenErr
			}
			return datapath.OpenWithPacketConn(config, socket)
		})
		_ = engineWriter.Close()
	}()
	h := &harness{
		t:       t,
		reader:  NewReader(hostReader, true),
		writer:  NewWriter(hostWriter),
		raw:     hostWriter,
		gateway: gateway,
		served:  served,
	}
	t.Cleanup(func() { _ = hostWriter.Close() })
	return h
}

func (h *harness) expect(want Opcode) []byte {
	h.t.Helper()
	opcode, payload, err := h.reader.Read()
	if err != nil {
		h.t.Fatalf("expecting %s: %v", want, err)
	}
	if opcode != want {
		h.t.Fatalf("got %s (%q), want %s", opcode, payload, want)
	}
	return append([]byte(nil), payload...)
}

func (h *harness) configJSON() []byte {
	return []byte(`{"contract":"` + datapath.ContractVersion +
		`","payload":"` + datapath.PayloadAWGDatagram +
		`","carrier":"` + datapath.CarrierDirectAWG +
		`","gateway_endpoint":"` + h.gateway.LocalAddr().String() +
		`","session_id":"duplex-test"}`)
}

// TestServeMovesDatagramsInBothDirections is the framed-transport twin of the
// in-process loopback test: bytes go in as Inbound frames, come out of a real
// UDP socket, and return as Outbound frames.
func TestServeMovesDatagramsInBothDirections(t *testing.T) {
	h := newHarness(t)

	// There is no banner frame; the first thing on the wire is the host's
	// Create. A banner would be an undefined opcode and would tear the channel
	// down at a conforming host.
	if err := h.writer.Write(OpCreate, h.configJSON()); err != nil {
		t.Fatalf("write create: %v", err)
	}
	var ack datapath.Status
	if err := json.Unmarshal(h.expect(OpCreateAck), &ack); err != nil {
		t.Fatalf("decode create-ack: %v", err)
	}
	if ack.Contract != datapath.ContractVersion || !ack.Up {
		t.Fatalf("create-ack status = %+v", ack)
	}

	payload := []byte("framed-duplex-host-to-gateway")
	if err := h.writer.Write(OpInbound, payload); err != nil {
		t.Fatalf("write inbound: %v", err)
	}
	buffer := make([]byte, 2048)
	_ = h.gateway.SetReadDeadline(time.Now().Add(10 * time.Second))
	count, from, err := h.gateway.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("gateway read: %v", err)
	}
	if !bytes.Equal(buffer[:count], payload) {
		t.Fatalf("gateway got %q, want %q", buffer[:count], payload)
	}

	reply := []byte("framed-duplex-gateway-to-host")
	if _, err := h.gateway.WriteToUDP(reply, from); err != nil {
		t.Fatalf("gateway write: %v", err)
	}
	if got := h.expect(OpOutbound); !bytes.Equal(got, reply) {
		t.Fatalf("outbound frame = %q, want %q", got, reply)
	}

	if err := h.writer.Write(OpStatusRequest, nil); err != nil {
		t.Fatalf("write status request: %v", err)
	}
	var status datapath.Status
	if err := json.Unmarshal(h.expect(OpStatusResponse), &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.TxDatagrams != 1 || status.RxDatagrams != 1 {
		t.Fatalf("status tx=%d rx=%d, want 1/1", status.TxDatagrams, status.RxDatagrams)
	}
	if status.SessionID != "duplex-test" {
		t.Fatalf("status session_id = %q", status.SessionID)
	}

	if err := h.writer.Write(OpClose, nil); err != nil {
		t.Fatalf("write close: %v", err)
	}
	// CloseAck is empty by the normative framing: final counters must be
	// fetched with StatusRequest before Close, as done above.
	if payload := h.expect(OpCloseAck); len(payload) != 0 {
		t.Fatalf("close-ack carried %d bytes, must be empty", len(payload))
	}
	select {
	case err := <-h.served:
		if err != nil {
			t.Fatalf("Serve returned %v for an orderly close", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after a Close frame")
	}
}

func TestServeRefusesASecondCreate(t *testing.T) {
	h := newHarness(t)
	if err := h.writer.Write(OpCreate, h.configJSON()); err != nil {
		t.Fatalf("write create: %v", err)
	}
	h.expect(OpCreateAck)
	if err := h.writer.Write(OpCreate, h.configJSON()); err != nil {
		t.Fatalf("write second create: %v", err)
	}
	if message := h.expect(OpError); !bytes.Contains(
		message, []byte("already has an open datapath"),
	) {
		t.Fatalf("second create error = %q", message)
	}
}

func TestServeReportsBadConfigurationWithoutDying(t *testing.T) {
	h := newHarness(t)
	bad := []byte(`{"contract":"` + datapath.ContractVersion +
		`","payload":"ip-packet","carrier":"` + datapath.CarrierDirectAWG +
		`","gateway_endpoint":"203.0.113.9:51820"}`)
	if err := h.writer.Write(OpCreate, bad); err != nil {
		t.Fatalf("write create: %v", err)
	}
	if message := h.expect(OpError); !bytes.Contains(
		message, []byte("ip-packet"),
	) {
		t.Fatalf("error frame = %q, want the ip-packet refusal", message)
	}
	// The session survives, and a valid configuration still works.
	if err := h.writer.Write(OpCreate, h.configJSON()); err != nil {
		t.Fatalf("write recovery create: %v", err)
	}
	h.expect(OpCreateAck)
}

func TestServeRejectsInboundBeforeCreate(t *testing.T) {
	h := newHarness(t)
	if err := h.writer.Write(OpInbound, []byte("too early")); err != nil {
		t.Fatalf("write inbound: %v", err)
	}
	if message := h.expect(OpError); !bytes.Contains(
		message, []byte("before create"),
	) {
		t.Fatalf("error frame = %q", message)
	}
}

// TestServeTearsDownOnAMalformedFrame proves the engine does not try to
// recover from a corrupt stream, and reports why before it goes.
func TestServeTearsDownOnAMalformedFrame(t *testing.T) {
	h := newHarness(t)
	if err := h.writer.Write(OpCreate, h.configJSON()); err != nil {
		t.Fatalf("write create: %v", err)
	}
	h.expect(OpCreateAck)

	// Write a header a conforming writer would never emit.
	raw := frame(Magic, 9, OpInbound, 1, 0)
	if _, err := h.writeRaw(raw); err != nil {
		t.Fatalf("write raw: %v", err)
	}
	if message := h.expect(OpError); !bytes.Contains(message, []byte("version")) {
		t.Fatalf("error frame = %q, want a version complaint", message)
	}
	select {
	case err := <-h.served:
		if !errors.Is(err, ErrInvalidFrame) {
			t.Fatalf("Serve returned %v, want ErrInvalidFrame", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve kept running after a malformed frame")
	}
}

func TestServeRequiresBothStreamsAndAnOpener(t *testing.T) {
	if err := Serve(nil, io.Discard, func([]byte) (*datapath.Engine, error) {
		return nil, nil
	}); err == nil {
		t.Fatal("Serve accepted a nil reader")
	}
	if err := Serve(bytes.NewReader(nil), io.Discard, nil); err == nil {
		t.Fatal("Serve accepted a nil opener")
	}
}

// TestServeStopsInboundAfterEngineToHostPipeBreaks is the negative of
// Serve's ownership claim: a host that loses the engine-to-host pipe must
// not keep a live UDP sender. Before the pump closed the engine on Write
// failure, a second Inbound still reached the gateway (measured).
func TestServeStopsInboundAfterEngineToHostPipeBreaks(t *testing.T) {
	gateway, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1), Port: 0,
	})
	if err != nil {
		t.Fatalf("listen gateway: %v", err)
	}
	t.Cleanup(func() { _ = gateway.Close() })

	hostReader, engineWriter := io.Pipe()
	engineReader, hostWriter := io.Pipe()
	t.Cleanup(func() { _ = hostWriter.Close() })
	served := make(chan error, 1)
	go func() {
		served <- Serve(engineReader, engineWriter, func(blob []byte) (*datapath.Engine, error) {
			config, parseErr := datapath.ParseConfig(blob)
			if parseErr != nil {
				return nil, parseErr
			}
			socket, listenErr := net.ListenUDP("udp4", &net.UDPAddr{
				IP: net.IPv4(127, 0, 0, 1), Port: 0,
			})
			if listenErr != nil {
				return nil, listenErr
			}
			return datapath.OpenWithPacketConn(config, socket)
		})
		_ = engineWriter.Close()
	}()

	reader := NewReader(hostReader, true)
	writer := NewWriter(hostWriter)
	cfg := []byte(`{"contract":"` + datapath.ContractVersion +
		`","payload":"` + datapath.PayloadAWGDatagram +
		`","carrier":"` + datapath.CarrierDirectAWG +
		`","gateway_endpoint":"` + gateway.LocalAddr().String() +
		`","session_id":"duplex-pipebreak"}`)
	if err := writer.Write(OpCreate, cfg); err != nil {
		t.Fatalf("write create: %v", err)
	}
	op, _, err := reader.Read()
	if err != nil || op != OpCreateAck {
		t.Fatalf("create-ack: op=%s err=%v", op, err)
	}

	first := []byte("pipebreak-before")
	if err := writer.Write(OpInbound, first); err != nil {
		t.Fatalf("write inbound1: %v", err)
	}
	buf := make([]byte, 2048)
	_ = gateway.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, from, err := gateway.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("gateway read1: %v", err)
	}
	if string(buf[:n]) != string(first) {
		t.Fatalf("gateway got %q, want %q", buf[:n], first)
	}

	reply := []byte("pipebreak-reply")
	if _, err := gateway.WriteToUDP(reply, from); err != nil {
		t.Fatalf("gateway write reply: %v", err)
	}
	op, payload, err := reader.Read()
	if err != nil || op != OpOutbound {
		t.Fatalf("outbound: op=%s err=%v payload=%q", op, err, payload)
	}
	if string(payload) != string(reply) {
		t.Fatalf("outbound = %q, want %q", payload, reply)
	}

	if err := hostReader.Close(); err != nil {
		t.Fatalf("close hostReader: %v", err)
	}
	wake := []byte("pipebreak-wake")
	if _, err := gateway.WriteToUDP(wake, from); err != nil {
		t.Fatalf("gateway wake: %v", err)
	}
	// Pump is blocked in ReadOutbound until the wake arrives, then Write
	// fails on the closed pipe and must Close the engine. 300ms is the
	// same order as the 200ms measurement that observed the leak.
	time.Sleep(300 * time.Millisecond)

	after := []byte("pipebreak-after")
	if err := writer.Write(OpInbound, after); err != nil {
		t.Fatalf("write inbound2: %v", err)
	}
	_ = gateway.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	n2, _, err2 := gateway.ReadFromUDP(buf)
	if err2 == nil {
		t.Fatalf("inbound after engine-to-host pipe break reached gateway: n=%d payload=%q", n2, buf[:n2])
	}

	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after inbound against a dead engine-to-host pipe")
	}
}
