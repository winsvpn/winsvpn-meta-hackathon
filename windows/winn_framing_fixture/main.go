// SPDX-License-Identifier: MIT
//
// WNN3 FRAMING CONFORMANCE FIXTURE. This is NOT an engine, and it is not
// shippable.
//
// It was written as a test double, when the real engine did not exist and the
// Windows host had nothing to talk to. That is over: winn_protocol_experimental/
// cmd/winn-datapath ships, and the Windows host runs it. This binary was kept
// for the one thing it is still uniquely good for -- being a SECOND INDEPENDENT
// IMPLEMENTATION of the frame layout in windows/runner/winn_frame.h.
//
// That is worth something no single implementation can provide. A framing bug
// that both the encoder and the decoder of one implementation share is invisible
// to that implementation's own round-trip test: it encodes wrongly, decodes its
// own wrong bytes back, and passes. Only a second implementation, written from
// the layout rather than from the first implementation's code, can catch it.
// tools/verify_winn_framing_conformance.sh checks the two against one byte-exact
// vector, in both directions.
//
// IT CANNOT BE REACHED AT RUNTIME, by two independent mechanisms, and neither
// may be relaxed to make anything here convenient:
//   - the host resolves `winn-datapath.exe` beside its own module and never this
//     artifact's name (FindWinnDatapathExecutable, windows_tunnel_backend.cpp);
//   - StartWindowsWinnEngine refuses any CreateAck without
//     `"contract":"winn-datapath/1"`, and this fixture emits no contract field.
//
// It also still identifies itself in-band as "winn-test-double" in every status
// document. That string is deliberately left alone: it is the third, in-band
// refusal, and the Windows host copies it verbatim rather than inferring engine
// identity from a file name.
//
// It honours the two structural rules the contract puts on the Go side:
//   - it never creates an OS network interface, edits a route, or touches DNS;
//   - it never shells out to another process.
//
// Behaviour: a loopback "protocol". Every inbound IPv4 packet comes back out
// with source and destination swapped, and ICMP echo requests come back as
// well-formed echo replies. That makes the whole host path -- WinTun read ->
// frame -> pipe -> engine -> pipe -> frame -> WinTun write -- observable with
// nothing but a ping and no server anywhere.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// Must match windows/runner/winn_frame.h exactly.
const (
	frameMagic       uint32 = 0x334E4E57 // 'W' 'N' 'N' '3' little-endian
	frameVersion     uint16 = 1
	frameHeaderBytes        = 16
	maxFramePayload  uint32 = 65535

	opCreate         uint16 = 0x0001
	opCreateAck      uint16 = 0x0002
	opInbound        uint16 = 0x0010
	opOutbound       uint16 = 0x0011
	opStatusRequest  uint16 = 0x0020
	opStatusResponse uint16 = 0x0021
	opClose          uint16 = 0x0030
	opCloseAck       uint16 = 0x0031
	opError          uint16 = 0x00F0

	engineIdentity = "winn-test-double"
)

func isHostToEngine(op uint16) bool {
	return op == opCreate || op == opInbound || op == opStatusRequest ||
		op == opClose
}

func isEngineToHost(op uint16) bool {
	return op == opCreateAck || op == opOutbound || op == opStatusResponse ||
		op == opCloseAck || op == opError
}

type frame struct {
	opcode  uint16
	payload []byte
}

// readFrame decodes exactly one host->engine frame. Every rejection is fatal to
// the channel: resynchronizing after a bad length would let a confused peer
// choose the next frame boundary.
func readFrame(r *bufio.Reader) (frame, error) {
	header := make([]byte, frameHeaderBytes)
	if _, err := io.ReadFull(r, header); err != nil {
		return frame{}, err
	}
	if binary.LittleEndian.Uint32(header[0:4]) != frameMagic {
		return frame{}, errors.New("winn frame: bad magic")
	}
	if binary.LittleEndian.Uint16(header[4:6]) != frameVersion {
		return frame{}, errors.New("winn frame: bad version")
	}
	if binary.LittleEndian.Uint32(header[12:16]) != 0 {
		return frame{}, errors.New("winn frame: reserved must be zero")
	}
	op := binary.LittleEndian.Uint16(header[6:8])
	length := binary.LittleEndian.Uint32(header[8:12])
	if length > maxFramePayload {
		return frame{}, errors.New("winn frame: oversize payload")
	}
	if !isHostToEngine(op) {
		if isEngineToHost(op) {
			return frame{}, errors.New("winn frame: wrong direction")
		}
		return frame{}, errors.New("winn frame: unknown opcode")
	}
	if (op == opStatusRequest || op == opClose) && length != 0 {
		return frame{}, errors.New("winn frame: payload on empty opcode")
	}
	if op == opInbound && length == 0 {
		return frame{}, errors.New("winn frame: empty packet")
	}
	payload := make([]byte, length)
	if length != 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return frame{}, err
		}
	}
	return frame{opcode: op, payload: payload}, nil
}

// writer serializes frames from the packet path and the control path onto the
// single stdout pipe. Interleaved partial writes would corrupt the stream.
type writer struct {
	mu  sync.Mutex
	out *bufio.Writer
}

func (w *writer) write(op uint16, payload []byte) error {
	if uint32(len(payload)) > maxFramePayload {
		return errors.New("winn frame: oversize payload")
	}
	if !isEngineToHost(op) {
		return errors.New("winn frame: refusing to emit a host-bound opcode")
	}
	header := make([]byte, frameHeaderBytes)
	binary.LittleEndian.PutUint32(header[0:4], frameMagic)
	binary.LittleEndian.PutUint16(header[4:6], frameVersion)
	binary.LittleEndian.PutUint16(header[6:8], op)
	binary.LittleEndian.PutUint32(header[8:12], uint32(len(payload)))
	binary.LittleEndian.PutUint32(header[12:16], 0)

	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.out.Write(header); err != nil {
		return err
	}
	if len(payload) != 0 {
		if _, err := w.out.Write(payload); err != nil {
			return err
		}
	}
	return w.out.Flush()
}

type createConfig struct {
	Protocol string `json:"protocol"`
	MTU      int    `json:"mtu"`
}

type statusDocument struct {
	Engine          string `json:"engine"`
	Protocol        string `json:"protocol"`
	Handle          uint64 `json:"handle"`
	Up              bool   `json:"up"`
	MTU             int    `json:"mtu"`
	PacketsInbound  uint64 `json:"packets_inbound"`
	PacketsOutbound uint64 `json:"packets_outbound"`
	BytesInbound    uint64 `json:"bytes_inbound"`
	BytesOutbound   uint64 `json:"bytes_outbound"`
	Note            string `json:"note"`
}

type engine struct {
	mu              sync.Mutex
	handle          uint64
	protocol        string
	mtu             int
	up              bool
	packetsInbound  uint64
	packetsOutbound uint64
	bytesInbound    uint64
	bytesOutbound   uint64
}

func (e *engine) status() statusDocument {
	e.mu.Lock()
	defer e.mu.Unlock()
	return statusDocument{
		Engine:          engineIdentity,
		Protocol:        e.protocol,
		Handle:          e.handle,
		Up:              e.up,
		MTU:             e.mtu,
		PacketsInbound:  e.packetsInbound,
		PacketsOutbound: e.packetsOutbound,
		BytesInbound:    e.bytesInbound,
		BytesOutbound:   e.bytesOutbound,
		Note:            "test double: loopback only, carries no Winn Protocol traffic",
	}
}

func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// loopback turns an inbound packet into the packet that should come back out.
// Returns nil when the packet is not something the double can answer, which the
// caller treats as a silent drop rather than an error.
func loopback(packet []byte) []byte {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return nil
	}
	ihl := int(packet[0]&0x0F) * 4
	if ihl < 20 || len(packet) < ihl {
		return nil
	}
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if total < ihl || total > len(packet) {
		return nil
	}
	out := make([]byte, total)
	copy(out, packet[:total])

	// Swap source and destination so the reply is addressed back to the sender.
	var addr [4]byte
	copy(addr[:], out[12:16])
	copy(out[12:16], out[16:20])
	copy(out[16:20], addr[:])

	if out[9] == 1 && total >= ihl+8 && out[ihl] == 8 {
		// ICMP echo request -> echo reply.
		out[ihl] = 0
		out[ihl+2] = 0
		out[ihl+3] = 0
		binary.BigEndian.PutUint16(out[ihl+2:ihl+4], ipChecksum(out[ihl:total]))
	}

	out[10] = 0
	out[11] = 0
	binary.BigEndian.PutUint16(out[10:12], ipChecksum(out[:ihl]))
	return out
}

func run() error {
	// The real engine takes its configuration only over the pipe. Refuse any
	// command line so the launch contract cannot drift, exactly as
	// windows/awg_engine/main.go does.
	if len(os.Args) != 1 {
		return errors.New("winn engine double accepts no arguments")
	}
	in := bufio.NewReaderSize(os.Stdin, 1<<16)
	w := &writer{out: bufio.NewWriterSize(os.Stdout, 1<<16)}
	e := &engine{}

	first, err := readFrame(in)
	if err != nil {
		return err
	}
	if first.opcode != opCreate {
		return fmt.Errorf("winn engine double: expected create, got 0x%04X",
			first.opcode)
	}
	var config createConfig
	if err := json.Unmarshal(first.payload, &config); err != nil {
		_ = w.write(opError, []byte("create config is not valid JSON"))
		return err
	}
	e.mu.Lock()
	e.handle = 1
	e.protocol = config.Protocol
	e.mtu = config.MTU
	e.up = true
	e.mu.Unlock()

	ack, err := json.Marshal(e.status())
	if err != nil {
		return err
	}
	if err := w.write(opCreateAck, ack); err != nil {
		return err
	}

	for {
		f, err := readFrame(in)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		switch f.opcode {
		case opInbound:
			e.mu.Lock()
			e.packetsInbound++
			e.bytesInbound += uint64(len(f.payload))
			e.mu.Unlock()
			reply := loopback(f.payload)
			if reply == nil {
				continue
			}
			if err := w.write(opOutbound, reply); err != nil {
				return err
			}
			e.mu.Lock()
			e.packetsOutbound++
			e.bytesOutbound += uint64(len(reply))
			e.mu.Unlock()
		case opStatusRequest:
			document, err := json.Marshal(e.status())
			if err != nil {
				return err
			}
			if err := w.write(opStatusResponse, document); err != nil {
				return err
			}
		case opClose:
			e.mu.Lock()
			e.up = false
			e.mu.Unlock()
			return w.write(opCloseAck, nil)
		default:
			return fmt.Errorf("winn engine double: unhandled opcode 0x%04X",
				f.opcode)
		}
	}
}

func main() {
	// Conformance mode. No sockets, no stdio protocol, no privileges: it only
	// runs the framing against the vectors the C++ half uses. See selftest.go.
	for _, arg := range os.Args[1:] {
		if arg == "-selftest" || arg == "--selftest" {
			if err := runSelfTest(); err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				os.Exit(1)
			}
			return
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
