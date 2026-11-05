// Package duplex is the framed duplex wire protocol that carries the Winn
// datapath contract across a process boundary.
//
// It exists because Android and Windows already consume Go engines as
// subprocesses — libxray.so is executed from nativeLibraryDir on Android and
// winsvpn_awg_engine.exe is a standalone binary on Windows — and adding a fifth
// native strategy for Winn would be gratuitous. iOS and macOS use the c-archive
// in ../../cdatapath instead, because iOS forbids subprocesses.
//
// # The layout is normative and is not this package's to choose
//
// The byte layout below is fixed by WINN_PROTOCOL_PLATFORM_PLAN.md section 2
// and its reference implementation, windows/runner/winn_frame.h. This package
// is the Go side of THAT header, not an independent design. Where the two
// disagree the header is right and this file is the bug; TestGoldenFrameBytes
// pins the exact bytes so a disagreement fails the build rather than a tunnel.
//
//	offset  size  field
//	0       4     magic    u32 little-endian, Magic ("WNN3")
//	4       2     version  u16 little-endian, Version
//	6       2     opcode   u16 little-endian, see Opcode
//	8       4     length   u32 little-endian, payload byte count
//	12      4     reserved u32 little-endian, must be zero
//	16      len   payload
//
// Every field is little-endian, so encoding/binary.LittleEndian maps to it with
// no conversion on either defined Windows target.
//
// # No resynchronisation
//
// A frame whose magic, version, reserved field, opcode, direction or length is
// wrong tears the channel down. It is never skipped and the stream is never
// scanned forward for the next magic: doing that converts a length confusion
// into an attacker-chosen frame boundary. This mirrors DecodeStatus::kInvalid
// in the reference header.
//
// # Direction is part of the contract
//
// Each side rejects opcodes it is not supposed to receive. A Reader is built
// for one role and enforces it, so a confused or hostile peer cannot feed the
// host an inbound packet and have it looped straight back out.
//
// # Conversation
//
//	host   -> engine   Create         payload is the datapath configuration JSON
//	engine -> host     CreateAck      payload is the initial status JSON
//	host   -> engine   Inbound        payload is one datagram, host -> protocol
//	engine -> host     Outbound       payload is one datagram, protocol -> host
//	host   -> engine   StatusRequest  empty
//	engine -> host     StatusResponse payload is status JSON
//	host   -> engine   Close          empty
//	engine -> host     CloseAck       empty, then the stream ends
//	engine -> host     Error          payload is UTF-8 error text, any time
//
// CloseAck carries no payload, by the normative header. A host that wants final
// counters must send StatusRequest BEFORE Close; there is no status in the
// close acknowledgement to read them from.
//
// Outbound frames are produced by the engine's own reader and interleave with
// responses at any time, so a host must demultiplex by opcode rather than
// assume request/response ordering.
//
// # What the packet payloads actually are
//
// The reference header describes Inbound and Outbound payloads as "exactly one
// IP packet". For this engine they are NOT. They are AmneziaWG OUTER
// DATAGRAMS: what the host's own AWG engine would otherwise have sent to and
// received from the gateway's UDP endpoint. The framing is payload-agnostic so
// the wire is unaffected, but a host that feeds raw tun packets in here is
// putting cleartext on the network. See ../doc.go for why the boundary is
// below AmneziaWG rather than above it.
package duplex

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Wire constants. These mirror kFrameMagic, kFrameVersion, kFrameHeaderBytes
// and kMaxFramePayloadBytes in windows/runner/winn_frame.h and must not be
// changed on one side alone.
const (
	// Magic is 'W' 'N' 'N' '3' read as a little-endian u32.
	Magic uint32 = 0x334E4E57

	// Version is the frame version, not the datapath contract version.
	Version uint16 = 1

	// HeaderSize is the fixed frame header length.
	HeaderSize = 16

	// MaxPayload is kMaxFramePayloadBytes: 65535, not 65536.
	MaxPayload = 65535
)

// Opcode identifies a frame's operation.
type Opcode uint16

const (
	OpCreate         Opcode = 0x0001
	OpCreateAck      Opcode = 0x0002
	OpInbound        Opcode = 0x0010
	OpOutbound       Opcode = 0x0011
	OpStatusRequest  Opcode = 0x0020
	OpStatusResponse Opcode = 0x0021
	OpClose          Opcode = 0x0030
	OpCloseAck       Opcode = 0x0031
	OpError          Opcode = 0x00F0
)

// ErrPayloadTooLarge is returned when a frame declares or supplies more than
// MaxPayload bytes.
var ErrPayloadTooLarge = errors.New("winn frame payload exceeds the maximum")

// ErrInvalidFrame is the tear-down condition: a header this side will not
// accept. It is deliberately one error rather than several, because every one
// of them has the same correct response, which is to stop.
var ErrInvalidFrame = errors.New("invalid winn frame")

// PayloadLength decodes the payload length from a frame header.
func PayloadLength(hdr []byte) int {
	if len(hdr) < HeaderSize {
		return 0
	}
	return int(binary.LittleEndian.Uint32(hdr[8:12]))
}

func (opcode Opcode) String() string {
	switch opcode {
	case OpCreate:
		return "create"
	case OpCreateAck:
		return "create-ack"
	case OpInbound:
		return "inbound"
	case OpOutbound:
		return "outbound"
	case OpStatusRequest:
		return "status-request"
	case OpStatusResponse:
		return "status-response"
	case OpClose:
		return "close"
	case OpCloseAck:
		return "close-ack"
	case OpError:
		return "error"
	default:
		return fmt.Sprintf("unknown(0x%04x)", uint16(opcode))
	}
}

// HostToEngine mirrors IsHostToEngineOpcode.
func (opcode Opcode) HostToEngine() bool {
	switch opcode {
	case OpCreate, OpInbound, OpStatusRequest, OpClose:
		return true
	default:
		return false
	}
}

// EngineToHost mirrors IsEngineToHostOpcode.
func (opcode Opcode) EngineToHost() bool {
	switch opcode {
	case OpCreateAck, OpOutbound, OpStatusResponse, OpCloseAck, OpError:
		return true
	default:
		return false
	}
}

// Known mirrors IsKnownOpcode.
func (opcode Opcode) Known() bool {
	return opcode.HostToEngine() || opcode.EngineToHost()
}

// mustBeEmpty reports the opcodes whose payload is fixed as empty. A trailing
// payload on one of these would otherwise be silently discarded.
func (opcode Opcode) mustBeEmpty() bool {
	switch opcode {
	case OpStatusRequest, OpClose, OpCloseAck:
		return true
	default:
		return false
	}
}

// mustBeNonEmpty reports the opcodes that carry exactly one datagram. A
// zero-length one carries nothing and is a protocol error rather than a no-op,
// because silently dropping it hides a broken peer.
func (opcode Opcode) mustBeNonEmpty() bool {
	return opcode == OpInbound || opcode == OpOutbound
}

// Writer serialises frames onto a stream. Its Write is safe for concurrent
// use: the outbound datagram pump and the request responder share one stream,
// and a partially interleaved frame would corrupt it.
type Writer struct {
	mu     sync.Mutex
	writer io.Writer
	header [HeaderSize]byte
}

// NewWriter wraps a stream.
func NewWriter(writer io.Writer) *Writer { return &Writer{writer: writer} }

// Write emits one frame. It refuses to emit a frame the peer's decoder would
// reject, so an encoding bug fails here rather than tearing down the channel
// at the far end where it is much harder to attribute.
func (w *Writer) Write(opcode Opcode, payload []byte) error {
	if !opcode.Known() {
		return fmt.Errorf("%w: opcode %s is not defined", ErrInvalidFrame, opcode)
	}
	if len(payload) > MaxPayload {
		return fmt.Errorf("%w (%d bytes, opcode %s)",
			ErrPayloadTooLarge, len(payload), opcode)
	}
	if opcode.mustBeEmpty() && len(payload) != 0 {
		return fmt.Errorf("%w: %s carries no payload, got %d bytes",
			ErrInvalidFrame, opcode, len(payload))
	}
	if opcode.mustBeNonEmpty() && len(payload) == 0 {
		return fmt.Errorf("%w: %s must carry exactly one datagram",
			ErrInvalidFrame, opcode)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	binary.LittleEndian.PutUint32(w.header[0:4], Magic)
	binary.LittleEndian.PutUint16(w.header[4:6], Version)
	binary.LittleEndian.PutUint16(w.header[6:8], uint16(opcode))
	// #nosec G115 -- this function rejects len(payload) > MaxPayload (65535)
	// above, so the length is already far inside uint32 and cannot truncate.
	binary.LittleEndian.PutUint32(w.header[8:12], uint32(len(payload)))
	binary.LittleEndian.PutUint32(w.header[12:16], 0)
	if _, err := w.writer.Write(w.header[:]); err != nil {
		return fmt.Errorf("write %s frame header: %w", opcode, err)
	}
	if len(payload) == 0 {
		if opcode != OpOutbound && opcode != OpInbound {
			if flusher, ok := w.writer.(interface{ Flush() error }); ok {
				if err := flusher.Flush(); err != nil {
					return fmt.Errorf("flush %s frame: %w", opcode, err)
				}
			}
		}
		return nil
	}
	if _, err := w.writer.Write(payload); err != nil {
		return fmt.Errorf("write %s frame payload: %w", opcode, err)
	}
	if opcode != OpOutbound && opcode != OpInbound {
		if flusher, ok := w.writer.(interface{ Flush() error }); ok {
			if err := flusher.Flush(); err != nil {
				return fmt.Errorf("flush %s frame: %w", opcode, err)
			}
		}
	}
	return nil
}

// Flush flushes buffered data if the underlying writer implements a Flush method.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if flusher, ok := w.writer.(interface{ Flush() error }); ok {
		return flusher.Flush()
	}
	return nil
}

// WriteOutboundBatch emits multiple OpOutbound frames under a single mutex lock.
func (w *Writer) WriteOutboundBatch(payloads [][]byte) error {
	if len(payloads) == 0 {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	var hdr [HeaderSize]byte
	binary.LittleEndian.PutUint32(hdr[0:4], Magic)
	binary.LittleEndian.PutUint16(hdr[4:6], Version)
	binary.LittleEndian.PutUint16(hdr[6:8], uint16(OpOutbound))
	binary.LittleEndian.PutUint32(hdr[12:16], 0)

	for _, payload := range payloads {
		if len(payload) == 0 {
			continue
		}
		if len(payload) > MaxPayload {
			return fmt.Errorf("%w (%d bytes, opcode %s)",
				ErrPayloadTooLarge, len(payload), OpOutbound)
		}
		binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(payload)))
		if _, err := w.writer.Write(hdr[:]); err != nil {
			return fmt.Errorf("write %s frame header: %w", OpOutbound, err)
		}
		if _, err := w.writer.Write(payload); err != nil {
			return fmt.Errorf("write %s frame payload: %w", OpOutbound, err)
		}
	}
	return nil
}

// Reader deserialises frames from a stream for one role. It is
// single-goroutine: one dedicated reader per stream.
type Reader struct {
	reader             io.Reader
	acceptEngineToHost bool
	header             [HeaderSize]byte
	buffer             []byte

	// failed latches the first terminal error. Without it, a stream-oriented
	// reader would silently resynchronise: rejecting a bad header still
	// consumes its 16 bytes, so the next Read would land on whatever follows
	// and hand it back as a valid frame. That is precisely the
	// attacker-chosen frame boundary the reference decoder refuses to allow,
	// so once this reader has failed it stays failed.
	failed error
}

// NewReader wraps a stream for one role. acceptEngineToHost selects the
// direction filter: a host passes true, the engine passes false. Getting this
// backwards is not a subtle bug, it rejects every frame immediately.
func NewReader(reader io.Reader, acceptEngineToHost bool) *Reader {
	return &Reader{
		reader:             reader,
		acceptEngineToHost: acceptEngineToHost,
		buffer:             make([]byte, 0, 2048),
	}
}

// Read returns the next frame. The returned payload aliases an internal buffer
// that the next Read overwrites; a caller that keeps it must copy it.
//
// io.EOF at a frame boundary is returned unwrapped so a caller can treat a
// clean shutdown differently from a truncated frame, which returns
// io.ErrUnexpectedEOF. Every other error is terminal: the caller must stop.
func (r *Reader) Read() (Opcode, []byte, error) {
	if r.failed != nil {
		return 0, nil, r.failed
	}
	opcode, payload, err := r.readFrame()
	if err != nil {
		r.failed = err
		return 0, nil, err
	}
	return opcode, payload, nil
}

// readFrame does the decoding. Every error it returns is terminal, which is
// why Read latches rather than classifies.
func (r *Reader) readFrame() (Opcode, []byte, error) {
	if _, err := io.ReadFull(r.reader, r.header[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return 0, nil, io.EOF
		}
		return 0, nil, fmt.Errorf("read frame header: %w", err)
	}
	if magic := binary.LittleEndian.Uint32(r.header[0:4]); magic != Magic {
		return 0, nil, fmt.Errorf("%w: magic 0x%08x, want 0x%08x",
			ErrInvalidFrame, magic, Magic)
	}
	if version := binary.LittleEndian.Uint16(r.header[4:6]); version != Version {
		return 0, nil, fmt.Errorf("%w: version %d, want %d",
			ErrInvalidFrame, version, Version)
	}
	if reserved := binary.LittleEndian.Uint32(r.header[12:16]); reserved != 0 {
		return 0, nil, fmt.Errorf("%w: reserved field is 0x%08x, must be zero",
			ErrInvalidFrame, reserved)
	}
	opcode := Opcode(binary.LittleEndian.Uint16(r.header[6:8]))
	length := binary.LittleEndian.Uint32(r.header[8:12])
	if !opcode.Known() {
		return 0, nil, fmt.Errorf("%w: opcode 0x%04x is not defined",
			ErrInvalidFrame, uint16(opcode))
	}
	accepted := opcode.HostToEngine()
	if r.acceptEngineToHost {
		accepted = opcode.EngineToHost()
	}
	if !accepted {
		return 0, nil, fmt.Errorf(
			"%w: %s travels the other way on this channel",
			ErrInvalidFrame, opcode,
		)
	}
	if length > MaxPayload {
		return 0, nil, fmt.Errorf("%w (declared %d bytes, opcode %s)",
			ErrPayloadTooLarge, length, opcode)
	}
	if opcode.mustBeEmpty() && length != 0 {
		return 0, nil, fmt.Errorf("%w: %s carries no payload, declared %d bytes",
			ErrInvalidFrame, opcode, length)
	}
	if opcode.mustBeNonEmpty() && length == 0 {
		return 0, nil, fmt.Errorf("%w: %s must carry exactly one datagram",
			ErrInvalidFrame, opcode)
	}
	if length == 0 {
		return opcode, nil, nil
	}
	if cap(r.buffer) < int(length) {
		r.buffer = make([]byte, length)
	}
	r.buffer = r.buffer[:length]
	if _, err := io.ReadFull(r.reader, r.buffer); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return 0, nil, fmt.Errorf("read %s frame payload: %w", opcode, err)
	}
	return opcode, r.buffer, nil
}
