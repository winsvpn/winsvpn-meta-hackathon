package duplex

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"winsvpn.local/winnprotocol/datapath"
)

// Opener creates the engine for one conversation. The subprocess entry point
// supplies this so the descriptor it was launched with — the protected one on
// Android — is bound outside the wire protocol, where a peer cannot influence
// it. A descriptor number sent inside a Create frame would be meaningless
// across a process boundary anyway.
type Opener func(configJSON []byte) (*datapath.Engine, error)

// WireVersion identifies this framing in the contract banner. The on-the-wire
// version field is Version; this string is for humans and build verification.
const WireVersion = "winn-datapath-duplex/1"

// Serve runs one conversation to completion over the supplied streams. It
// returns nil for an orderly shutdown: either a Close frame or a clean EOF.
//
// Serve owns the engine it opens and always closes it before returning, so a
// host that dies mid-session cannot leave a datapath running.
//
// There is no banner frame. The normative opcode set has none, and emitting an
// undefined opcode would make a conforming host tear the channel down before it
// ever sent a configuration. A host that wants to check the engine's build
// runs it once with -print-contract.
func Serve(input io.Reader, output io.Writer, open Opener) error {
	if input == nil || output == nil {
		return errors.New("duplex serve requires both streams")
	}
	if open == nil {
		return errors.New("duplex serve requires an engine opener")
	}
	writer := NewWriter(output)
	// The engine accepts host-to-engine opcodes only.
	reader := NewReader(input, false)

	session := &session{writer: writer, open: open}
	defer session.shutdown()

	for {
		opcode, payload, err := reader.Read()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			// The channel is already untrustworthy, so telling the peer why is
			// best-effort. It is still worth doing: a host that logs the Error
			// payload gets the real reason instead of a bare broken pipe.
			_ = writer.Write(OpError, []byte(err.Error()))
			return err
		}
		done, err := session.handle(opcode, payload)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
}

type session struct {
	writer *Writer
	open   Opener

	mu       sync.Mutex
	engine   *datapath.Engine
	pumpDone chan struct{}
}

func (s *session) handle(opcode Opcode, payload []byte) (bool, error) {
	switch opcode {
	case OpCreate:
		return false, s.handleCreate(payload)
	case OpInbound:
		return false, s.handleInbound(payload)
	case OpStatusRequest:
		return false, s.writer.Write(OpStatusResponse, []byte(s.statusJSON()))
	case OpClose:
		// CloseAck carries no payload by the normative framing. A host that
		// wants final counters must send StatusRequest before Close.
		s.shutdown()
		return true, s.writer.Write(OpCloseAck, nil)
	default:
		// The Reader already rejected unknown and wrong-direction opcodes, so
		// reaching here means this switch and the opcode table disagree.
		return false, fmt.Errorf("unhandled duplex opcode %s", opcode)
	}
}

func (s *session) handleCreate(configJSON []byte) error {
	s.mu.Lock()
	if s.engine != nil {
		s.mu.Unlock()
		return s.writer.Write(OpError,
			[]byte("this duplex session already has an open datapath; one "+
				"session carries exactly one tunnel"))
	}
	s.mu.Unlock()

	// The reader's buffer is reused by the next Read, so the configuration
	// must be copied before anything can block on it.
	blob := append([]byte(nil), configJSON...)
	engine, err := s.open(blob)
	if err != nil {
		return s.writer.Write(OpError, []byte(err.Error()))
	}

	s.mu.Lock()
	s.engine = engine
	s.pumpDone = make(chan struct{})
	pumpDone := s.pumpDone
	s.mu.Unlock()

	go s.pump(engine, pumpDone)
	return s.writer.Write(OpCreateAck, []byte(engine.StatusJSON()))
}

func (s *session) handleInbound(payload []byte) error {
	engine := s.current()
	if engine == nil {
		return s.writer.Write(OpError,
			[]byte("inbound datagram before create"))
	}
	if _, err := engine.WriteInbound(payload); err != nil {
		// A rejected datagram is not a session failure: an oversize frame or a
		// transient carrier write must not tear down a working tunnel.
		return s.writer.Write(OpError, []byte(err.Error()))
	}
	return nil
}

// pump forwards datagrams from the engine to the peer until the engine stops.
func (s *session) pump(engine *datapath.Engine, done chan struct{}) {
	defer close(done)
	buffer := make([]byte, datapath.MaxDatagramCeiling)
	for {
		count, err := engine.ReadOutbound(buffer)
		// A truncated datagram plus an error must not be emitted as a valid
		// Outbound: the host would inject the short payload before it saw
		// OpError. Only a clean read is forwarded.
		if count > 0 && err == nil {
			if writeErr := s.writer.Write(
				OpOutbound, buffer[:count],
			); writeErr != nil {
				// The engine-to-host stream is dead. Closing the engine stops
				// further Inbound from reaching the gateway; otherwise Serve
				// keeps accepting host frames and the tunnel silently becomes
				// upload-only (measured 2026-08-12).
				_ = engine.Close()
				return
			}
		}
		if err != nil {
			if errors.Is(err, datapath.ErrClosed) {
				return
			}
			if errors.Is(err, datapath.ErrDatagramTooLarge) {
				// buffer is sized at the absolute ceiling, so this cannot
				// happen; reporting rather than looping keeps it visible.
				_ = s.writer.Write(OpError, []byte(err.Error()))
				continue
			}
			_ = s.writer.Write(OpError, []byte(err.Error()))
			_ = engine.Close()
			return
		}
	}
}

func (s *session) current() *datapath.Engine {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.engine
}

func (s *session) statusJSON() string {
	engine := s.current()
	if engine == nil {
		return `{"contract":"` + datapath.ContractVersion +
			`","up":false,"closed":true,` +
			`"carrier_error":"no datapath has been created"}`
	}
	return engine.StatusJSON()
}

// shutdown closes the engine and waits for the pump. It is idempotent.
func (s *session) shutdown() {
	s.mu.Lock()
	engine := s.engine
	pumpDone := s.pumpDone
	s.engine = nil
	s.pumpDone = nil
	s.mu.Unlock()
	if engine == nil {
		return
	}
	_ = engine.Close()
	if pumpDone != nil {
		<-pumpDone
	}
}
