package wcf3

import (
	"errors"
	"math"
	"sync"
)

const (
	DefaultReplayWindow uint64 = 1024
	MinimumReplayWindow uint64 = 64
	MaximumReplayWindow uint64 = 4096
)

type Direction byte

const (
	DirectionIngress Direction = 1
	DirectionEgress  Direction = 2
)

type directionState struct {
	highest uint64
	seen    map[uint64]struct{}
}

// ReplayWindow tracks independent ingress and egress sequence spaces for one
// immutable connection context and epoch. A new epoch requires a new window.
type ReplayWindow struct {
	mu      sync.Mutex
	context Context
	size    uint64
	states  map[Direction]*directionState
}

func NewReplayWindow(
	context Context,
	size uint64,
) (*ReplayWindow, error) {
	if zero16(context.SessionID) || zero16(context.BindingID) ||
		context.PSKGeneration == 0 || context.SequenceEpoch == 0 {
		return nil, errors.New("WCF3 replay context is invalid")
	}
	if size == 0 {
		size = DefaultReplayWindow
	}
	if size < MinimumReplayWindow || size > MaximumReplayWindow {
		return nil, errors.New("WCF3 replay window size is invalid")
	}
	return &ReplayWindow{
		context: context,
		size:    size,
		states: map[Direction]*directionState{
			DirectionIngress: {seen: make(map[uint64]struct{})},
			DirectionEgress:  {seen: make(map[uint64]struct{})},
		},
	}, nil
}

func (window *ReplayWindow) Accept(
	direction Direction,
	frame Frame,
) error {
	if window == nil {
		return errors.New("WCF3 replay window is required")
	}
	window.mu.Lock()
	defer window.mu.Unlock()
	state, ok := window.states[direction]
	if !ok {
		return errors.New("WCF3 direction is invalid")
	}
	if frame.SessionID != window.context.SessionID ||
		frame.BindingID != window.context.BindingID ||
		frame.PSKGeneration != window.context.PSKGeneration ||
		frame.SequenceEpoch != window.context.SequenceEpoch {
		return errors.New("WCF3 replay context mismatch")
	}
	if frame.Sequence == 0 {
		return errors.New("WCF3 sequence is zero")
	}
	if state.highest != 0 && frame.Sequence <= state.highest {
		if state.highest-frame.Sequence >= window.size {
			return errors.New("WCF3 sequence is outside replay window")
		}
		if _, duplicate := state.seen[frame.Sequence]; duplicate {
			return errors.New("WCF3 replay detected")
		}
	}
	if frame.Sequence > state.highest {
		state.highest = frame.Sequence
		floor := uint64(1)
		if state.highest >= window.size {
			floor = state.highest - window.size + 1
		}
		for sequence := range state.seen {
			if sequence < floor {
				delete(state.seen, sequence)
			}
		}
	}
	state.seen[frame.Sequence] = struct{}{}
	return nil
}

// Sequencer allocates non-zero sequence numbers for one direction and epoch.
// It fails closed at MaxUint64 and never wraps to zero.
type Sequencer struct {
	mu        sync.Mutex
	next      uint64
	exhausted bool
}

func NewSequencer(first uint64) (*Sequencer, error) {
	if first == 0 {
		return nil, errors.New("WCF3 first sequence must be non-zero")
	}
	return &Sequencer{next: first}, nil
}

func (sequencer *Sequencer) Next() (uint64, error) {
	if sequencer == nil {
		return 0, errors.New("WCF3 sequencer is required")
	}
	sequencer.mu.Lock()
	defer sequencer.mu.Unlock()
	if sequencer.exhausted {
		return 0, errors.New("WCF3 sequence space is exhausted")
	}
	current := sequencer.next
	if current == math.MaxUint64 {
		sequencer.exhausted = true
	} else {
		sequencer.next++
	}
	return current, nil
}
