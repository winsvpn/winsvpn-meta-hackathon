package stagebreflector

import (
	"crypto/hmac"
	"sync"
)

// AttemptState is the state owned by ClientResponseAcceptor.
type AttemptState uint8

const (
	AttemptStateActive AttemptState = iota
	AttemptStateSucceeded
	AttemptStateFailed
	AttemptStateCancelled
	AttemptStateSuperseded
)

// MonotonicNanosecondClock is a trusted process-local monotonic clock. The
// acceptance domain invokes it while holding its replay lock; response callers
// never provide acceptance timestamps.
type MonotonicNanosecondClock func() uint64

// ClientAcceptanceDomain is the shared authority for client response
// acceptance. It owns the key, trusted clock, bounded replay state, pruning,
// and nondecreasing clock watermark, and is the only acceptor constructor.
//
// Exactly one constructor-created domain must be used per key and local
// acceptance scope. Do not split one scope across parallel domains, because
// doing so splits its replay boundary, and do not reuse a domain for unrelated
// scopes. Domain object identity is the local scope identity; it is never
// serialized onto the wire.
type ClientAcceptanceDomain struct {
	mu           sync.Mutex
	initialized  bool
	key          [KeyLength]byte
	clock        MonotonicNanosecondClock
	capacity     int
	entries      map[[TagLength]byte]uint64
	watermark    uint64
	hasWatermark bool
}

func NewClientAcceptanceDomain(
	key []byte,
	capacity int,
	clock MonotonicNanosecondClock,
) (*ClientAcceptanceDomain, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	if capacity <= 0 || capacity > MaxReplayCacheCapacity {
		return nil, ErrCacheCapacity
	}
	if clock == nil {
		return nil, ErrClock
	}
	domain := &ClientAcceptanceDomain{
		initialized: true,
		clock:       clock,
		capacity:    capacity,
		entries:     make(map[[TagLength]byte]uint64, capacity),
	}
	copy(domain.key[:], key)
	return domain, nil
}

// NewAcceptor captures an immutable active lease and nonzero path ID.
func (domain *ClientAcceptanceDomain) NewAcceptor(
	request Request,
	requestTag [TagLength]byte,
	lease AttemptLease,
) (*ClientResponseAcceptor, error) {
	if domain == nil {
		return nil, ErrClosed
	}
	domain.mu.Lock()
	defer domain.mu.Unlock()
	if err := domain.validateInitializedLocked(); err != nil {
		return nil, err
	}
	if err := validateRequestFields(request); err != nil {
		return nil, err
	}
	if err := validateLeaseBinding(request, lease); err != nil {
		return nil, err
	}
	deadline, err := leaseDeadline(request, lease)
	if err != nil {
		return nil, err
	}
	requestBody := encodeBody(request, 1)
	expectedTag := authenticate(domain.key[:], requestDomain, requestBody[:])
	if !hmac.Equal(expectedTag[:], requestTag[:]) {
		return nil, ErrRequestBinding
	}
	return &ClientResponseAcceptor{
		domain:     domain,
		request:    request,
		requestTag: requestTag,
		lease:      lease,
		deadline:   deadline,
		state:      AttemptStateActive,
	}, nil
}

// acceptResponse captures processingNow from the trusted clock while holding
// the same lock that owns replay pruning and insertion.
func (domain *ClientAcceptanceDomain) acceptResponse(
	responseTag [TagLength]byte,
	earliest uint64,
	deadline uint64,
) error {
	if domain == nil {
		return ErrClosed
	}
	domain.mu.Lock()
	defer domain.mu.Unlock()
	if err := domain.validateInitializedLocked(); err != nil {
		return err
	}

	processingNow := domain.clock()
	if domain.hasWatermark && processingNow < domain.watermark {
		return ErrClockRollback
	}
	domain.watermark = processingNow
	domain.hasWatermark = true
	if processingNow < earliest || processingNow > deadline {
		return ErrDeadline
	}
	if _, exists := domain.entries[responseTag]; exists {
		return ErrReplay
	}
	for cachedTag, cachedExpiry := range domain.entries {
		if processingNow > cachedExpiry {
			delete(domain.entries, cachedTag)
		}
	}
	if len(domain.entries) >= domain.capacity {
		return ErrCacheFull
	}
	domain.entries[responseTag] = deadline
	return nil
}

// validateInitializedLocked rejects zero-value and malformed domains before
// any clock call, map mutation, or key use. The caller must hold domain.mu.
func (domain *ClientAcceptanceDomain) validateInitializedLocked() error {
	if !domain.initialized ||
		domain.clock == nil ||
		domain.capacity <= 0 ||
		domain.capacity > MaxReplayCacheCapacity ||
		domain.entries == nil ||
		len(domain.entries) > domain.capacity ||
		(!domain.hasWatermark && domain.watermark != 0) {
		return ErrClosed
	}
	return nil
}

// ClientResponseAcceptor binds one immutable attempt lease and nonzero path ID
// to one response. Every outcome is terminal: success becomes Succeeded and
// any failed acceptance becomes Failed. Cancellation and supersession race
// safely with acceptance.
type ClientResponseAcceptor struct {
	mu         sync.Mutex
	domain     *ClientAcceptanceDomain
	request    Request
	requestTag [TagLength]byte
	lease      AttemptLease
	deadline   uint64
	state      AttemptState
}

// Accept compares the caller's current active lease, including PathID, with
// the immutable lease captured at construction. Processing time is captured
// internally by the shared domain; callers cannot influence replay ordering.
func (acceptor *ClientResponseAcceptor) Accept(
	datagram []byte,
	current AttemptLease,
) (VerifiedResponse, error) {
	var zero VerifiedResponse
	if acceptor == nil {
		return zero, ErrTerminal
	}
	acceptor.mu.Lock()
	defer acceptor.mu.Unlock()
	if acceptor.state != AttemptStateActive {
		return zero, ErrTerminal
	}
	if !sameLease(current, acceptor.lease) {
		acceptor.state = AttemptStateFailed
		return zero, ErrLease
	}
	verified, err := verifyResponseCodec(
		datagram,
		acceptor.domain.key[:],
		acceptor.request,
		acceptor.requestTag,
	)
	if err != nil {
		acceptor.state = AttemptStateFailed
		return zero, err
	}
	earliest := acceptor.request.RequestSentMonotonicNanoseconds
	if acceptor.lease.RequestedAtMonotonicNanoseconds > earliest {
		earliest = acceptor.lease.RequestedAtMonotonicNanoseconds
	}
	if err := acceptor.domain.acceptResponse(
		verified.ResponseTag,
		earliest,
		acceptor.deadline,
	); err != nil {
		acceptor.state = AttemptStateFailed
		return zero, err
	}
	acceptor.state = AttemptStateSucceeded
	return verified, nil
}

func (acceptor *ClientResponseAcceptor) State() AttemptState {
	if acceptor == nil {
		return AttemptStateFailed
	}
	acceptor.mu.Lock()
	defer acceptor.mu.Unlock()
	return acceptor.state
}

func (acceptor *ClientResponseAcceptor) Cancel() error {
	return acceptor.transition(AttemptStateCancelled)
}

func (acceptor *ClientResponseAcceptor) Supersede() error {
	return acceptor.transition(AttemptStateSuperseded)
}

func (acceptor *ClientResponseAcceptor) Fail() error {
	return acceptor.transition(AttemptStateFailed)
}

func (acceptor *ClientResponseAcceptor) transition(next AttemptState) error {
	if acceptor == nil {
		return ErrTerminal
	}
	acceptor.mu.Lock()
	defer acceptor.mu.Unlock()
	if acceptor.state != AttemptStateActive {
		return ErrTerminal
	}
	acceptor.state = next
	return nil
}

func leaseDeadline(request Request, lease AttemptLease) (uint64, error) {
	if lease.RequestedAtMonotonicNanoseconds >
		^uint64(0)-StageBDeadlineNanoseconds {
		return 0, ErrDeadline
	}
	deadline := lease.RequestedAtMonotonicNanoseconds +
		StageBDeadlineNanoseconds
	if request.RequestSentMonotonicNanoseconds <
		lease.RequestedAtMonotonicNanoseconds ||
		request.RequestSentMonotonicNanoseconds > deadline {
		return 0, ErrDeadline
	}
	return deadline, nil
}

func sameLease(left, right AttemptLease) bool {
	return left.Active &&
		!left.Cancelled &&
		!left.Superseded &&
		right.Active &&
		!right.Cancelled &&
		!right.Superseded &&
		hmac.Equal(left.AttemptNonce[:], right.AttemptNonce[:]) &&
		hmac.Equal(left.WCF3SessionID[:], right.WCF3SessionID[:]) &&
		hmac.Equal(left.WCF3BindingID[:], right.WCF3BindingID[:]) &&
		hmac.Equal(left.PathID[:], right.PathID[:]) &&
		left.PSKGeneration == right.PSKGeneration &&
		left.SequenceEpoch == right.SequenceEpoch &&
		left.RequestedAtMonotonicNanoseconds ==
			right.RequestedAtMonotonicNanoseconds
}
