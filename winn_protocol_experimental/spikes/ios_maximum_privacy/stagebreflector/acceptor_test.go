package stagebreflector

import (
	"errors"
	"sync"
	"testing"
)

func domainWithTimes(
	t *testing.T,
	capacity int,
	times ...uint64,
) *ClientAcceptanceDomain {
	t.Helper()
	clock := &sequenceClock{values: times}
	domain, err := NewClientAcceptanceDomain(
		publicKey(),
		capacity,
		clock.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	return domain
}

func validAcceptorInputs(
	t *testing.T,
	domain *ClientAcceptanceDomain,
) (*ClientResponseAcceptor, AttemptLease, []byte) {
	t.Helper()
	request, _, verifiedRequest, response := validExchange(t)
	if domain == nil {
		domain = domainWithTimes(
			t,
			4,
			request.RequestSentMonotonicNanoseconds+1,
		)
	}
	lease := testLease(request)
	acceptor, err := domain.NewAcceptor(
		request,
		verifiedRequest.Tag,
		lease,
	)
	if err != nil {
		t.Fatal(err)
	}
	return acceptor, lease, response
}

func TestClientResponseAcceptorSuccessIsTerminal(t *testing.T) {
	acceptor, lease, response := validAcceptorInputs(t, nil)
	if _, err := acceptor.Accept(response, lease); err != nil {
		t.Fatal(err)
	}
	if acceptor.State() != AttemptStateSucceeded {
		t.Fatalf("state = %d", acceptor.State())
	}
	if _, err := acceptor.Accept(response, lease); !errors.Is(err, ErrTerminal) {
		t.Fatalf("post-success accept: %v", err)
	}
	if err := acceptor.Cancel(); !errors.Is(err, ErrTerminal) {
		t.Fatalf("post-success cancel: %v", err)
	}
}

func TestClientResponseAcceptorPathMismatchTerminallyFails(t *testing.T) {
	acceptor, lease, response := validAcceptorInputs(t, nil)
	wrongPath := lease
	wrongPath.PathID[0] ^= 1
	if _, err := acceptor.Accept(response, wrongPath); !errors.Is(err, ErrLease) {
		t.Fatalf("path mismatch: %v", err)
	}
	if acceptor.State() != AttemptStateFailed {
		t.Fatalf("state = %d", acceptor.State())
	}
	if _, err := acceptor.Accept(response, lease); !errors.Is(err, ErrTerminal) {
		t.Fatalf("corrected retry: %v", err)
	}
}

func TestClientResponseAcceptorValidationFailureRejectsCorrectedRetry(t *testing.T) {
	acceptor, lease, response := validAcceptorInputs(t, nil)
	malformed := append([]byte{}, response...)
	malformed[len(malformed)-1] ^= 1
	if _, err := acceptor.Accept(
		malformed,
		lease,
	); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("malformed response: %v", err)
	}
	if acceptor.State() != AttemptStateFailed {
		t.Fatalf("state = %d", acceptor.State())
	}
	if _, err := acceptor.Accept(response, lease); !errors.Is(err, ErrTerminal) {
		t.Fatalf("corrected response retry: %v", err)
	}
}

func TestClientAcceptanceDomainSameTagHasOneWinner(t *testing.T) {
	request := deterministicRequest()
	domain := domainWithTimes(
		t,
		4,
		request.RequestSentMonotonicNanoseconds+1,
		request.RequestSentMonotonicNanoseconds+2,
	)
	first, firstLease, response := validAcceptorInputs(t, domain)
	second, secondLease, _ := validAcceptorInputs(t, domain)
	if _, err := first.Accept(response, firstLease); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Accept(response, secondLease); !errors.Is(err, ErrReplay) {
		t.Fatalf("shared replay: %v", err)
	}
	if first.State() != AttemptStateSucceeded ||
		second.State() != AttemptStateFailed {
		t.Fatalf("states = %d, %d", first.State(), second.State())
	}
}

func TestClientAcceptanceDomainReverseCallerObservationDoesNotFalseRollback(t *testing.T) {
	firstRequest := deterministicRequest()
	secondRequest := firstRequest
	secondRequest.AttemptNonce[0] ^= 1
	secondRequest.CanarySequence++
	_, _, firstVerified, firstResponse :=
		validExchangeForRequest(t, firstRequest)
	_, _, secondVerified, secondResponse :=
		validExchangeForRequest(t, secondRequest)

	// A callback could have observed first at t1 and second at t2, but scheduler
	// admission is intentionally reversed. Those caller observations never
	// enter the authority; its lock-captured trusted times remain ordered.
	externalT1 := firstRequest.RequestSentMonotonicNanoseconds + 1
	externalT2 := firstRequest.RequestSentMonotonicNanoseconds + 2
	if externalT1 >= externalT2 {
		t.Fatal("invalid test observations")
	}
	domain := domainWithTimes(t, 4, externalT1, externalT2)
	firstLease := testLease(firstRequest)
	secondLease := testLease(secondRequest)
	first, err := domain.NewAcceptor(
		firstRequest,
		firstVerified.Tag,
		firstLease,
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := domain.NewAcceptor(
		secondRequest,
		secondVerified.Tag,
		secondLease,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Accept(secondResponse, secondLease); err != nil {
		t.Fatalf("reverse-scheduled second: %v", err)
	}
	if _, err := first.Accept(firstResponse, firstLease); err != nil {
		t.Fatalf("reverse-scheduled first: %v", err)
	}
}

func TestClientAcceptanceDomainTrustedClockRollbackRejected(t *testing.T) {
	firstRequest := deterministicRequest()
	secondRequest := firstRequest
	secondRequest.AttemptNonce[0] ^= 1
	secondRequest.CanarySequence++
	_, _, firstVerified, firstResponse :=
		validExchangeForRequest(t, firstRequest)
	_, _, secondVerified, secondResponse :=
		validExchangeForRequest(t, secondRequest)
	domain := domainWithTimes(
		t,
		4,
		firstRequest.RequestSentMonotonicNanoseconds+2,
		firstRequest.RequestSentMonotonicNanoseconds+1,
	)
	firstLease := testLease(firstRequest)
	secondLease := testLease(secondRequest)
	first, err := domain.NewAcceptor(firstRequest, firstVerified.Tag, firstLease)
	if err != nil {
		t.Fatal(err)
	}
	second, err := domain.NewAcceptor(secondRequest, secondVerified.Tag, secondLease)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Accept(firstResponse, firstLease); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Accept(
		secondResponse,
		secondLease,
	); !errors.Is(err, ErrClockRollback) {
		t.Fatalf("trusted clock rollback: %v", err)
	}
}

func TestClientAcceptanceDomainCapacityAndPruning(t *testing.T) {
	firstRequest := deterministicRequest()
	secondRequest := firstRequest
	secondRequest.AttemptNonce[0] ^= 1
	secondRequest.CanarySequence++
	_, _, firstVerified, firstResponse :=
		validExchangeForRequest(t, firstRequest)
	_, _, secondVerified, secondResponse :=
		validExchangeForRequest(t, secondRequest)

	fullDomain := domainWithTimes(
		t,
		1,
		firstRequest.RequestSentMonotonicNanoseconds+1,
		firstRequest.RequestSentMonotonicNanoseconds+2,
	)
	firstLease := testLease(firstRequest)
	secondLease := testLease(secondRequest)
	first, err := fullDomain.NewAcceptor(
		firstRequest,
		firstVerified.Tag,
		firstLease,
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fullDomain.NewAcceptor(
		secondRequest,
		secondVerified.Tag,
		secondLease,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Accept(firstResponse, firstLease); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Accept(
		secondResponse,
		secondLease,
	); !errors.Is(err, ErrCacheFull) {
		t.Fatalf("capacity: %v", err)
	}

	laterRequest := secondRequest
	laterRequest.RequestSentMonotonicNanoseconds =
		firstRequest.RequestSentMonotonicNanoseconds +
			StageBDeadlineNanoseconds + 1
	_, _, laterVerified, laterResponse :=
		validExchangeForRequest(t, laterRequest)
	pruningDomain := domainWithTimes(
		t,
		1,
		firstRequest.RequestSentMonotonicNanoseconds,
		laterRequest.RequestSentMonotonicNanoseconds,
	)
	firstForPruning, err := pruningDomain.NewAcceptor(
		firstRequest,
		firstVerified.Tag,
		firstLease,
	)
	if err != nil {
		t.Fatal(err)
	}
	laterLease := testLease(laterRequest)
	later, err := pruningDomain.NewAcceptor(
		laterRequest,
		laterVerified.Tag,
		laterLease,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := firstForPruning.Accept(
		firstResponse,
		firstLease,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := later.Accept(laterResponse, laterLease); err != nil {
		t.Fatalf("expired entry not pruned: %v", err)
	}
}

func TestClientAcceptanceDomainProcessingTimeBounds(t *testing.T) {
	request := deterministicRequest()
	for name, processingNow := range map[string]uint64{
		"before-request-send": request.RequestSentMonotonicNanoseconds - 1,
		"after-deadline": request.RequestSentMonotonicNanoseconds +
			StageBDeadlineNanoseconds + 1,
	} {
		t.Run(name, func(t *testing.T) {
			domain := domainWithTimes(t, 2, processingNow)
			acceptor, lease, response := validAcceptorInputs(t, domain)
			if _, err := acceptor.Accept(
				response,
				lease,
			); !errors.Is(err, ErrDeadline) {
				t.Fatalf("got %v", err)
			}
			if acceptor.State() != AttemptStateFailed {
				t.Fatalf("state = %d", acceptor.State())
			}
		})
	}
	domain := domainWithTimes(
		t,
		2,
		request.RequestSentMonotonicNanoseconds+StageBDeadlineNanoseconds,
	)
	acceptor, lease, response := validAcceptorInputs(t, domain)
	if _, err := acceptor.Accept(response, lease); err != nil {
		t.Fatalf("exact deadline: %v", err)
	}
}

func TestClientResponseAcceptorTerminalTransitions(t *testing.T) {
	for name, transition := range map[string]struct {
		run      func(*ClientResponseAcceptor) error
		expected AttemptState
	}{
		"cancelled": {
			run:      (*ClientResponseAcceptor).Cancel,
			expected: AttemptStateCancelled,
		},
		"superseded": {
			run:      (*ClientResponseAcceptor).Supersede,
			expected: AttemptStateSuperseded,
		},
		"failed": {
			run:      (*ClientResponseAcceptor).Fail,
			expected: AttemptStateFailed,
		},
	} {
		t.Run(name, func(t *testing.T) {
			acceptor, lease, response := validAcceptorInputs(t, nil)
			if err := transition.run(acceptor); err != nil {
				t.Fatal(err)
			}
			if acceptor.State() != transition.expected {
				t.Fatalf("state = %d", acceptor.State())
			}
			if _, err := acceptor.Accept(
				response,
				lease,
			); !errors.Is(err, ErrTerminal) {
				t.Fatalf("post-terminal accept: %v", err)
			}
		})
	}
}

func TestClientResponseAcceptorCurrentLeaseMismatchIsTerminal(t *testing.T) {
	mutations := map[string]func(*AttemptLease){
		"attempt":   func(lease *AttemptLease) { lease.AttemptNonce[0] ^= 1 },
		"session":   func(lease *AttemptLease) { lease.WCF3SessionID[0] ^= 1 },
		"binding":   func(lease *AttemptLease) { lease.WCF3BindingID[0] ^= 1 },
		"path":      func(lease *AttemptLease) { lease.PathID[0] ^= 1 },
		"psk":       func(lease *AttemptLease) { lease.PSKGeneration++ },
		"epoch":     func(lease *AttemptLease) { lease.SequenceEpoch++ },
		"requested": func(lease *AttemptLease) { lease.RequestedAtMonotonicNanoseconds++ },
		"inactive":  func(lease *AttemptLease) { lease.Active = false },
		"cancelled": func(lease *AttemptLease) { lease.Cancelled = true },
		"superseded": func(lease *AttemptLease) {
			lease.Superseded = true
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			acceptor, lease, response := validAcceptorInputs(t, nil)
			mutate(&lease)
			if _, err := acceptor.Accept(
				response,
				lease,
			); !errors.Is(err, ErrLease) {
				t.Fatalf("mismatch: %v", err)
			}
		})
	}
}

func TestClientAcceptanceDomainConstructionFailsClosed(t *testing.T) {
	if _, err := NewClientAcceptanceDomain(
		publicKey(),
		0,
		func() uint64 { return 1 },
	); !errors.Is(err, ErrCacheCapacity) {
		t.Fatalf("zero capacity: %v", err)
	}
	if _, err := NewClientAcceptanceDomain(
		publicKey(),
		MaxReplayCacheCapacity+1,
		func() uint64 { return 1 },
	); !errors.Is(err, ErrCacheCapacity) {
		t.Fatalf("over capacity: %v", err)
	}
	if _, err := NewClientAcceptanceDomain(
		publicKey(),
		1,
		nil,
	); !errors.Is(err, ErrClock) {
		t.Fatalf("nil clock: %v", err)
	}
	request, _, verifiedRequest, _ := validExchange(t)
	lease := testLease(request)
	domain := domainWithTimes(
		t,
		2,
		request.RequestSentMonotonicNanoseconds+1,
	)
	zeroPath := lease
	zeroPath.PathID = [16]byte{}
	if _, err := domain.NewAcceptor(
		request,
		verifiedRequest.Tag,
		zeroPath,
	); !errors.Is(err, ErrLease) {
		t.Fatalf("zero path: %v", err)
	}
	wrongTag := verifiedRequest.Tag
	wrongTag[0] ^= 1
	if _, err := domain.NewAcceptor(
		request,
		wrongTag,
		lease,
	); !errors.Is(err, ErrRequestBinding) {
		t.Fatalf("wrong request tag: %v", err)
	}
	var nilDomain *ClientAcceptanceDomain
	if _, err := nilDomain.NewAcceptor(
		request,
		verifiedRequest.Tag,
		lease,
	); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil domain: %v", err)
	}
}

func TestClientAcceptanceDomainZeroAndMalformedStatesFailClosed(t *testing.T) {
	request, _, verifiedRequest, response := validExchange(t)
	lease := testLease(request)
	malformed := map[string]*ClientAcceptanceDomain{
		"zero": {},
		"missing-clock": {
			initialized: true,
			capacity:    1,
			entries:     make(map[[TagLength]byte]uint64),
		},
		"zero-capacity": {
			initialized: true,
			clock:       func() uint64 { return 1 },
			entries:     make(map[[TagLength]byte]uint64),
		},
		"missing-map": {
			initialized: true,
			clock:       func() uint64 { return 1 },
			capacity:    1,
		},
		"invalid-watermark": {
			initialized: true,
			clock:       func() uint64 { return 1 },
			capacity:    1,
			entries:     make(map[[TagLength]byte]uint64),
			watermark:   1,
		},
	}
	overfullEntries := make(map[[TagLength]byte]uint64)
	overfullEntries[[TagLength]byte{1}] = 1
	overfullEntries[[TagLength]byte{2}] = 1
	malformed["overfull-map"] = &ClientAcceptanceDomain{
		initialized: true,
		clock:       func() uint64 { return 1 },
		capacity:    1,
		entries:     overfullEntries,
	}
	for name, domain := range malformed {
		t.Run(name, func(t *testing.T) {
			if _, err := domain.NewAcceptor(
				request,
				verifiedRequest.Tag,
				lease,
			); !errors.Is(err, ErrClosed) {
				t.Fatalf("got %v", err)
			}
			var responseTag [TagLength]byte
			if err := domain.acceptResponse(
				responseTag,
				request.RequestSentMonotonicNanoseconds,
				request.RequestSentMonotonicNanoseconds+
					StageBDeadlineNanoseconds,
			); !errors.Is(err, ErrClosed) {
				t.Fatalf("direct acceptance got %v", err)
			}
		})
	}

	domain := domainWithTimes(
		t,
		2,
		request.RequestSentMonotonicNanoseconds+1,
	)
	acceptor, err := domain.NewAcceptor(
		request,
		verifiedRequest.Tag,
		lease,
	)
	if err != nil {
		t.Fatal(err)
	}
	domain.mu.Lock()
	domain.clock = nil
	domain.mu.Unlock()
	if _, err := acceptor.Accept(
		response,
		lease,
	); !errors.Is(err, ErrClosed) {
		t.Fatalf("post-construction corruption: %v", err)
	}
	if acceptor.State() != AttemptStateFailed {
		t.Fatalf("state = %d", acceptor.State())
	}
}

func TestClientResponseAcceptorConstructionChecksMonotonicOrder(t *testing.T) {
	request, _, verifiedRequest, _ := validExchange(t)
	baseLease := testLease(request)
	domain := domainWithTimes(
		t,
		4,
		request.RequestSentMonotonicNanoseconds+1,
	)
	for name, requestedAt := range map[string]uint64{
		"request-sent-before-requested": request.RequestSentMonotonicNanoseconds + 1,
		"request-sent-after-deadline": request.RequestSentMonotonicNanoseconds -
			StageBDeadlineNanoseconds - 1,
		"deadline-overflow": ^uint64(0) - StageBDeadlineNanoseconds + 1,
	} {
		t.Run(name, func(t *testing.T) {
			lease := baseLease
			lease.RequestedAtMonotonicNanoseconds = requestedAt
			if _, err := domain.NewAcceptor(
				request,
				verifiedRequest.Tag,
				lease,
			); !errors.Is(err, ErrDeadline) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestClientResponseAcceptorConcurrentAcceptance(t *testing.T) {
	acceptor, lease, response := validAcceptorInputs(t, nil)
	const workers = 16
	results := make(chan error, workers)
	var start sync.WaitGroup
	start.Add(1)
	for index := 0; index < workers; index++ {
		go func() {
			start.Wait()
			_, err := acceptor.Accept(response, lease)
			results <- err
		}()
	}
	start.Done()
	successes := 0
	for index := 0; index < workers; index++ {
		err := <-results
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrTerminal) {
			t.Fatalf("concurrent error: %v", err)
		}
	}
	if successes != 1 || acceptor.State() != AttemptStateSucceeded {
		t.Fatalf("successes/state = %d/%d", successes, acceptor.State())
	}
}
