package h3candidate

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/mobility"
)

func TestAssignFreshPreparationIdentitySeparatesLanes(t *testing.T) {
	first := &carrier.H3Dialer{
		SessionID:     "shared-session",
		SequenceEpoch: "shared-epoch",
	}
	second := &carrier.H3Dialer{
		SessionID:     "shared-session",
		SequenceEpoch: "shared-epoch",
	}
	if err := assignFreshPreparationIdentity(first); err != nil {
		t.Fatal(err)
	}
	if err := assignFreshPreparationIdentity(second); err != nil {
		t.Fatal(err)
	}
	if !mobility.ValidSessionID(first.SessionID) ||
		!mobility.ValidSessionID(first.SequenceEpoch) ||
		!mobility.ValidSessionID(second.SessionID) ||
		!mobility.ValidSessionID(second.SequenceEpoch) {
		t.Fatalf("invalid lane identities: first=%#v second=%#v", first, second)
	}
	if first.SessionID == second.SessionID ||
		first.SequenceEpoch == second.SequenceEpoch ||
		first.SessionID == first.SequenceEpoch ||
		second.SessionID == second.SequenceEpoch {
		t.Fatalf(
			"preparation lane identities are not independent: first=%#v second=%#v",
			first,
			second,
		)
	}
}

func TestFirstSuccessfulRaceCancelsAndCleansLoser(t *testing.T) {
	winnerReady := make(chan struct{})
	loserStarted := make(chan struct{})
	var (
		cleanupMu sync.Mutex
		cleaned   []string
	)
	winner, err := firstSuccessfulHedgedRace(
		context.Background(),
		time.Millisecond,
		20*time.Millisecond,
		[]func(context.Context) (string, error){
			func(context.Context) (string, error) {
				<-loserStarted
				close(winnerReady)
				return "winner", nil
			},
			func(ctx context.Context) (string, error) {
				close(loserStarted)
				<-winnerReady
				<-ctx.Done()
				return "loser", context.Cause(ctx)
			},
		},
		func(_ context.Context, value string) error {
			cleanupMu.Lock()
			cleaned = append(cleaned, value)
			cleanupMu.Unlock()
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if winner != "winner" {
		t.Fatalf("winner = %q", winner)
	}
	cleanupMu.Lock()
	defer cleanupMu.Unlock()
	if len(cleaned) != 1 || cleaned[0] != "loser" {
		t.Fatalf("cleaned values = %v, want only loser", cleaned)
	}
}

func TestFirstSuccessfulRaceCleansAllFailures(t *testing.T) {
	expected := errors.New("dial failed")
	var (
		cleanupMu sync.Mutex
		cleaned   = make(map[int]bool)
	)
	winner, err := firstSuccessfulHedgedRace(
		context.Background(),
		time.Millisecond,
		20*time.Millisecond,
		[]func(context.Context) (int, error){
			func(context.Context) (int, error) {
				return 1, expected
			},
			func(context.Context) (int, error) {
				return 2, expected
			},
		},
		func(_ context.Context, value int) error {
			cleanupMu.Lock()
			cleaned[value] = true
			cleanupMu.Unlock()
			return nil
		},
	)
	if !errors.Is(err, expected) {
		t.Fatalf("race error = %v, want %v", err, expected)
	}
	if winner != 0 {
		t.Fatalf("failed race winner = %d", winner)
	}
	cleanupMu.Lock()
	defer cleanupMu.Unlock()
	if !cleaned[1] || !cleaned[2] || len(cleaned) != 2 {
		t.Fatalf("cleaned values = %v, want both failures", cleaned)
	}
}

func TestFirstSuccessfulRaceRejectsLoserCleanupFailure(t *testing.T) {
	cleanupFailure := errors.New("cleanup failed")
	releaseWinner := make(chan struct{})
	loserStarted := make(chan struct{})
	var (
		cleanupMu sync.Mutex
		cleaned   = make(map[string]int)
	)
	winner, err := firstSuccessfulHedgedRace(
		context.Background(),
		time.Millisecond,
		20*time.Millisecond,
		[]func(context.Context) (string, error){
			func(context.Context) (string, error) {
				<-loserStarted
				close(releaseWinner)
				return "winner", nil
			},
			func(ctx context.Context) (string, error) {
				close(loserStarted)
				<-releaseWinner
				<-ctx.Done()
				return "loser", context.Cause(ctx)
			},
		},
		func(_ context.Context, value string) error {
			cleanupMu.Lock()
			cleaned[value]++
			cleanupMu.Unlock()
			if value == "loser" {
				return cleanupFailure
			}
			return nil
		},
	)
	if !errors.Is(err, cleanupFailure) {
		t.Fatalf("race error = %v, want cleanup failure", err)
	}
	if winner != "" {
		t.Fatalf("cleanup-failed race winner = %q", winner)
	}
	cleanupMu.Lock()
	defer cleanupMu.Unlock()
	if cleaned["loser"] != 1 || cleaned["winner"] != 1 {
		t.Fatalf("cleanup counts = %v, want loser and rejected winner", cleaned)
	}
}

func TestFirstSuccessfulRaceHonorsParentCancellation(t *testing.T) {
	var secondCalls int
	ctx, cancel := context.WithTimeout(
		context.Background(),
		20*time.Millisecond,
	)
	defer cancel()
	task := func(ctx context.Context) (int, error) {
		<-ctx.Done()
		return 1, context.Cause(ctx)
	}
	if _, err := firstSuccessfulHedgedRace(
		ctx,
		50*time.Millisecond,
		20*time.Millisecond,
		[]func(context.Context) (int, error){
			task,
			func(ctx context.Context) (int, error) {
				secondCalls++
				return task(ctx)
			},
		},
		func(context.Context, int) error { return nil },
	); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("race error = %v, want parent deadline", err)
	}
	if secondCalls != 0 {
		t.Fatalf("parent cancellation launched %d hedge tasks", secondCalls)
	}
}

func TestFirstSuccessfulHedgedRaceSuppressesFastSecondLane(t *testing.T) {
	var secondCalls int
	winner, err := firstSuccessfulHedgedRace(
		context.Background(),
		50*time.Millisecond,
		20*time.Millisecond,
		[]func(context.Context) (string, error){
			func(context.Context) (string, error) {
				return "first", nil
			},
			func(context.Context) (string, error) {
				secondCalls++
				return "second", nil
			},
		},
		func(context.Context, string) error { return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if winner != "first" || secondCalls != 0 {
		t.Fatalf(
			"winner = %q, second calls = %d; want first/0",
			winner,
			secondCalls,
		)
	}
}

func TestFirstSuccessfulHedgedRaceBoundsFailedLaneCleanup(t *testing.T) {
	releaseWinner := make(chan struct{})
	loserStarted := make(chan struct{})
	started := time.Now()
	if _, err := firstSuccessfulHedgedRace(
		context.Background(),
		time.Millisecond,
		20*time.Millisecond,
		[]func(context.Context) (string, error){
			func(context.Context) (string, error) {
				<-loserStarted
				close(releaseWinner)
				return "winner", nil
			},
			func(ctx context.Context) (string, error) {
				close(loserStarted)
				<-releaseWinner
				<-ctx.Done()
				return "blocked-cleanup", context.Cause(ctx)
			},
		},
		func(ctx context.Context, value string) error {
			if value != "blocked-cleanup" {
				return nil
			}
			<-ctx.Done()
			return context.Cause(ctx)
		},
	); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("race error = %v, want cleanup deadline", err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("bounded cleanup took %s", elapsed)
	}
}

func TestFirstSuccessfulHedgedRaceBoundsBlockedTaskDrain(t *testing.T) {
	loserStarted := make(chan struct{})
	releaseLoser := make(chan struct{})
	cleaned := make(chan string, 2)
	started := time.Now()
	winner, err := firstSuccessfulHedgedRace(
		context.Background(),
		time.Millisecond,
		20*time.Millisecond,
		[]func(context.Context) (string, error){
			func(context.Context) (string, error) {
				<-loserStarted
				return "winner", nil
			},
			func(context.Context) (string, error) {
				close(loserStarted)
				<-releaseLoser
				return "late-loser", nil
			},
		},
		func(_ context.Context, value string) error {
			cleaned <- value
			return nil
		},
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked task drain error = %v, want deadline", err)
	}
	if winner != "" {
		t.Fatalf("blocked task drain returned winner %q", winner)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("blocked task drain took %s", elapsed)
	}
	close(releaseLoser)
	seen := make(map[string]bool)
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for len(seen) < 2 {
		select {
		case value := <-cleaned:
			seen[value] = true
		case <-deadline.C:
			t.Fatalf("late task cleanup = %v, want winner and loser", seen)
		}
	}
	if !seen["winner"] || !seen["late-loser"] {
		t.Fatalf("late task cleanup = %v, want winner and loser", seen)
	}
}

func TestFirstSuccessfulHedgedRaceAbortsBlockedLoser(t *testing.T) {
	loserStarted := make(chan struct{})
	releaseLoser := make(chan struct{})
	cleaned := make(chan string, 1)
	var abortOnce sync.Once
	winner, err := firstSuccessfulHedgedRace(
		context.Background(),
		time.Millisecond,
		20*time.Millisecond,
		[]func(context.Context) (string, error){
			func(context.Context) (string, error) {
				<-loserStarted
				return "winner", nil
			},
			func(context.Context) (string, error) {
				close(loserStarted)
				<-releaseLoser
				return "loser", nil
			},
		},
		func(_ context.Context, value string) error {
			cleaned <- value
			return nil
		},
		func(_ context.Context, index int) error {
			if index != 1 {
				t.Errorf("aborted lane = %d, want 1", index)
			}
			abortOnce.Do(func() { close(releaseLoser) })
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if winner != "winner" {
		t.Fatalf("winner = %q", winner)
	}
	select {
	case value := <-cleaned:
		if value != "loser" {
			t.Fatalf("cleaned value = %q, want loser", value)
		}
	case <-time.After(time.Second):
		t.Fatal("aborted loser was not cleaned")
	}
}

func TestFirstSuccessfulHedgedRaceSharesOneCleanupDeadline(t *testing.T) {
	expected := errors.New("dial failed")
	started := time.Now()
	if _, err := firstSuccessfulHedgedRace(
		context.Background(),
		time.Millisecond,
		20*time.Millisecond,
		[]func(context.Context) (int, error){
			func(context.Context) (int, error) { return 1, expected },
			func(context.Context) (int, error) { return 2, expected },
		},
		func(ctx context.Context, _ int) error {
			<-ctx.Done()
			return context.Cause(ctx)
		},
	); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("race cleanup error = %v, want cleanup deadline", err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("shared cleanup deadline took %s", elapsed)
	}
}

// A committed H3 session must not inherit the preparation-age bound. Before
// this separation, warm-prepared candidates took warmUntil as their session
// lifetime, so a healthy committed tunnel self-terminated one WarmAge after
// preparation regardless of how much trusted lifetime remained.
func TestPreparedLifetimesKeepCommittedSessionTrustDerived(t *testing.T) {
	current := time.Now().UTC()
	const warmAge = time.Minute
	descriptorExpiresAt := current.Add(2 * time.Hour)
	sessionExpiresAt := current.Add(time.Hour)

	warmUntil, committed := preparedLifetimes(
		current, warmAge, descriptorExpiresAt, sessionExpiresAt,
	)

	if !warmUntil.Equal(current.Add(warmAge)) {
		t.Fatalf(
			"warmUntil = %s, want the preparation-age bound %s",
			warmUntil, current.Add(warmAge),
		)
	}
	if !committed.Equal(sessionExpiresAt) {
		t.Fatalf(
			"committed session expiry = %s, want the trusted expiry %s",
			committed, sessionExpiresAt,
		)
	}
	if !committed.After(warmUntil) {
		t.Fatal(
			"committed session expiry is still bounded by preparation age",
		)
	}
}

// The committed lifetime must still never exceed the trust material, so a
// shorter trusted expiry continues to win over both bounds.
func TestPreparedLifetimesRespectShorterTrustedExpiry(t *testing.T) {
	current := time.Now().UTC()
	const warmAge = time.Hour
	descriptorExpiresAt := current.Add(90 * time.Second)
	sessionExpiresAt := current.Add(30 * time.Second)

	warmUntil, committed := preparedLifetimes(
		current, warmAge, descriptorExpiresAt, sessionExpiresAt,
	)

	if !committed.Equal(sessionExpiresAt) {
		t.Fatalf("committed = %s, want %s", committed, sessionExpiresAt)
	}
	if warmUntil.After(sessionExpiresAt) {
		t.Fatalf(
			"warmUntil = %s exceeds the trusted expiry %s",
			warmUntil, sessionExpiresAt,
		)
	}
}
