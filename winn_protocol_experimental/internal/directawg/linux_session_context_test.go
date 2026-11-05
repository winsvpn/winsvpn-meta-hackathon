package directawg

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
)

func TestLinuxSessionCloseContextStopsAtPolicyAndResumes(t *testing.T) {
	events := &contextCloseEvents{}
	policy := newContextClosePolicy(events)
	policy.blockFirst.Store(true)
	runner := &contextCloseRunner{events: events}
	process := newContextCloseProcess(events)
	var releases atomic.Int32
	session := newContextCloseSession(
		policy, runner, process, &contextCloseVerifier{},
		func() { releases.Add(1) },
	)

	short, cancel := context.WithTimeout(
		context.Background(), 15*time.Millisecond,
	)
	defer cancel()
	err := session.CloseContext(short)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first CloseContext() error = %v, want deadline", err)
	}
	if runner.calls.Load() != 0 ||
		process.stops.Load() != 0 ||
		releases.Load() != 0 {
		t.Fatalf(
			"later teardown ran after policy timeout: runner=%d process=%d releases=%d",
			runner.calls.Load(), process.stops.Load(), releases.Load(),
		)
	}
	select {
	case healthErr, ok := <-session.Health():
		if !ok || !errors.Is(healthErr, context.DeadlineExceeded) {
			t.Fatalf("teardown health = (%v, %v)", healthErr, ok)
		}
	default:
		t.Fatal("teardown timeout was not published to health")
	}

	if err := session.CloseContext(context.Background()); err != nil {
		t.Fatalf("retry CloseContext() error = %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("idempotent Close() error = %v", err)
	}
	if got := policy.rollbacks.Load(); got != 2 {
		t.Fatalf("policy rollback attempts = %d, want 2", got)
	}
	if got := process.stops.Load(); got != 1 {
		t.Fatalf("process stop count = %d, want 1", got)
	}
	if got := releases.Load(); got != 2 {
		t.Fatalf("port/address releases = %d, want 2", got)
	}
	wantOrder := []string{
		"policy.rollback.timeout",
		"policy.rollback",
		"route.commit-rule",
		"route.verify-rule",
		"route.table",
		"link.delete",
		"process.stop",
	}
	if got := events.snapshot(); !orderedContextEvents(got, wantOrder) {
		t.Fatalf("teardown order = %v, want ordered %v", got, wantOrder)
	}
}

func TestLinuxSessionCloseCancelsInflightVerifier(t *testing.T) {
	events := &contextCloseEvents{}
	policy := newContextClosePolicy(events)
	runner := &contextCloseRunner{events: events}
	process := newContextCloseProcess(events)
	verifier := &contextCloseVerifier{
		entered: make(chan struct{}),
		block:   true,
	}
	session := newContextCloseSession(
		policy, runner, process, verifier, nil,
	)
	verifyResult := make(chan error, 1)
	go func() {
		verifyResult <- session.VerifyProtectedDNS(
			context.Background(), contextCloseBinding(),
		)
	}()
	<-verifier.entered

	if err := session.CloseContext(context.Background()); err != nil {
		t.Fatalf("CloseContext() error = %v", err)
	}
	select {
	case err := <-verifyResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("in-flight verifier error = %v, want canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight verifier was not canceled before close")
	}
	if got := policy.rollbacks.Load(); got != 1 {
		t.Fatalf("policy rollbacks = %d, want 1", got)
	}
}

func TestLinuxSessionCloseGateHonorsWaiterDeadline(t *testing.T) {
	events := &contextCloseEvents{}
	policy := newContextClosePolicy(events)
	runner := &contextCloseRunner{events: events}
	process := newContextCloseProcess(events)
	process.block = make(chan struct{})
	process.entered = make(chan struct{})
	session := newContextCloseSession(
		policy, runner, process, &contextCloseVerifier{}, nil,
	)
	first := make(chan error, 1)
	go func() {
		first <- session.CloseContext(context.Background())
	}()
	<-process.entered

	short, cancel := context.WithTimeout(
		context.Background(), 15*time.Millisecond,
	)
	defer cancel()
	if err := session.CloseContext(short); !errors.Is(
		err, context.DeadlineExceeded,
	) {
		t.Fatalf("waiting CloseContext() error = %v, want deadline", err)
	}
	close(process.block)
	if err := <-first; err != nil {
		t.Fatalf("first CloseContext() error = %v", err)
	}

	const callers = 16
	results := make(chan error, callers)
	var group sync.WaitGroup
	for range callers {
		group.Add(1)
		go func() {
			defer group.Done()
			results <- session.CloseContext(context.Background())
		}()
	}
	group.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("idempotent concurrent CloseContext() error = %v", err)
		}
	}
	if got := process.stops.Load(); got != 1 {
		t.Fatalf("process stops = %d, want 1", got)
	}
}

func TestLinuxSessionCloseUsesConfiguredTimeoutCeiling(t *testing.T) {
	events := &contextCloseEvents{}
	policy := newContextClosePolicy(events)
	runner := &contextCloseRunner{events: events}
	process := newContextCloseProcess(events)
	process.block = make(chan struct{})
	process.entered = make(chan struct{})
	var releases atomic.Int32
	session := newContextCloseSession(
		policy,
		runner,
		process,
		&contextCloseVerifier{},
		func() { releases.Add(1) },
	)
	session.config.stopTimeout = 20 * time.Millisecond

	started := time.Now()
	err := session.CloseContext(context.Background())
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CloseContext() error = %v, want internal deadline", err)
	}
	if elapsed > 10*session.config.stopTimeout {
		t.Fatalf(
			"CloseContext() elapsed = %s, timeout = %s",
			elapsed, session.config.stopTimeout,
		)
	}
	if got := releases.Load(); got != 0 {
		t.Fatalf("leases released before process stopped: %d", got)
	}
	close(process.block)
	if err := session.CloseContext(context.Background()); err != nil {
		t.Fatalf("retry CloseContext() error = %v", err)
	}
	if got := releases.Load(); got != 2 {
		t.Fatalf("lease releases = %d, want 2", got)
	}
	if got := policy.rollbacks.Load(); got != 1 {
		t.Fatalf("completed policy stage repeated: %d", got)
	}
}

func TestLinuxSessionCloseRetriesOnlyFailedRouteStage(t *testing.T) {
	events := &contextCloseEvents{}
	policy := newContextClosePolicy(events)
	runner := &contextCloseRunner{
		events:        events,
		failSubstring: "rule|del|priority|200",
	}
	process := newContextCloseProcess(events)
	session := newContextCloseSession(
		policy, runner, process, &contextCloseVerifier{}, nil,
	)
	if err := session.CloseContext(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "routes") {
		t.Fatalf("first CloseContext() error = %v, want route failure", err)
	}
	if got := policy.rollbacks.Load(); got != 1 {
		t.Fatalf("policy rollbacks after route failure = %d, want 1", got)
	}
	if got := process.stops.Load(); got != 0 {
		t.Fatalf("process stopped before route rollback: %d", got)
	}
	if err := session.CloseContext(context.Background()); err != nil {
		t.Fatalf("retry CloseContext() error = %v", err)
	}
	if got := policy.rollbacks.Load(); got != 1 {
		t.Fatalf("completed policy stage repeated: %d", got)
	}
	if got := process.stops.Load(); got != 1 {
		t.Fatalf("process stops = %d, want 1", got)
	}
}

func TestLinuxSessionCloseAcceptsProvenExternallyRemovedLink(t *testing.T) {
	events := &contextCloseEvents{}
	policy := newContextClosePolicy(events)
	runner := &contextCloseRunner{
		events:            events,
		linkAlreadyAbsent: true,
	}
	process := newContextCloseProcess(events)
	session := newContextCloseSession(
		policy, runner, process, &contextCloseVerifier{}, nil,
	)
	if err := session.CloseContext(context.Background()); err != nil {
		t.Fatalf("CloseContext() error = %v", err)
	}
	if got := process.stops.Load(); got != 1 {
		t.Fatalf("process stops = %d, want 1", got)
	}
	wantOrder := []string{
		"policy.rollback",
		"route.commit-rule",
		"route.verify-rule",
		"route.table",
		"link.delete",
		"link.show-absent",
		"process.stop",
	}
	if got := events.snapshot(); !orderedContextEvents(got, wantOrder) {
		t.Fatalf("teardown order = %v, want ordered %v", got, wantOrder)
	}
}

func TestLinuxSessionCloseRejectsAmbiguousMissingLinkCheck(t *testing.T) {
	events := &contextCloseEvents{}
	policy := newContextClosePolicy(events)
	runner := &contextCloseRunner{
		events:             events,
		linkAlreadyAbsent:  true,
		ambiguousLinkError: true,
	}
	process := newContextCloseProcess(events)
	session := newContextCloseSession(
		policy, runner, process, &contextCloseVerifier{}, nil,
	)
	err := session.CloseContext(context.Background())
	if err == nil ||
		!strings.Contains(err.Error(), "verify deleted Linux AWG interface") {
		t.Fatalf("CloseContext() error = %v, want absence-proof failure", err)
	}
	if got := process.stops.Load(); got != 0 {
		t.Fatalf("process stopped after ambiguous link check: %d", got)
	}
}

func newContextCloseSession(
	policy LinuxPolicyTransaction,
	runner *contextCloseRunner,
	process *contextCloseProcess,
	verifier LinuxProtectedVerifier,
	release func(),
) *linuxTunnelSession {
	route := &linuxRouteTransaction{
		runner:   runner,
		ipBinary: "/usr/sbin/ip",
		identity: linuxCandidateIdentity{
			InterfaceName:  "winnctx",
			RouteTable:     100,
			FirewallMark:   0x77,
			VerifyPriority: 200,
			CommitPriority: 100,
		},
		family:         "-4",
		verifyRule:     true,
		commitRule:     true,
		tablePopulated: true,
	}
	return newLinuxTunnelSession(linuxTunnelSessionConfig{
		binding: contextCloseBinding(),
		status: &CLIStatusSource{
			interfaceName: "winnctx",
		},
		verifier: verifier,
		probe: LinuxProbeContext{
			Binding:       contextCloseBinding(),
			InterfaceName: "winnctx",
			InnerAddress: netip.MustParsePrefix(
				"10.55.0.2/32",
			),
			FirewallMark: 0x77,
		},
		route:          route,
		policy:         policy,
		process:        process,
		runner:         runner,
		ipBinary:       "/usr/sbin/ip",
		interfaceName:  "winnctx",
		stopTimeout:    time.Second,
		releasePort:    release,
		releaseAddress: release,
	})
}

func contextCloseBinding() connectivity.Binding {
	return connectivity.Binding{
		AttemptID:      strings.Repeat("1", 32),
		Profile:        "default",
		Mode:           connectivity.ModeAuto,
		ManifestDigest: strings.Repeat("2", 64),
		CandidateID:    "direct-context",
		NodeID:         "gateway-context",
		SessionID:      strings.Repeat("3", 32),
		PSKGeneration:  1,
		SequenceEpoch:  1,
		Nonce:          strings.Repeat("4", 32),
		ExpiresAt: time.Date(
			2030, 1, 1, 0, 0, 0, 0, time.UTC,
		),
	}
}

type contextClosePolicy struct {
	events     *contextCloseEvents
	health     chan error
	blockFirst atomic.Bool
	rollbacks  atomic.Int32
}

func newContextClosePolicy(
	events *contextCloseEvents,
) *contextClosePolicy {
	return &contextClosePolicy{
		events: events,
		health: make(chan error, 1),
	}
}

func (*contextClosePolicy) Commit(context.Context) error {
	return nil
}

func (policy *contextClosePolicy) Rollback(ctx context.Context) error {
	policy.rollbacks.Add(1)
	if policy.blockFirst.CompareAndSwap(true, false) {
		<-ctx.Done()
		policy.events.add("policy.rollback.timeout")
		return context.Cause(ctx)
	}
	policy.events.add("policy.rollback")
	return nil
}

func (policy *contextClosePolicy) Health() <-chan error {
	return policy.health
}

type contextCloseRunner struct {
	events             *contextCloseEvents
	calls              atomic.Int32
	failSubstring      string
	failed             atomic.Bool
	linkAlreadyAbsent  bool
	ambiguousLinkError bool
}

func (*contextCloseRunner) Start(
	LinuxCommand,
) (LinuxManagedProcess, error) {
	return nil, errors.New("unused")
}

func (runner *contextCloseRunner) Run(
	ctx context.Context,
	command LinuxCommand,
) (LinuxCommandResult, error) {
	runner.calls.Add(1)
	event := strings.Join(command.Args, "|")
	switch {
	case strings.Contains(event, "priority|100"):
		runner.events.add("route.commit-rule")
	case strings.Contains(event, "priority|200"):
		runner.events.add("route.verify-rule")
	case strings.Contains(event, "route|flush"):
		runner.events.add("route.table")
	case strings.Contains(event, "link|delete"):
		runner.events.add("link.delete")
		if runner.linkAlreadyAbsent {
			return LinuxCommandResult{
				Stderr: []byte("Cannot find device \"winnctx\"\n"),
			}, errors.New("injected absent link")
		}
	case strings.Contains(event, "-j|link|show"):
		if runner.linkAlreadyAbsent {
			runner.events.add("link.show-absent")
			stderr := []byte("Device \"winnctx\" does not exist.\n")
			if runner.ambiguousLinkError {
				stderr = []byte("permission denied\n")
			}
			return LinuxCommandResult{Stderr: stderr},
				errors.New("injected link check failure")
		}
	}
	if cause := context.Cause(ctx); cause != nil {
		return LinuxCommandResult{}, cause
	}
	if runner.failSubstring != "" &&
		strings.Contains(event, runner.failSubstring) &&
		runner.failed.CompareAndSwap(false, true) {
		return LinuxCommandResult{}, errors.New("injected runner failure")
	}
	return LinuxCommandResult{}, nil
}

type contextCloseProcess struct {
	events  *contextCloseEvents
	exited  chan struct{}
	stops   atomic.Int32
	block   chan struct{}
	entered chan struct{}
	once    sync.Once
}

func newContextCloseProcess(
	events *contextCloseEvents,
) *contextCloseProcess {
	return &contextCloseProcess{
		events: events,
		exited: make(chan struct{}),
	}
}

func (process *contextCloseProcess) Exited() <-chan struct{} {
	return process.exited
}

func (*contextCloseProcess) Err() error {
	return nil
}

func (process *contextCloseProcess) Stop(ctx context.Context) error {
	process.stops.Add(1)
	process.events.add("process.stop")
	if process.entered != nil {
		process.once.Do(func() { close(process.entered) })
	}
	if process.block != nil {
		select {
		case <-process.block:
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
	return nil
}

type contextCloseVerifier struct {
	entered chan struct{}
	block   bool
	once    sync.Once
}

func (verifier *contextCloseVerifier) VerifyProtectedDNS(
	ctx context.Context,
	_ LinuxProbeContext,
) error {
	if verifier.entered != nil {
		verifier.once.Do(func() { close(verifier.entered) })
	}
	if verifier.block {
		<-ctx.Done()
		return context.Cause(ctx)
	}
	return nil
}

func (*contextCloseVerifier) VerifyTunnelCanary(
	context.Context,
	LinuxProbeContext,
) error {
	return nil
}

type contextCloseEvents struct {
	mu     sync.Mutex
	events []string
}

func (events *contextCloseEvents) add(event string) {
	events.mu.Lock()
	events.events = append(events.events, event)
	events.mu.Unlock()
}

func (events *contextCloseEvents) snapshot() []string {
	events.mu.Lock()
	defer events.mu.Unlock()
	return append([]string(nil), events.events...)
}

func orderedContextEvents(got, want []string) bool {
	index := 0
	for _, event := range got {
		if index < len(want) && event == want[index] {
			index++
		}
	}
	return index == len(want)
}

var _ ContextTunnelSession = (*linuxTunnelSession)(nil)
