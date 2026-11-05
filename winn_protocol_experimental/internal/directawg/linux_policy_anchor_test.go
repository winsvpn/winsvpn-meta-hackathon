package directawg

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLinuxPolicyAnchorSharesReferencesWithCandidateBothReleaseOrders(
	t *testing.T,
) {
	t.Run("anchor-first", func(t *testing.T) {
		factory, runner, batch := newAnchorTestFactory()
		lease := prepareTestAnchor(t, factory, time.Now().Add(time.Hour))
		assertAnchorCommandsOnlyNft(t, runner.snapshot())
		transaction := prepareAnchorTestCandidate(t, factory)
		if err := lease.Resource.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		assertAnchorFactoryReferences(t, factory, 1, 0)
		if err := transaction.Rollback(context.Background()); err != nil {
			t.Fatal(err)
		}
		assertAnchorFactoryReferences(t, factory, 0, 0)
		scripts := batch.snapshot()
		if countScript(scripts, "add element inet winn_anchor underlay_ifaces") != 1 ||
			countScript(scripts, "delete element inet winn_anchor underlay_marks") != 1 {
			t.Fatalf("shared underlay batches = %#v", scripts)
		}
		if err := factory.Release(context.Background()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("candidate-first", func(t *testing.T) {
		factory, runner, batch := newAnchorTestFactory()
		transaction := prepareAnchorTestCandidate(t, factory)
		commandsBeforeAnchor := len(runner.snapshot())
		lease := prepareTestAnchor(t, factory, time.Now().Add(time.Hour))
		assertAnchorCommandsOnlyNft(
			t, runner.snapshot()[commandsBeforeAnchor:],
		)
		if err := transaction.Rollback(context.Background()); err != nil {
			t.Fatal(err)
		}
		assertAnchorFactoryReferences(t, factory, 1, 1)
		if err := lease.Resource.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		assertAnchorFactoryReferences(t, factory, 0, 0)
		scripts := batch.snapshot()
		if countScript(scripts, "add element inet winn_anchor underlay_ifaces") != 1 ||
			countScript(scripts, "delete element inet winn_anchor underlay_marks") != 1 {
			t.Fatalf("shared underlay batches = %#v", scripts)
		}
		if err := factory.Release(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestLinuxPolicyAnchorConcurrentAcquireAndIdempotentClose(
	t *testing.T,
) {
	factory, _, batch := newAnchorTestFactory()
	const anchors = 32
	leases := make([]LinuxUnderlayPolicyAnchorLease, anchors)
	errs := make(chan error, anchors)
	var acquire sync.WaitGroup
	for index := range anchors {
		acquire.Add(1)
		go func(index int) {
			defer acquire.Done()
			lease, err := factory.prepareUnderlayPolicyAnchor(
				context.Background(),
				anchorTestSpec(time.Now().Add(time.Hour)),
			)
			leases[index] = lease
			errs <- err
		}(index)
	}
	acquire.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	assertAnchorFactoryReferences(t, factory, anchors, anchors)

	var closeGroup sync.WaitGroup
	closeErrs := make(chan error, anchors*2)
	for _, lease := range leases {
		for range 2 {
			closeGroup.Add(1)
			go func(resource LinuxUnderlayPolicyAnchorResource) {
				defer closeGroup.Done()
				closeErrs <- resource.Close(context.Background())
			}(lease.Resource)
		}
	}
	closeGroup.Wait()
	close(closeErrs)
	for err := range closeErrs {
		if err != nil {
			t.Fatal(err)
		}
	}
	assertAnchorFactoryReferences(t, factory, 0, 0)
	scripts := batch.snapshot()
	if countScript(scripts, "table inet winn_anchor") != 1 ||
		countScript(scripts, "add element inet winn_anchor underlay_ifaces") != 1 ||
		countScript(scripts, "delete element inet winn_anchor underlay_marks") != 1 {
		t.Fatalf("concurrent lifecycle batches = %#v", scripts)
	}
	if err := factory.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxPolicyAnchorCleanupFailureIsRetryableAndBlocksRelease(
	t *testing.T,
) {
	factory, _, batch := newAnchorTestFactory()
	lease := prepareTestAnchor(t, factory, time.Now().Add(time.Hour))
	if err := factory.Release(context.Background()); err == nil {
		t.Fatal("factory release succeeded with a live anchor")
	}
	batch.failRemoves(1)
	if err := lease.Resource.Close(
		context.Background(),
	); err == nil || !strings.Contains(err.Error(), "remove") {
		t.Fatalf("first close error = %v", err)
	}
	assertAnchorFactoryReferences(t, factory, 1, 1)
	if err := lease.Resource.Close(context.Background()); err != nil {
		t.Fatalf("retry close: %v", err)
	}
	if err := lease.Resource.Close(context.Background()); err != nil {
		t.Fatalf("idempotent close: %v", err)
	}
	assertAnchorFactoryReferences(t, factory, 0, 0)
	if err := factory.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxPolicyAnchorCloseHonorsContextAndRetries(
	t *testing.T,
) {
	factory, _, batch := newAnchorTestFactory()
	lease := prepareTestAnchor(t, factory, time.Now().Add(time.Hour))
	batch.stallOneRemove()
	ctx, cancel := context.WithTimeout(
		context.Background(), 15*time.Millisecond,
	)
	defer cancel()
	err := lease.Resource.Close(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled close error = %v", err)
	}
	assertAnchorFactoryReferences(t, factory, 1, 1)
	if err := lease.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertAnchorFactoryReferences(t, factory, 0, 0)
}

func TestLinuxPolicyAnchorExpiryRetriesCleanup(
	t *testing.T,
) {
	factory, _, batch := newAnchorTestFactory()
	batch.failRemoves(1)
	_ = prepareTestAnchor(t, factory, time.Now().Add(30*time.Millisecond))
	deadline := time.Now().Add(2 * time.Second)
	for {
		factory.mu.Lock()
		references := factory.underlayReferences
		anchors := len(factory.anchors)
		factory.mu.Unlock()
		if references == 0 && anchors == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf(
				"expired anchor residue: references=%d anchors=%d",
				references, anchors,
			)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := factory.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxPolicyAnchorRejectsMismatchedContractBeforeMutation(
	t *testing.T,
) {
	cases := []func(*LinuxUnderlayPolicyAnchorSpec){
		func(spec *LinuxUnderlayPolicyAnchorSpec) { spec.TableFamily = "ip" },
		func(spec *LinuxUnderlayPolicyAnchorSpec) { spec.TableName = "other" },
		func(spec *LinuxUnderlayPolicyAnchorSpec) { spec.OutputChain = "forward" },
		func(spec *LinuxUnderlayPolicyAnchorSpec) { spec.UnderlayInterface = "eth1" },
		func(spec *LinuxUnderlayPolicyAnchorSpec) { spec.DirectAWGUnderlayMark++ },
		func(spec *LinuxUnderlayPolicyAnchorSpec) { spec.ExpiresAt = time.Now().Add(-time.Second) },
	}
	for index, mutate := range cases {
		factory, runner, batch := newAnchorTestFactory()
		spec := anchorTestSpec(time.Now().Add(time.Hour))
		mutate(&spec)
		if _, err := factory.prepareUnderlayPolicyAnchor(
			context.Background(), spec,
		); err == nil {
			t.Fatalf("case %d unexpectedly succeeded", index)
		}
		if len(batch.snapshot()) != 0 || len(runner.snapshot()) != 0 {
			t.Fatalf(
				"case %d mutated policy: batches=%v commands=%v",
				index, batch.snapshot(), runner.snapshot(),
			)
		}
	}
}

func TestLinuxPolicyAnchorVerificationFailureRollsBackOwnedState(
	t *testing.T,
) {
	factory, runner, batch := newAnchorTestFactory()
	runner.chain = "type filter hook output; policy accept;"
	if _, err := factory.prepareUnderlayPolicyAnchor(
		context.Background(),
		anchorTestSpec(time.Now().Add(time.Hour)),
	); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("verification error = %v", err)
	}
	assertAnchorFactoryReferences(t, factory, 0, 0)
	factory.mu.Lock()
	installed := factory.installed
	factory.mu.Unlock()
	if installed {
		t.Fatal("failed first anchor left its owned table installed")
	}
	scripts := batch.snapshot()
	if countScript(scripts, "delete element inet winn_anchor underlay_marks") != 1 ||
		countScript(scripts, "delete table inet winn_anchor") != 1 {
		t.Fatalf("verification rollback batches = %#v", scripts)
	}
}

func prepareTestAnchor(
	t *testing.T,
	factory *LinuxNftResolvedPolicyFactory,
	expiresAt time.Time,
) LinuxUnderlayPolicyAnchorLease {
	t.Helper()
	lease, err := factory.prepareUnderlayPolicyAnchor(
		context.Background(), anchorTestSpec(expiresAt),
	)
	if err != nil {
		t.Fatal(err)
	}
	if lease.Resource == nil ||
		lease.TableFamily != "inet" ||
		lease.TableName != "winn_anchor" ||
		lease.OutputChain != "output" ||
		lease.UnderlayInterface != "eth0" ||
		lease.DirectAWGUnderlayMark != 0x9001 ||
		!lease.ExpiresAt.Equal(expiresAt.UTC()) {
		t.Fatalf("anchor lease = %#v", lease)
	}
	return lease
}

func prepareAnchorTestCandidate(
	t *testing.T,
	factory *LinuxNftResolvedPolicyFactory,
) LinuxPolicyTransaction {
	t.Helper()
	transaction, err := factory.Prepare(
		context.Background(),
		LinuxPolicySpec{
			Binding:       verticalBinding(time.Now().UTC()),
			InterfaceName: "winn123",
			InnerAddress:  netip.MustParsePrefix("10.77.0.2/32"),
			RouteTable:    10001,
			FirewallMark:  0x1234,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return transaction
}

func anchorTestSpec(expiresAt time.Time) LinuxUnderlayPolicyAnchorSpec {
	return LinuxUnderlayPolicyAnchorSpec{
		TableFamily:           "inet",
		TableName:             "winn_anchor",
		OutputChain:           "output",
		UnderlayInterface:     "eth0",
		DirectAWGUnderlayMark: 0x9001,
		ExpiresAt:             expiresAt,
	}
}

func newAnchorTestFactory() (
	*LinuxNftResolvedPolicyFactory,
	*anchorPolicyRunner,
	*anchorBatchRunner,
) {
	runner := &anchorPolicyRunner{
		chain: "type filter hook output priority mangle; policy drop;\n" +
			"meta mark @underlay_marks oifname @underlay_ifaces accept\n",
		sets: map[string]string{
			"tunnel_ifaces":   `type ifname; elements = { }`,
			"underlay_ifaces": `type ifname; elements = { "eth0" }`,
			"underlay_marks":  `type mark; elements = { 0x00009001 }`,
		},
	}
	batch := &anchorBatchRunner{}
	factory := &LinuxNftResolvedPolicyFactory{
		config: LinuxNftResolvedPolicyConfig{
			NftBinary:         "/test/nft",
			ResolvectlBinary:  "/test/resolvectl",
			TableName:         "winn_anchor",
			UnderlayInterface: "eth0",
			UnderlayMark:      0x9001,
			DNSResolver:       netip.MustParseAddr("10.66.0.53"),
			HealthInterval:    30 * time.Second,
			Runner:            runner,
		},
		batch: batch,
	}
	return factory, runner, batch
}

func assertAnchorFactoryReferences(
	t *testing.T,
	factory *LinuxNftResolvedPolicyFactory,
	references int,
	anchors int,
) {
	t.Helper()
	factory.mu.Lock()
	defer factory.mu.Unlock()
	if factory.underlayReferences != references ||
		len(factory.anchors) != anchors {
		t.Fatalf(
			"factory references=%d anchors=%d, want %d/%d",
			factory.underlayReferences, len(factory.anchors),
			references, anchors,
		)
	}
}

func assertAnchorCommandsOnlyNft(
	t *testing.T,
	commands []LinuxCommand,
) {
	t.Helper()
	for _, command := range commands {
		if command.Path != "/test/nft" {
			t.Fatalf("anchor issued non-nft command: %#v", command)
		}
	}
}

func countScript(scripts []string, needle string) int {
	count := 0
	for _, script := range scripts {
		if strings.Contains(script, needle) {
			count++
		}
	}
	return count
}

type anchorBatchRunner struct {
	mu              sync.Mutex
	scripts         []string
	failRemoveCount int
	stallRemove     bool
}

func (runner *anchorBatchRunner) Run(
	ctx context.Context,
	script string,
) error {
	runner.mu.Lock()
	runner.scripts = append(runner.scripts, script)
	remove := strings.HasPrefix(script, "delete element")
	if remove && runner.failRemoveCount > 0 {
		runner.failRemoveCount--
		runner.mu.Unlock()
		return errors.New("injected anchor removal failure")
	}
	stall := remove && runner.stallRemove
	if stall {
		runner.stallRemove = false
	}
	runner.mu.Unlock()
	if stall {
		<-ctx.Done()
		return context.Cause(ctx)
	}
	return nil
}

func (runner *anchorBatchRunner) snapshot() []string {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return append([]string(nil), runner.scripts...)
}

func (runner *anchorBatchRunner) failRemoves(count int) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.failRemoveCount = count
}

func (runner *anchorBatchRunner) stallOneRemove() {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.stallRemove = true
}

type anchorPolicyRunner struct {
	mu       sync.Mutex
	commands []LinuxCommand
	chain    string
	sets     map[string]string
}

func (runner *anchorPolicyRunner) Run(
	_ context.Context,
	command LinuxCommand,
) (LinuxCommandResult, error) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.commands = append(runner.commands, command)
	if len(command.Args) >= 2 &&
		command.Args[0] == "list" &&
		command.Args[1] == "chain" {
		return LinuxCommandResult{Stdout: []byte(runner.chain)}, nil
	}
	if len(command.Args) >= 2 &&
		command.Args[0] == "list" &&
		command.Args[1] == "set" {
		return LinuxCommandResult{
			Stdout: []byte(runner.sets[command.Args[len(command.Args)-1]]),
		}, nil
	}
	return LinuxCommandResult{}, nil
}

func (*anchorPolicyRunner) Start(
	LinuxCommand,
) (LinuxManagedProcess, error) {
	return nil, errors.New("unexpected process start")
}

func (runner *anchorPolicyRunner) snapshot() []LinuxCommand {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	result := make([]LinuxCommand, len(runner.commands))
	copy(result, runner.commands)
	return result
}
