package preparation

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
)

func TestLinuxUnderlayAuthorizerRequiresExactNamespaceAndTableContract(
	t *testing.T,
) {
	runner := newFakeLinuxUnderlayRunner()
	tests := []struct {
		name   string
		mutate func(*LinuxUnderlayMarkAuthorizerConfig)
	}{
		{
			name: "implicit root namespace",
			mutate: func(config *LinuxUnderlayMarkAuthorizerConfig) {
				config.AllowRootNetworkNamespace = false
			},
		},
		{
			name: "ambiguous named and root namespace",
			mutate: func(config *LinuxUnderlayMarkAuthorizerConfig) {
				config.NetworkNamespace = "winn-ns"
			},
		},
		{
			name: "namespace path instead of exact name",
			mutate: func(config *LinuxUnderlayMarkAuthorizerConfig) {
				config.AllowRootNetworkNamespace = false
				config.NetworkNamespace = "/run/netns/winn"
			},
		},
		{
			name: "relative nft command",
			mutate: func(config *LinuxUnderlayMarkAuthorizerConfig) {
				config.NftBinary = "nft"
			},
		},
		{
			name: "wrong family",
			mutate: func(config *LinuxUnderlayMarkAuthorizerConfig) {
				config.TableFamily = "ip"
			},
		},
		{
			name: "wrong chain",
			mutate: func(config *LinuxUnderlayMarkAuthorizerConfig) {
				config.OutputChain = "forward"
			},
		},
		{
			name: "zero mark",
			mutate: func(config *LinuxUnderlayMarkAuthorizerConfig) {
				config.FirewallMark = 0
			},
		},
		{
			name: "H3 mark aliases Direct AWG mark",
			mutate: func(config *LinuxUnderlayMarkAuthorizerConfig) {
				config.FirewallMark = config.DirectAWGUnderlayMark
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := testLinuxUnderlayConfig(runner)
			test.mutate(&config)
			if _, err := NewLinuxUnderlayMarkAuthorizer(
				config,
			); err == nil {
				t.Fatal("ambiguous Linux policy contract was accepted")
			}
		})
	}
}

func TestLinuxUnderlayAuthorizerInstallsVerifiesAndReferenceCounts(
	t *testing.T,
) {
	runner := newFakeLinuxUnderlayRunner()
	authorizer := newTestLinuxUnderlayAuthorizer(t, runner)
	now := time.Now().UTC()
	request := testLinuxUnderlayRequest(now.Add(time.Minute))
	first, err := authorizer.AuthorizeUnderlayMark(
		context.Background(), request,
	)
	if err != nil {
		t.Fatal(err)
	}
	secondRequest := request
	secondRequest.CandidateID = "h3-secondary"
	second, err := authorizer.AuthorizeUnderlayMark(
		context.Background(), secondRequest,
	)
	if err != nil {
		t.Fatal(err)
	}
	if first.InterfaceName != "eth0" ||
		first.FirewallMark != 0x9101 ||
		first.SignedEndpoint != request.SignedEndpoint ||
		first.AuthorizationID == second.AuthorizationID ||
		first.Resource == nil ||
		second.Resource == nil {
		t.Fatalf(
			"Linux authorization mapping first=%#v second=%#v",
			first, second,
		)
	}
	if runner.adds != 1 || !runner.markPresent {
		t.Fatalf(
			"mark installation adds=%d present=%t",
			runner.adds, runner.markPresent,
		)
	}
	if err := first.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !runner.markPresent || runner.deletes != 0 {
		t.Fatal("first reference revoked a shared authorization")
	}
	if err := second.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.markPresent || runner.deletes != 1 {
		t.Fatal("last reference did not synchronously revoke the mark")
	}
	if err := second.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, command := range runner.snapshot() {
		if command.Path != "/test/nft" ||
			!strings.HasPrefix(command.Path, "/") {
			t.Fatalf("non-absolute or unexpected command: %#v", command)
		}
		for _, argument := range command.Args {
			if strings.ContainsRune(argument, 0) {
				t.Fatalf("NUL-bearing argv: %#v", command)
			}
			if strings.Contains(argument, "gateway.example") {
				t.Fatalf(
					"signed endpoint leaked into privileged argv: %#v",
					command,
				)
			}
		}
	}
	if !runner.sawArgs([]string{
		"add", "element", "inet", "winn_filter",
		"underlay_marks", "{", "0x00009101", "}",
	}) {
		t.Fatal("exact argv-safe nft add command was not executed")
	}
}

func TestLinuxUnderlayAuthorizerUsesExactNamedNamespace(t *testing.T) {
	runner := newFakeLinuxUnderlayRunner()
	config := testLinuxUnderlayConfig(runner)
	config.AllowRootNetworkNamespace = false
	config.NetworkNamespace = "winn-carrier"
	authorizer, err := NewLinuxUnderlayMarkAuthorizer(config)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := authorizer.AuthorizeUnderlayMark(
		context.Background(),
		testLinuxUnderlayRequest(time.Now().UTC().Add(time.Minute)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, command := range runner.snapshot() {
		if command.Path != "/test/ip" ||
			len(command.Args) < 5 ||
			!slices.Equal(command.Args[:4], []string{
				"netns", "exec", "winn-carrier", "/test/nft",
			}) {
			t.Fatalf("namespace command changed: %#v", command)
		}
	}
}

func TestLinuxUnderlayAuthorizerNeverAdoptsOrWeakensPolicy(
	t *testing.T,
) {
	tests := []struct {
		name   string
		mutate func(*fakeLinuxUnderlayRunner)
	}{
		{
			name: "persistent chain is not drop",
			mutate: func(runner *fakeLinuxUnderlayRunner) {
				runner.policyValid = false
			},
		},
		{
			name: "persistent chain priority differs",
			mutate: func(runner *fakeLinuxUnderlayRunner) {
				runner.policyPriority = -149
			},
		},
		{
			name: "bypass match is not equality",
			mutate: func(runner *fakeLinuxUnderlayRunner) {
				runner.matchOperator = "!="
			},
		},
		{
			name: "persistent interface member absent",
			mutate: func(runner *fakeLinuxUnderlayRunner) {
				runner.interfacePresent = false
			},
		},
		{
			name: "Direct AWG anchor mark absent",
			mutate: func(runner *fakeLinuxUnderlayRunner) {
				runner.ownerMarkPresent = false
			},
		},
		{
			name: "configured mark already owned",
			mutate: func(runner *fakeLinuxUnderlayRunner) {
				runner.markPresent = true
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := newFakeLinuxUnderlayRunner()
			test.mutate(runner)
			authorizer := newTestLinuxUnderlayAuthorizer(t, runner)
			if _, err := authorizer.AuthorizeUnderlayMark(
				context.Background(),
				testLinuxUnderlayRequest(
					time.Now().UTC().Add(time.Minute),
				),
			); err == nil {
				t.Fatal("unsafe persistent policy was accepted")
			}
			if runner.adds != 0 || runner.deletes != 0 {
				t.Fatalf(
					"persistent policy was mutated adds=%d deletes=%d",
					runner.adds, runner.deletes,
				)
			}
		})
	}
}

func TestLinuxUnderlayAuthorizerRollsBackFailedReadback(
	t *testing.T,
) {
	runner := newFakeLinuxUnderlayRunner()
	runner.malformedMarkReadsAfterAdd = 1
	authorizer := newTestLinuxUnderlayAuthorizer(t, runner)
	request := testLinuxUnderlayRequest(
		time.Now().UTC().Add(time.Minute),
	)
	if _, err := authorizer.AuthorizeUnderlayMark(
		context.Background(), request,
	); err == nil {
		t.Fatal("failed installed-membership readback was accepted")
	}
	if runner.markPresent || runner.adds != 1 || runner.deletes != 1 {
		t.Fatalf(
			"failed installation was not rolled back: present=%t add=%d delete=%d",
			runner.markPresent, runner.adds, runner.deletes,
		)
	}
	lease, err := authorizer.AuthorizeUnderlayMark(
		context.Background(), request,
	)
	if err != nil {
		t.Fatalf("authorizer did not recover after rollback: %v", err)
	}
	if err := lease.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxUnderlayAuthorizerRetainsRetryableCleanupState(
	t *testing.T,
) {
	runner := newFakeLinuxUnderlayRunner()
	authorizer := newTestLinuxUnderlayAuthorizer(t, runner)
	request := testLinuxUnderlayRequest(
		time.Now().UTC().Add(time.Minute),
	)
	lease, err := authorizer.AuthorizeUnderlayMark(
		context.Background(), request,
	)
	if err != nil {
		t.Fatal(err)
	}
	runner.failDeletes = 1
	if err := lease.Resource.Close(
		context.Background(),
	); err == nil {
		t.Fatal("failed mark cleanup was hidden")
	}
	if !runner.markPresent {
		t.Fatal("test did not retain failed cleanup state")
	}
	if _, err := authorizer.AuthorizeUnderlayMark(
		context.Background(), request,
	); err == nil {
		t.Fatal("new authorization entered cleanup-pending state")
	}
	if err := lease.Resource.Close(context.Background()); err != nil {
		t.Fatalf("retryable cleanup did not recover: %v", err)
	}
	if runner.markPresent || runner.deletes != 2 {
		t.Fatalf(
			"retry cleanup present=%t deletes=%d",
			runner.markPresent, runner.deletes,
		)
	}
}

func TestLinuxUnderlayAuthorizerExpiresAndRevokesMark(t *testing.T) {
	runner := newFakeLinuxUnderlayRunner()
	config := testLinuxUnderlayConfig(runner)
	config.CommandTimeout = 100 * time.Millisecond
	config.CleanupRetryInterval = 10 * time.Millisecond
	authorizer, err := NewLinuxUnderlayMarkAuthorizer(config)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := authorizer.AuthorizeUnderlayMark(
		context.Background(),
		testLinuxUnderlayRequest(
			time.Now().UTC().Add(35*time.Millisecond),
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	runner.failDeletes = 1
	runner.mu.Unlock()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		runner.mu.Lock()
		present := runner.markPresent
		runner.mu.Unlock()
		if !present {
			break
		}
		time.Sleep(time.Millisecond)
	}
	runner.mu.Lock()
	present := runner.markPresent
	runner.mu.Unlock()
	if present {
		t.Fatal("expired authorization mark remained installed")
	}
	runner.mu.Lock()
	deletes := runner.deletes
	runner.mu.Unlock()
	if deletes != 2 {
		t.Fatalf("expiry cleanup attempts = %d; want retry after failure", deletes)
	}
	if err := lease.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxUnderlayAuthorizerProtectsColdH3Builder(t *testing.T) {
	harness := newProductionHarness(t)
	runner := newFakeLinuxUnderlayRunner()
	config := testLinuxUnderlayConfig(runner)
	config.Now = func() time.Time { return harness.now }
	authorizer, err := NewLinuxUnderlayMarkAuthorizer(config)
	if err != nil {
		t.Fatal(err)
	}
	checkingBuilder := &markCheckingH3Builder{
		runner:   runner,
		delegate: harness.h3,
	}
	factory, err := NewProductionFactory(ProductionFactoryConfig{
		Deployments:  []VerifiedDeploymentV2{harness.deployment},
		PSKs:         harness.psks,
		Credentials:  harness.credentials,
		PolicyAnchor: harness.policyAnchor,
		Underlay:     authorizer,
		DirectAWG:    harness.direct,
		H3:           checkingBuilder,
		Now:          func() time.Time { return harness.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := factory.PrepareCandidate(
		context.Background(), harness.h3Context(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !checkingBuilder.sawAuthorized {
		t.Fatal("cold H3 builder ran before mark authorization")
	}
	if err := prepared.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	present := runner.markPresent
	runner.mu.Unlock()
	if present {
		t.Fatal("H3 candidate cleanup retained its underlay mark")
	}
}

func TestLinuxUnderlayAuthorizerConcurrentReferences(t *testing.T) {
	runner := newFakeLinuxUnderlayRunner()
	authorizer := newTestLinuxUnderlayAuthorizer(t, runner)
	const workers = 64
	expiresAt := time.Now().UTC().Add(time.Minute)
	resources := make(chan Resource, workers)
	failures := make(chan error, workers)
	var authorizeGroup sync.WaitGroup
	authorizeGroup.Add(workers)
	for index := range workers {
		go func() {
			defer authorizeGroup.Done()
			request := testLinuxUnderlayRequest(expiresAt)
			request.CandidateID = "h3-race-" + strconvItoa(index)
			lease, err := authorizer.AuthorizeUnderlayMark(
				context.Background(), request,
			)
			if err != nil {
				failures <- err
				return
			}
			resources <- lease.Resource
		}()
	}
	authorizeGroup.Wait()
	close(resources)
	var closeGroup sync.WaitGroup
	for resource := range resources {
		closeGroup.Add(1)
		go func(current Resource) {
			defer closeGroup.Done()
			if err := current.Close(context.Background()); err != nil {
				failures <- err
			}
		}(resource)
	}
	closeGroup.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if runner.adds != 1 || runner.deletes != 1 ||
		runner.markPresent {
		t.Fatalf(
			"reference counts add=%d delete=%d present=%t",
			runner.adds, runner.deletes, runner.markPresent,
		)
	}
}

func newTestLinuxUnderlayAuthorizer(
	t testing.TB,
	runner *fakeLinuxUnderlayRunner,
) *LinuxUnderlayMarkAuthorizer {
	t.Helper()
	authorizer, err := NewLinuxUnderlayMarkAuthorizer(
		testLinuxUnderlayConfig(runner),
	)
	if err != nil {
		t.Fatal(err)
	}
	return authorizer
}

func testLinuxUnderlayConfig(
	runner LinuxUnderlayCommandRunner,
) LinuxUnderlayMarkAuthorizerConfig {
	return LinuxUnderlayMarkAuthorizerConfig{
		NftBinary:                 "/test/nft",
		IPBinary:                  "/test/ip",
		AllowRootNetworkNamespace: true,
		TableFamily:               "inet",
		TableName:                 "winn_filter",
		OutputChain:               "output",
		UnderlayInterface:         "eth0",
		DirectAWGUnderlayMark:     0x9001,
		FirewallMark:              0x9101,
		CommandTimeout:            time.Second,
		CleanupRetryInterval:      time.Minute,
		Runner:                    runner,
	}
}

func testLinuxUnderlayRequest(
	expiresAt time.Time,
) UnderlayMarkAuthorizationRequest {
	return UnderlayMarkAuthorizationRequest{
		CandidateID:      "h3-primary",
		NodeID:           "gateway-production",
		Carrier:          connectivity.CarrierHTTP3,
		ManifestDigest:   strings.Repeat("a", 64),
		ManifestSequence: 7,
		SignedEndpoint:   "https://gateway.example/.well-known/masque/udp/{target_host}/{target_port}/",
		ExpiresAt:        expiresAt,
	}
}

type markCheckingH3Builder struct {
	runner        *fakeLinuxUnderlayRunner
	delegate      H3PreparationBuilder
	sawAuthorized bool
}

func (builder *markCheckingH3Builder) PrepareH3(
	ctx context.Context,
	input H3PreparationInput,
) (CandidateBuild, error) {
	builder.runner.mu.Lock()
	builder.sawAuthorized = builder.runner.markPresent &&
		input.UnderlayMark.FirewallMark == 0x9101 &&
		input.UnderlayMark.InterfaceName == "eth0"
	builder.runner.mu.Unlock()
	if !builder.sawAuthorized {
		return CandidateBuild{},
			errors.New("H3 builder received no installed authorization")
	}
	return builder.delegate.PrepareH3(ctx, input)
}

type fakeLinuxUnderlayRunner struct {
	mu sync.Mutex

	commands                   []LinuxUnderlayCommand
	policyValid                bool
	policyPriority             int
	matchOperator              string
	interfacePresent           bool
	ownerMarkPresent           bool
	markPresent                bool
	adds                       int
	deletes                    int
	failDeletes                int
	malformedMarkReadsAfterAdd int
}

func newFakeLinuxUnderlayRunner() *fakeLinuxUnderlayRunner {
	return &fakeLinuxUnderlayRunner{
		policyValid:      true,
		policyPriority:   -150,
		matchOperator:    "==",
		interfacePresent: true,
		ownerMarkPresent: true,
	}
}

func (runner *fakeLinuxUnderlayRunner) Run(
	_ context.Context,
	command LinuxUnderlayCommand,
) (LinuxUnderlayCommandResult, error) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	command.Args = slices.Clone(command.Args)
	runner.commands = append(runner.commands, command)
	args := command.Args
	if command.Path == "/test/ip" {
		if len(args) < 5 ||
			args[0] != "netns" ||
			args[1] != "exec" ||
			args[3] != "/test/nft" {
			return LinuxUnderlayCommandResult{},
				errors.New("invalid namespace command")
		}
		args = args[4:]
	} else if command.Path != "/test/nft" {
		return LinuxUnderlayCommandResult{},
			errors.New("unexpected command path")
	}
	if len(args) == 6 &&
		slices.Equal(args[:3], []string{"-j", "list", "chain"}) {
		return LinuxUnderlayCommandResult{
			Stdout: runner.chainJSON(),
		}, nil
	}
	if len(args) == 6 &&
		slices.Equal(args[:3], []string{"-j", "list", "set"}) {
		switch args[5] {
		case "underlay_ifaces":
			return LinuxUnderlayCommandResult{
				Stdout: runner.setJSON(
					"underlay_ifaces",
					runner.interfacePresent,
					"eth0",
				),
			}, nil
		case "underlay_marks":
			if runner.markPresent &&
				runner.malformedMarkReadsAfterAdd > 0 {
				runner.malformedMarkReadsAfterAdd--
				return LinuxUnderlayCommandResult{
					Stdout: []byte("{"),
				}, nil
			}
			elements := []any{}
			if runner.ownerMarkPresent {
				elements = append(elements, uint32(0x9001))
			}
			if runner.markPresent {
				elements = append(elements, uint32(0x9101))
			}
			return LinuxUnderlayCommandResult{
				Stdout: runner.setElementsJSON(
					"underlay_marks", elements,
				),
			}, nil
		}
	}
	if len(args) == 8 &&
		args[1] == "element" &&
		args[4] == "underlay_marks" {
		switch args[0] {
		case "add":
			runner.adds++
			runner.markPresent = true
			return LinuxUnderlayCommandResult{}, nil
		case "delete":
			runner.deletes++
			if runner.failDeletes > 0 {
				runner.failDeletes--
				return LinuxUnderlayCommandResult{},
					errors.New("injected nft delete failure")
			}
			runner.markPresent = false
			return LinuxUnderlayCommandResult{}, nil
		}
	}
	return LinuxUnderlayCommandResult{},
		errors.New("unexpected nft argv")
}

func (runner *fakeLinuxUnderlayRunner) chainJSON() []byte {
	policy := "drop"
	if !runner.policyValid {
		policy = "accept"
	}
	return mustJSON(map[string]any{
		"nftables": []any{
			map[string]any{
				"chain": map[string]any{
					"family": "inet",
					"table":  "winn_filter",
					"name":   "output",
					"type":   "filter",
					"hook":   "output",
					"prio":   runner.policyPriority,
					"policy": policy,
				},
			},
			map[string]any{
				"rule": map[string]any{
					"family": "inet",
					"table":  "winn_filter",
					"chain":  "output",
					"expr": []any{
						map[string]any{
							"match": map[string]any{
								"op": runner.matchOperator,
								"left": map[string]any{
									"meta": map[string]any{
										"key": "mark",
									},
								},
								"right": "@underlay_marks",
							},
						},
						map[string]any{
							"match": map[string]any{
								"op": runner.matchOperator,
								"left": map[string]any{
									"meta": map[string]any{
										"key": "oifname",
									},
								},
								"right": "@underlay_ifaces",
							},
						},
						map[string]any{"accept": nil},
					},
				},
			},
		},
	})
}

func (runner *fakeLinuxUnderlayRunner) setJSON(
	name string,
	present bool,
	value any,
) []byte {
	elements := []any{}
	if present {
		elements = append(elements, value)
	}
	return runner.setElementsJSON(name, elements)
}

func (runner *fakeLinuxUnderlayRunner) setElementsJSON(
	name string,
	elements []any,
) []byte {
	dataType := "ifname"
	if name == "underlay_marks" {
		dataType = "mark"
	}
	return mustJSON(map[string]any{
		"nftables": []any{
			map[string]any{
				"set": map[string]any{
					"family": "inet",
					"table":  "winn_filter",
					"name":   name,
					"type":   dataType,
					"elem":   elements,
				},
			},
		},
	})
}

func (runner *fakeLinuxUnderlayRunner) snapshot() []LinuxUnderlayCommand {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	result := make([]LinuxUnderlayCommand, len(runner.commands))
	for index, command := range runner.commands {
		command.Args = slices.Clone(command.Args)
		result[index] = command
	}
	return result
}

func (runner *fakeLinuxUnderlayRunner) sawArgs(expected []string) bool {
	for _, command := range runner.snapshot() {
		args := command.Args
		if command.Path == "/test/ip" && len(args) >= 4 {
			args = args[4:]
		}
		if reflect.DeepEqual(args, expected) {
			return true
		}
	}
	return false
}

func mustJSON(value any) []byte {
	result, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return result
}

func strconvItoa(value int) string {
	const digits = "0123456789"
	if value == 0 {
		return "0"
	}
	var raw [20]byte
	index := len(raw)
	for value > 0 {
		index--
		raw[index] = digits[value%10]
		value /= 10
	}
	return string(raw[index:])
}

var _ H3PreparationBuilder = (*markCheckingH3Builder)(nil)
var _ LinuxUnderlayCommandRunner = (*fakeLinuxUnderlayRunner)(nil)
