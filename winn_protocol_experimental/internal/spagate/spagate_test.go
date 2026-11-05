package spagate

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/knock"
)

const testPacketSize = 256

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

// recordingRunner captures the argv nft would have been invoked with.
type recordingRunner struct {
	mu     sync.Mutex
	calls  [][]string
	stdins []string
	output []byte
	err    error
}

func (r *recordingRunner) run(
	_ context.Context, name, stdin string, args ...string,
) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, append([]string{name}, args...))
	r.stdins = append(r.stdins, stdin)
	return r.output, r.err
}

func (r *recordingRunner) stdinAt(i int) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i >= len(r.stdins) {
		return ""
	}
	return r.stdins[i]
}

func (r *recordingRunner) snapshot() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]string, len(r.calls))
	copy(out, r.calls)
	return out
}

// --- Enforcer ---------------------------------------------------------------

// Authorize must submit ONE transaction that destroys then re-adds the element.
//
// A plain `add element` on a live element does NOT renew its timeout - measured
// against nftables 1.0.9, a re-add at t=10 of a 30s element left it at
// `expires 19s989ms` and returned exit 0, with or without an explicit
// `timeout`. This test pins the destroy+add shape so that regression cannot
// come back silently. It is still only a STRUCTURAL check; the behavioural
// proof that the deadline actually moves lives in
// deploy/spa/test/run_integration_test.sh, which reads the deadline back out of
// a real kernel.
func TestNFTEnforcerAuthorizeRenewsWithDestroyThenAdd(t *testing.T) {
	runner := &recordingRunner{}
	enforcer, err := NewNFTEnforcer(NFTConfig{
		Binary: "/usr/sbin/nft", SetV4: "spa_allow_v4", runner: runner.run,
	})
	if err != nil {
		t.Fatalf("NewNFTEnforcer: %v", err)
	}
	err = enforcer.Authorize(
		context.Background(), netip.MustParseAddr("203.0.113.7"), 90*time.Second,
	)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	calls := runner.snapshot()
	if len(calls) != 1 {
		t.Fatalf("got %d nft calls, want 1: %v", len(calls), calls)
	}
	if got, want := strings.Join(calls[0], " "), "/usr/sbin/nft -f -"; got != want {
		t.Fatalf("argv = %q, want %q (the transaction goes on stdin)", got, want)
	}

	transaction := runner.stdinAt(0)
	destroyAt := strings.Index(transaction, "destroy element")
	addAt := strings.Index(transaction, "add element")
	if destroyAt < 0 {
		t.Fatalf("transaction has no destroy, so it cannot renew:\n%s", transaction)
	}
	if addAt < 0 {
		t.Fatalf("transaction has no add:\n%s", transaction)
	}
	if destroyAt > addAt {
		t.Fatalf("destroy must precede add, got:\n%s", transaction)
	}
	for _, fragment := range []string{
		"destroy element inet winn_spa spa_allow_v4 { 203.0.113.7 }",
		"add element inet winn_spa spa_allow_v4 { 203.0.113.7 timeout 90s }",
	} {
		if !strings.Contains(transaction, fragment) {
			t.Fatalf("transaction missing %q:\n%s", fragment, transaction)
		}
	}
}

// Deadline must read the remaining time back out of nft's own output, because
// that is the only thing that can prove a renewal took effect.
func TestDeadlineParsesKernelExpiry(t *testing.T) {
	listing := `table inet winn_spa {
	set spa_allow_v4 {
		type ipv4_addr
		flags dynamic,timeout
		timeout 30m
		elements = { 203.0.113.7 expires 29m59s968ms, 198.51.100.2 expires 4s }
	}
}`
	runner := &recordingRunner{output: []byte(listing)}
	enforcer, err := NewNFTEnforcer(NFTConfig{
		SetV4: "spa_allow_v4", runner: runner.run,
	})
	if err != nil {
		t.Fatalf("NewNFTEnforcer: %v", err)
	}
	remaining, ok, err := enforcer.Deadline(
		context.Background(), netip.MustParseAddr("203.0.113.7"),
	)
	if err != nil || !ok {
		t.Fatalf("Deadline: remaining=%s ok=%v err=%v", remaining, ok, err)
	}
	if remaining < 29*time.Minute || remaining > 30*time.Minute {
		t.Fatalf("remaining = %s, want ~29m59s", remaining)
	}
	// A second element in the same set must not be confused for the first.
	remaining, ok, err = enforcer.Deadline(
		context.Background(), netip.MustParseAddr("198.51.100.2"),
	)
	if err != nil || !ok || remaining != 4*time.Second {
		t.Fatalf("second element: remaining=%s ok=%v err=%v", remaining, ok, err)
	}
	// An address that is not authorized must report ok=false, not an error.
	_, ok, err = enforcer.Deadline(
		context.Background(), netip.MustParseAddr("192.0.2.1"),
	)
	if err != nil || ok {
		t.Fatalf("absent address: ok=%v err=%v, want ok=false err=nil", ok, err)
	}
}

// A grant must never be silently dropped because the operator configured only
// one address family. Half-configured must be loud.
func TestNFTEnforcerRefusesFamilyWithNoSet(t *testing.T) {
	runner := &recordingRunner{}
	enforcer, err := NewNFTEnforcer(NFTConfig{
		SetV4: "spa_allow_v4", runner: runner.run,
	})
	if err != nil {
		t.Fatalf("NewNFTEnforcer: %v", err)
	}
	err = enforcer.Authorize(
		context.Background(), netip.MustParseAddr("2001:db8::1"), time.Minute,
	)
	if !errors.Is(err, ErrNoSetForFamily) {
		t.Fatalf("got %v, want ErrNoSetForFamily", err)
	}
	if calls := runner.snapshot(); len(calls) != 0 {
		t.Fatalf("nft was invoked for an unconfigured family: %v", calls)
	}
}

func TestNFTEnforcerRefusesNonUnicast(t *testing.T) {
	runner := &recordingRunner{}
	enforcer, err := NewNFTEnforcer(NFTConfig{
		SetV4: "spa_allow_v4", SetV6: "spa_allow_v6", runner: runner.run,
	})
	if err != nil {
		t.Fatalf("NewNFTEnforcer: %v", err)
	}
	for _, address := range []string{"0.0.0.0", "224.0.0.1", "127.0.0.1", "::"} {
		err := enforcer.Authorize(
			context.Background(), netip.MustParseAddr(address), time.Minute,
		)
		if !errors.Is(err, ErrUnroutableAddress) {
			t.Fatalf("%s: got %v, want ErrUnroutableAddress", address, err)
		}
	}
	if calls := runner.snapshot(); len(calls) != 0 {
		t.Fatalf("nft was invoked for a non-unicast address: %v", calls)
	}
}

// IPv4-in-IPv6 must land in the v4 set, or the same client would be tracked
// under two different keys and the v4 rule would never match it.
func TestNFTEnforcerMapsV4In6ToV4Set(t *testing.T) {
	runner := &recordingRunner{}
	enforcer, err := NewNFTEnforcer(NFTConfig{
		SetV4: "spa_allow_v4", SetV6: "spa_allow_v6", runner: runner.run,
	})
	if err != nil {
		t.Fatalf("NewNFTEnforcer: %v", err)
	}
	address := netip.MustParseAddr("::ffff:203.0.113.9")
	if err := enforcer.Authorize(context.Background(), address, time.Minute); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	got := runner.stdinAt(0)
	if !strings.Contains(got, "spa_allow_v4") {
		t.Fatalf("v4-in-v6 address did not use the v4 set: %q", got)
	}
	if strings.Contains(got, "spa_allow_v6") {
		t.Fatalf("v4-in-v6 address leaked into the v6 set: %q", got)
	}
}

func TestNFTEnforcerRejectsUnsafeObjectNames(t *testing.T) {
	// An EMPTY name is not in this list on purpose: empty means "use the
	// default" for the table and family, and "disable this family" for a set.
	// Only a name that is present and malformed is a refusal.
	for _, name := range []string{
		"winn spa", "winn;spa", "winn{spa}", "winn\nspa", "$(id)",
		strings.Repeat("a", 65),
	} {
		if _, err := NewNFTEnforcer(NFTConfig{Table: name, SetV4: "s"}); err == nil {
			t.Fatalf("accepted unsafe table name %q", name)
		}
		if _, err := NewNFTEnforcer(NFTConfig{SetV4: name}); err == nil {
			t.Fatalf("accepted unsafe set name %q", name)
		}
	}
}

// An empty table name must fall back to the documented default rather than
// producing a table literally named "".
func TestNFTEnforcerDefaultsEmptyNames(t *testing.T) {
	runner := &recordingRunner{}
	enforcer, err := NewNFTEnforcer(NFTConfig{SetV4: "s", runner: runner.run})
	if err != nil {
		t.Fatalf("NewNFTEnforcer: %v", err)
	}
	if err := enforcer.Authorize(
		context.Background(), netip.MustParseAddr("203.0.113.4"), time.Minute,
	); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if got := strings.Join(runner.snapshot()[0], " "); !strings.Contains(got, DefaultNFTBinary) {
		t.Fatalf("empty binary did not take the documented default: %q", got)
	}
	if got := runner.stdinAt(0); !strings.Contains(
		got, " "+DefaultFamily+" "+DefaultTable+" ",
	) {
		t.Fatalf("empty names did not take the documented defaults: %q", got)
	}
}

func TestNFTEnforcerRequiresAtLeastOneSet(t *testing.T) {
	if _, err := NewNFTEnforcer(NFTConfig{}); err == nil {
		t.Fatal("accepted a configuration with no sets")
	}
}

// SPA revert is `nft delete table FAMILY TABLE`. Those names are where
// iptables-nft stores WINN3GW-* (`ip filter`) and where firewalld/ufw-nft
// live (`inet filter`). Accepting them would make revert a host-firewall wipe.
func TestNFTEnforcerRefusesReservedIptablesTableNames(t *testing.T) {
	for _, name := range []string{"filter", "nat", "mangle", "raw", "security"} {
		if _, err := NewNFTEnforcer(NFTConfig{Table: name, SetV4: "spa_allow_v4"}); err == nil {
			t.Fatalf("accepted reserved table name %q", name)
		}
	}
	if _, err := NewNFTEnforcer(NFTConfig{Table: DefaultTable, SetV4: "spa_allow_v4"}); err != nil {
		t.Fatalf("default table %q was refused: %v", DefaultTable, err)
	}
}

// The daemon must never install or tear down the gate. A crash then cannot
// leave a rule the process created, and cannot delete WINN3GW-* by accident.
func TestNFTEnforcerAuthorizeNeverWritesRulesOrTables(t *testing.T) {
	runner := &recordingRunner{}
	enforcer, err := NewNFTEnforcer(NFTConfig{
		SetV4: "spa_allow_v4", runner: runner.run,
	})
	if err != nil {
		t.Fatalf("NewNFTEnforcer: %v", err)
	}
	if err := enforcer.Authorize(
		context.Background(), netip.MustParseAddr("203.0.113.7"), time.Minute,
	); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	transaction := runner.stdinAt(0)
	for _, forbidden := range []string{
		"add table", "create table", "add chain", "add rule",
		"delete table", "flush ruleset", "flush table", "delete chain",
		"delete rule", "add set",
	} {
		if strings.Contains(transaction, forbidden) {
			t.Fatalf("Authorize submitted %q; daemon may only mutate set elements:\n%s",
				forbidden, transaction)
		}
	}
	if !strings.Contains(transaction, "destroy element") ||
		!strings.Contains(transaction, "add element") {
		t.Fatalf("Authorize lost the destroy+add element transaction:\n%s", transaction)
	}
}

// nft(8) rejects fractional seconds, and rounding DOWN would silently shorten
// a grant.
func TestNFTDurationRoundsUpToWholeSeconds(t *testing.T) {
	for _, testCase := range []struct {
		in   time.Duration
		want string
	}{
		{90 * time.Second, "90s"},
		{1500 * time.Millisecond, "2s"},
		{time.Millisecond, "1s"},
		{0, "1s"},
		{2 * time.Minute, "120s"},
	} {
		if got := nftDuration(testCase.in); got != testCase.want {
			t.Fatalf("nftDuration(%s) = %q, want %q",
				testCase.in, got, testCase.want)
		}
	}
}

// scriptedRunner returns a different canned output per invocation, so a
// multi-step Preflight can be driven precisely.
type scriptedRunner struct {
	mu      sync.Mutex
	replies []scriptedReply
	calls   int
}

type scriptedReply struct {
	output string
	err    error
}

func (s *scriptedRunner) run(
	_ context.Context, _, _ string, _ ...string,
) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.calls >= len(s.replies) {
		s.calls++
		return nil, errors.New("scriptedRunner: unexpected extra call")
	}
	reply := s.replies[s.calls]
	s.calls++
	return []byte(reply.output), reply.err
}

const okVersion = "nftables v1.0.9 (Old Doc Yak #3)"

func setListing(timeout string) string {
	return "table inet winn_spa {\n\tset spa_allow_v4 {\n\t\ttype ipv4_addr\n" +
		"\t\tflags dynamic,timeout\n\t\ttimeout " + timeout + "\n\t}\n}"
}

func TestPreflightFailsWhenSetMissing(t *testing.T) {
	runner := &scriptedRunner{replies: []scriptedReply{
		{output: okVersion},
		{output: "", err: errors.New("No such file or directory")},
	}}
	enforcer, err := NewNFTEnforcer(NFTConfig{
		SetV4: "spa_allow_v4", runner: runner.run,
	})
	if err != nil {
		t.Fatalf("NewNFTEnforcer: %v", err)
	}
	err = enforcer.Preflight(context.Background(), 30*time.Minute)
	if err == nil {
		t.Fatal("Preflight accepted a missing set")
	}
	if !strings.Contains(err.Error(), "would authorize nothing") {
		t.Fatalf("error does not explain the consequence: %v", err)
	}
}

// An nft too old to parse `destroy element` must be refused at startup. If it
// is not, every Authorize fails while the daemon stays healthy -- systemd sees
// an active unit, ExecStopPost never runs, and the watchdog's is-active check
// is satisfied. Silent total lockout.
func TestPreflightRefusesOldNFT(t *testing.T) {
	for _, version := range []string{
		"nftables v1.0.6 (Lester Gooch #5)",
		"nftables v0.9.8",
		"nftables v1.0.7",
	} {
		runner := &scriptedRunner{replies: []scriptedReply{{output: version}}}
		enforcer, err := NewNFTEnforcer(NFTConfig{
			SetV4: "spa_allow_v4", runner: runner.run,
		})
		if err != nil {
			t.Fatalf("NewNFTEnforcer: %v", err)
		}
		err = enforcer.Preflight(context.Background(), 30*time.Minute)
		if err == nil {
			t.Fatalf("%s was accepted; destroy element needs >= %s",
				version, MinNFTVersion)
		}
		if !strings.Contains(err.Error(), "destroy element") {
			t.Fatalf("%s: error does not name the cause: %v", version, err)
		}
	}
	// And the supported one must pass this check.
	runner := &scriptedRunner{replies: []scriptedReply{
		{output: okVersion},
		{output: setListing("30m")},
	}}
	enforcer, _ := NewNFTEnforcer(NFTConfig{
		SetV4: "spa_allow_v4", runner: runner.run,
	})
	if err := enforcer.Preflight(context.Background(), 30*time.Minute); err != nil {
		t.Fatalf("nftables 1.0.9 with a matching timeout was refused: %v", err)
	}
}

// A set with no timeout would keep every granted address forever. That is a
// stuck-open port for whoever knocked once. Preflight must refuse it, not
// merely parse it as "timeout not found".
func TestPreflightRefusesSetWithoutTimeout(t *testing.T) {
	listing := "table inet winn_spa {\n\tset spa_allow_v4 {\n\t\ttype ipv4_addr\n" +
		"\t\tflags dynamic\n\t}\n}"
	runner := &scriptedRunner{replies: []scriptedReply{
		{output: okVersion},
		{output: listing},
	}}
	enforcer, err := NewNFTEnforcer(NFTConfig{
		SetV4: "spa_allow_v4", runner: runner.run,
	})
	if err != nil {
		t.Fatalf("NewNFTEnforcer: %v", err)
	}
	err = enforcer.Preflight(context.Background(), 30*time.Minute)
	if err == nil {
		t.Fatal("Preflight accepted a set with no timeout; grants would never expire")
	}
	if !strings.Contains(err.Error(), "would never expire") {
		t.Fatalf("error does not name the stuck-open consequence: %v", err)
	}
}

// N3: the set's timeout is what the kernel re-arms every element to, so a
// -grace that disagrees with it means the window silently collapses to the
// set's value on the first packet while the listing still shows the granted
// one. Preflight must refuse rather than let the two diverge.
func TestPreflightRefusesGraceMismatch(t *testing.T) {
	runner := &scriptedRunner{replies: []scriptedReply{
		{output: okVersion},
		{output: setListing("90s")},
	}}
	enforcer, err := NewNFTEnforcer(NFTConfig{
		SetV4: "spa_allow_v4", runner: runner.run,
	})
	if err != nil {
		t.Fatalf("NewNFTEnforcer: %v", err)
	}
	err = enforcer.Preflight(context.Background(), 30*time.Minute)
	if err == nil {
		t.Fatal("Preflight accepted a grace that disagrees with the set timeout")
	}
	for _, want := range []string{"30m", "1m30s", "MUST be equal"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error missing %q, so an operator cannot act on it: %v",
				want, err)
		}
	}
}

func TestParseSetTimeout(t *testing.T) {
	for _, testCase := range []struct {
		listing string
		want    time.Duration
		found   bool
	}{
		{setListing("30m"), 30 * time.Minute, true},
		{setListing("1m30s"), 90 * time.Second, true},
		{setListing("10s"), 10 * time.Second, true},
		{"table inet t {\n\tset s {\n\t\ttype ipv4_addr\n\t}\n}", 0, false},
	} {
		got, found := parseSetTimeout(testCase.listing)
		if found != testCase.found || got != testCase.want {
			t.Fatalf("parseSetTimeout = (%s, %v), want (%s, %v)",
				got, found, testCase.want, testCase.found)
		}
	}
	// An element timeout inside `elements = { ... }` must NOT be mistaken for
	// the set-level default.
	listing := setListing("30m") + "\n\t\telements = { 1.2.3.4 timeout 5s expires 4s }"
	got, found := parseSetTimeout(listing)
	if !found || got != 30*time.Minute {
		t.Fatalf("element timeout leaked into the set default: got %s", got)
	}
}

// --- Daemon -----------------------------------------------------------------

type captureEnforcer struct {
	mu      sync.Mutex
	granted []netip.Addr
	err     error
}

func (c *captureEnforcer) Authorize(
	_ context.Context, ip netip.Addr, _ time.Duration,
) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.granted = append(c.granted, ip)
	return nil
}

func (c *captureEnforcer) DescribeForLog() string { return "capture" }

func (c *captureEnforcer) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.granted)
}

// serveDaemon starts a daemon on a real loopback UDP socket and returns the
// address to send knocks to.
func serveDaemon(
	t *testing.T, keys [][]byte, enforcer Enforcer,
) (*Daemon, string) {
	t.Helper()
	counters := new(Counters)
	gate, err := NewGateFor(keys, testPacketSize, knock.Options{},
		DefaultGrace, DefaultLimits(), counters)
	if err != nil {
		t.Fatalf("NewGateFor: %v", err)
	}
	daemon, err := New(Config{
		Gate: gate, Enforcer: enforcer, PacketSize: testPacketSize,
		Counters: counters,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = daemon.Serve(ctx, conn) }()
	t.Cleanup(func() { cancel(); conn.Close(); <-done })
	return daemon, conn.LocalAddr().String()
}

// waitFor polls until condition holds, so these tests never depend on a sleep
// long enough to be flaky or short enough to be wrong.
func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestDaemonAuthorizesValidKnock(t *testing.T) {
	key := testKey(t)
	enforcer := &captureEnforcer{}
	daemon, addr := serveDaemon(t, [][]byte{key}, enforcer)

	packet, err := knock.Build(key, testPacketSize, time.Now(), knock.Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(packet); err != nil {
		t.Fatalf("Write: %v", err)
	}

	waitFor(t, "a grant", func() bool { return enforcer.count() == 1 })
	if got := daemon.Counters.Accepted.Load(); got != 1 {
		t.Fatalf("Accepted = %d, want 1", got)
	}
	if got := enforcer.granted[0]; !got.IsLoopback() {
		t.Fatalf("granted %s, want the loopback source", got)
	}
}

// The whole design rests on the server answering nothing, ever. A daemon that
// replied - even with an error - would let a prober distinguish a live SPA port
// from a filtered one.
func TestDaemonNeverAnswers(t *testing.T) {
	key := testKey(t)
	_, addr := serveDaemon(t, [][]byte{key}, &captureEnforcer{})

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	valid, _ := knock.Build(key, testPacketSize, time.Now(), knock.Options{})
	for _, payload := range [][]byte{
		valid,                          // a real knock
		make([]byte, testPacketSize),   // right size, wrong tag
		[]byte("hello"),                // garbage
		make([]byte, testPacketSize+1), // oversized
	} {
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)
	if err == nil {
		t.Fatalf("daemon answered with %d bytes; it must never write", n)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("got %v, want a read timeout (silence)", err)
	}
}

func TestDaemonRejectsWrongKeyWrongSizeAndReplay(t *testing.T) {
	key := testKey(t)
	other := make([]byte, 32)
	for i := range other {
		other[i] = 0xAA
	}
	enforcer := &captureEnforcer{}
	daemon, addr := serveDaemon(t, [][]byte{key}, enforcer)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	// Wrong key.
	wrongKey, _ := knock.Build(other, testPacketSize, time.Now(), knock.Options{})
	if _, err := conn.Write(wrongKey); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Wrong size, built with the RIGHT key - proves the length check is what
	// rejects it, not the crypto.
	wrongSize, _ := knock.Build(key, testPacketSize/2, time.Now(), knock.Options{})
	if _, err := conn.Write(wrongSize); err != nil {
		t.Fatalf("Write: %v", err)
	}

	waitFor(t, "both rejections", func() bool {
		return daemon.Counters.Received.Load() == 2
	})
	if enforcer.count() != 0 {
		t.Fatalf("granted %d times, want 0", enforcer.count())
	}
	if got := daemon.Counters.RejectedUnauthenticated.Load(); got != 1 {
		t.Fatalf("RejectedUnauthenticated = %d, want 1", got)
	}
	if got := daemon.Counters.RejectedLength.Load(); got != 1 {
		t.Fatalf("RejectedLength = %d, want 1", got)
	}

	// Replay: the exact same datagram twice. The first authorizes, the second
	// must be refused by the replay cache, or a captured knock would be a
	// reusable credential.
	valid, _ := knock.Build(key, testPacketSize, time.Now(), knock.Options{})
	if _, err := conn.Write(valid); err != nil {
		t.Fatalf("Write: %v", err)
	}
	waitFor(t, "the first grant", func() bool { return enforcer.count() == 1 })
	if _, err := conn.Write(valid); err != nil {
		t.Fatalf("Write: %v", err)
	}
	waitFor(t, "the replay rejection", func() bool {
		return daemon.Counters.RejectedReplay.Load() == 1
	})
	if enforcer.count() != 1 {
		t.Fatalf("a replayed knock produced a second grant (%d)", enforcer.count())
	}
}

// A client that re-knocks (knockdial does, before every dial) must be able to
// renew. Only a REPLAYED datagram is refused, never a fresh one.
func TestDaemonAllowsFreshReKnock(t *testing.T) {
	key := testKey(t)
	enforcer := &captureEnforcer{}
	_, addr := serveDaemon(t, [][]byte{key}, enforcer)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	for i := 0; i < 3; i++ {
		packet, buildErr := knock.Build(
			key, testPacketSize, time.Now(), knock.Options{},
		)
		if buildErr != nil {
			t.Fatalf("Build: %v", buildErr)
		}
		if _, err := conn.Write(packet); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	waitFor(t, "three grants", func() bool { return enforcer.count() == 3 })
}

// A rotation overlap must work: a client still holding the previous key gets
// in until the operator retires it.
func TestDaemonAcceptsAnyConfiguredKeyForRotation(t *testing.T) {
	current := testKey(t)
	previous := make([]byte, 32)
	for i := range previous {
		previous[i] = 0x5A
	}
	enforcer := &captureEnforcer{}
	_, addr := serveDaemon(t, [][]byte{current, previous}, enforcer)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	packet, _ := knock.Build(previous, testPacketSize, time.Now(), knock.Options{})
	if _, err := conn.Write(packet); err != nil {
		t.Fatalf("Write: %v", err)
	}
	waitFor(t, "the previous key to be accepted", func() bool {
		return enforcer.count() == 1
	})
}

// A firewall failure must be counted and logged, never swallowed: it is the
// difference between "SPA is working" and "every user with a valid key is
// locked out".
func TestDaemonCountsEnforcementFailure(t *testing.T) {
	key := testKey(t)
	enforcer := &captureEnforcer{err: errors.New("nft exploded")}
	var logged []string
	var logMu sync.Mutex

	counters := new(Counters)
	gate, err := NewGateFor(
		[][]byte{key}, testPacketSize, knock.Options{}, DefaultGrace,
		DefaultLimits(), counters,
	)
	if err != nil {
		t.Fatalf("NewGateFor: %v", err)
	}
	daemon, err := New(Config{
		Gate: gate, Enforcer: enforcer, PacketSize: testPacketSize,
		Counters: counters,
		Log: func(format string, args ...any) {
			logMu.Lock()
			defer logMu.Unlock()
			logged = append(logged, format)
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = daemon.Serve(ctx, conn) }()
	defer func() { cancel(); conn.Close(); <-done }()

	client, err := net.Dial("udp", conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	packet, _ := knock.Build(key, testPacketSize, time.Now(), knock.Options{})
	if _, err := client.Write(packet); err != nil {
		t.Fatalf("Write: %v", err)
	}

	waitFor(t, "the enforcement failure", func() bool {
		return daemon.Counters.EnforceFailed.Load() == 1
	})
	logMu.Lock()
	defer logMu.Unlock()
	joined := strings.Join(logged, "\n")
	if !strings.Contains(joined, "FAILED") {
		t.Fatalf("enforcement failure was not logged loudly: %q", joined)
	}
}

// A daemon whose every Authorize fails is HEALTHY by every measure the safety
// mechanisms use (systemd Restart, ExecStopPost, the watchdog's is-active
// check) while admitting nobody. It must exit so the supervisor tears the gate
// down and the node fails open.
func TestDaemonExitsWhenEnforcementIsConsistentlyBroken(t *testing.T) {
	key := testKey(t)
	enforcer := &captureEnforcer{err: errors.New("nft too old to parse this")}
	counters := new(Counters)
	gate, err := NewGateFor(
		[][]byte{key}, testPacketSize, knock.Options{}, DefaultGrace,
		DefaultLimits(), counters,
	)
	if err != nil {
		t.Fatalf("NewGateFor: %v", err)
	}
	daemon, err := New(Config{
		Gate: gate, Enforcer: enforcer, PacketSize: testPacketSize,
		Counters: counters,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	served := make(chan error, 1)
	go func() { served <- daemon.Serve(context.Background(), conn) }()

	client, err := net.Dial("udp", conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	for i := 0; i < MaxConsecutiveEnforceFailures; i++ {
		packet, _ := knock.Build(key, testPacketSize, time.Now(), knock.Options{})
		if _, err := client.Write(packet); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	select {
	case err := <-served:
		if !errors.Is(err, ErrEnforcementBroken) {
			t.Fatalf("Serve returned %v, want ErrEnforcementBroken", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not exit after every authorization failed; a healthy " +
			"daemon that authorizes nobody is invisible to every watchdog")
	}
}

// One transient failure among working traffic must NOT take the gate down.
func TestDaemonToleratesAnIsolatedEnforcementFailure(t *testing.T) {
	key := testKey(t)
	flaky := &flakyEnforcer{failFirst: 1}
	counters := new(Counters)
	gate, err := NewGateFor(
		[][]byte{key}, testPacketSize, knock.Options{}, DefaultGrace,
		DefaultLimits(), counters,
	)
	if err != nil {
		t.Fatalf("NewGateFor: %v", err)
	}
	daemon, err := New(Config{
		Gate: gate, Enforcer: flaky, PacketSize: testPacketSize,
		Counters: counters,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- daemon.Serve(ctx, conn) }()
	defer func() { cancel(); conn.Close(); <-served }()

	client, err := net.Dial("udp", conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	for i := 0; i < 5; i++ {
		packet, _ := knock.Build(key, testPacketSize, time.Now(), knock.Options{})
		if _, err := client.Write(packet); err != nil {
			t.Fatalf("Write: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	waitFor(t, "four successful grants", func() bool {
		return daemon.Counters.Accepted.Load() == 5 &&
			daemon.Counters.EnforceFailed.Load() == 1
	})
	select {
	case err := <-served:
		t.Fatalf("Serve exited on a single transient failure: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
}

type flakyEnforcer struct {
	mu        sync.Mutex
	calls     int
	failFirst int
}

func (f *flakyEnforcer) Authorize(
	_ context.Context, _ netip.Addr, _ time.Duration,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls <= f.failFirst {
		return errors.New("transient")
	}
	return nil
}

func (f *flakyEnforcer) DescribeForLog() string { return "flaky" }

func TestDaemonRequiresGateAndEnforcer(t *testing.T) {
	if _, err := New(Config{PacketSize: testPacketSize}); err == nil {
		t.Fatal("accepted a config with no gate")
	}
	gate, err := NewGateFor(
		[][]byte{testKey(t)}, testPacketSize, knock.Options{}, DefaultGrace,
		DefaultLimits(), nil,
	)
	if err != nil {
		t.Fatalf("NewGateFor: %v", err)
	}
	if _, err := New(Config{Gate: gate, PacketSize: testPacketSize}); err == nil {
		t.Fatal("accepted a config with no enforcer")
	}
	if _, err := New(Config{
		Gate: gate, Enforcer: &captureEnforcer{}, PacketSize: 1,
	}); err == nil {
		t.Fatal("accepted a packet size below the knock header")
	}
}

func TestDryRunEnforcerChangesNothing(t *testing.T) {
	var seen []netip.Addr
	enforcer := &DryRunEnforcer{
		OnAuthorize: func(ip netip.Addr, _ time.Duration) {
			seen = append(seen, ip)
		},
	}
	if !strings.Contains(enforcer.DescribeForLog(), "DRY RUN") {
		t.Fatalf("dry run does not announce itself: %q", enforcer.DescribeForLog())
	}
	err := enforcer.Authorize(
		context.Background(), netip.MustParseAddr("203.0.113.1"), time.Minute,
	)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if len(seen) != 1 {
		t.Fatalf("callback fired %d times, want 1", len(seen))
	}
}

// --- Rate-limiter exhaustion lockout -------------------------------------
//
// See MaxConsecutiveRateLimited. These pin the hole that
// MaxConsecutiveEnforceFailures cannot see: a limiter full of forged sources
// means Consider returns false BEFORE verification, so Authorize is never
// called, no enforcement failure is ever recorded, and the daemon stays
// healthy while admitting nobody.

// testClock is a manually advanced clock, so these tests assert the
// five-minute window rule without sleeping for five minutes. It drives only
// the Daemon's lockout detector; the Gate and the limiter keep real time.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// lockoutDaemon builds a daemon whose limiter tracks exactly ONE source, so
// every other source is refused before verification. That is the same
// condition a flood of forged addresses produces against the real 1<<18
// bound, reached without sending 262,144 packets.
func lockoutDaemon(t *testing.T, clock *testClock) (*Daemon, []byte) {
	t.Helper()
	key := testKey(t)
	counters := new(Counters)
	gate, err := NewGateFor(
		[][]byte{key}, testPacketSize, knock.Options{}, DefaultGrace,
		Limits{
			// Burst and refill are generous so the ONE tracked source can
			// knock repeatedly; MaxSources is what does the work here.
			RateBurst: 50, RatePerMinute: 6000, MaxSources: 1,
			MaxAuthorized: 1 << 10, MaxReplayNonces: 1 << 10,
		},
		counters,
	)
	if err != nil {
		t.Fatalf("NewGateFor: %v", err)
	}
	daemon, err := New(Config{
		Gate: gate, Enforcer: &captureEnforcer{}, PacketSize: testPacketSize,
		Counters: counters, Now: clock.Now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return daemon, key
}

// floodSource returns a distinct, routable-looking source address per index.
func floodSource(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
}

// A limiter that has been refusing every source for longer than the window,
// with nothing accepted, must take the daemon down so ExecStopPost reverts the
// gate and the node fails OPEN.
func TestDaemonExitsWhenRateLimiterLocksEveryoneOut(t *testing.T) {
	clock := &testClock{now: time.Now()}
	daemon, _ := lockoutDaemon(t, clock)
	ctx := context.Background()
	// Correctly sized so the length check passes and the limiter is reached;
	// the contents never matter, because rejection happens before crypto.
	packet := make([]byte, testPacketSize)

	// The first source claims the single limiter slot. Every source after it
	// is refused, which is the lockout.
	if err := daemon.handle(ctx, packet, floodSource(1)); err != nil {
		t.Fatalf("first packet returned %v, want nil", err)
	}
	// One rate-limited packet starts the streak; then push past the window.
	if err := daemon.handle(ctx, packet, floodSource(2)); err != nil {
		t.Fatalf("second packet returned %v, want nil", err)
	}
	if got := daemon.Counters.RejectedRateLimited.Load(); got != 1 {
		t.Fatalf("RejectedRateLimited = %d after the second source, want 1", got)
	}
	clock.advance(RateLimitedLockoutWindow + time.Second)

	var got error
	for i := 3; i < MaxConsecutiveRateLimited+100; i++ {
		if err := daemon.handle(ctx, packet, floodSource(i)); err != nil {
			got = err
			break
		}
	}
	if !errors.Is(got, ErrRateLimiterExhausted) {
		t.Fatalf("Serve path returned %v, want ErrRateLimiterExhausted; a full "+
			"limiter is a silent lockout that no watchdog can see", got)
	}
	if daemon.Counters.Accepted.Load() != 0 {
		t.Fatal("nothing should have been accepted in this test")
	}
	if daemon.Counters.EnforceFailed.Load() != 0 {
		t.Fatal("Authorize was never reached, which is exactly why " +
			"MaxConsecutiveEnforceFailures cannot catch this")
	}
}

// Rate limiting is NORMAL under load. A burst well past the count threshold
// that has not lasted the window must NOT take the gate down, or any source
// able to spend its own bucket could kill the daemon remotely.
func TestDaemonToleratesRateLimitingThatIsMerelyBusy(t *testing.T) {
	clock := &testClock{now: time.Now()}
	daemon, _ := lockoutDaemon(t, clock)
	ctx := context.Background()
	packet := make([]byte, testPacketSize)

	for i := 1; i < MaxConsecutiveRateLimited*2; i++ {
		if err := daemon.handle(ctx, packet, floodSource(i)); err != nil {
			t.Fatalf("packet %d returned %v; a busy moment is not a lockout", i, err)
		}
		// Well short of the window, however many packets arrive.
		clock.advance(time.Millisecond)
	}
	if got := daemon.Counters.RejectedRateLimited.Load(); got < MaxConsecutiveRateLimited {
		t.Fatalf("RejectedRateLimited = %d, want at least %d; the test did not "+
			"actually exercise the count threshold", got, MaxConsecutiveRateLimited)
	}
}

// One accepted knock proves the limiter still admits new sources, so it must
// reset the streak even when the window has long since elapsed.
func TestAcceptedKnockResetsTheRateLimitLockoutStreak(t *testing.T) {
	clock := &testClock{now: time.Now()}
	daemon, key := lockoutDaemon(t, clock)
	ctx := context.Background()
	packet := make([]byte, testPacketSize)

	// The legitimate client claims the single limiter slot first.
	good, err := knock.Build(key, testPacketSize, time.Now(), knock.Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := daemon.handle(ctx, good, floodSource(1)); err != nil {
		t.Fatalf("valid knock returned %v", err)
	}
	if daemon.Counters.Accepted.Load() != 1 {
		t.Fatal("the seeding knock was not accepted")
	}
	clock.advance(RateLimitedLockoutWindow + time.Second)

	// Flood past the count threshold from other sources.
	for i := 2; i < MaxConsecutiveRateLimited+10; i++ {
		if err := daemon.handle(ctx, packet, floodSource(i)); err != nil {
			// Reaching the threshold is expected; what matters is that a
			// successful knock afterwards clears it.
			break
		}
	}

	// A fresh knock from the source that still holds a bucket must reset.
	good2, err := knock.Build(key, testPacketSize, time.Now(), knock.Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := daemon.handle(ctx, good2, floodSource(1)); err != nil {
		t.Fatalf("second valid knock returned %v", err)
	}
	if got := daemon.consecutiveRateLimited.Load(); got != 0 {
		t.Fatalf("streak = %d after an accepted knock, want 0", got)
	}
	if got := daemon.rateLimitedSince.Load(); got != 0 {
		t.Fatalf("streak origin = %d after an accepted knock, want 0", got)
	}
	// And the daemon must now tolerate a fresh burst rather than exiting on
	// the very next packet because the old streak was still counted.
	if err := daemon.handle(ctx, packet, floodSource(99999)); err != nil {
		t.Fatalf("packet after a reset returned %v, want nil", err)
	}
}

// A verified knock that cannot be recorded in knock.Gate's userspace
// authorization map (ReasonCapacity) must still reach the kernel enforcer.
// The package doc says the daemon does not consult that map — the kernel
// set is the authority. Dropping the grant here is a silent lockout of a
// client holding a valid key: Consider returns false, Authorize is never
// called, EnforceFailed stays 0, and every watchdog sees a healthy daemon.
func TestDaemonGrantsAtKernelWhenUserspaceAuthMapIsFull(t *testing.T) {
	key := testKey(t)
	enforcer := &captureEnforcer{}
	counters := new(Counters)
	gate, err := NewGateFor(
		[][]byte{key}, testPacketSize, knock.Options{}, DefaultGrace,
		Limits{
			RateBurst: 50, RatePerMinute: 6000, MaxSources: 1 << 10,
			MaxAuthorized: 1, MaxReplayNonces: 1 << 10,
		},
		counters,
	)
	if err != nil {
		t.Fatalf("NewGateFor: %v", err)
	}
	daemon, err := New(Config{
		Gate: gate, Enforcer: enforcer, PacketSize: testPacketSize,
		Counters: counters,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	first, err := knock.Build(key, testPacketSize, time.Now(), knock.Options{})
	if err != nil {
		t.Fatalf("Build first: %v", err)
	}
	second, err := knock.Build(key, testPacketSize, time.Now().Add(time.Second), knock.Options{})
	if err != nil {
		t.Fatalf("Build second: %v", err)
	}
	if err := daemon.handle(ctx, first, floodSource(1)); err != nil {
		t.Fatalf("first knock: %v", err)
	}
	if enforcer.count() != 1 {
		t.Fatalf("after first knock, grants = %d, want 1", enforcer.count())
	}
	if got := daemon.Counters.Accepted.Load(); got != 1 {
		t.Fatalf("after first knock, Accepted = %d, want 1", got)
	}
	if err := daemon.handle(ctx, second, floodSource(2)); err != nil {
		t.Fatalf("second knock: %v", err)
	}
	if enforcer.count() != 2 {
		t.Fatalf("userspace map full dropped a verified knock before Authorize: grants=%d want 2; Accepted=%d EnforceFailed=%d RejectedCapacity=%d",
			enforcer.count(),
			daemon.Counters.Accepted.Load(),
			daemon.Counters.EnforceFailed.Load(),
			daemon.Counters.RejectedCapacity.Load())
	}
	if got := daemon.Counters.RejectedCapacity.Load(); got != 1 {
		t.Fatalf("RejectedCapacity = %d, want 1 (the ceiling must be visible)", got)
	}
	if got := daemon.Counters.Accepted.Load(); got != 2 {
		t.Fatalf("Accepted = %d, want 2 (both knocks were verified)", got)
	}
	if got := daemon.Counters.EnforceFailed.Load(); got != 0 {
		t.Fatalf("EnforceFailed = %d, want 0", got)
	}
	snap := daemon.Counters.Snapshot()
	if snap.RejectedCapacity != 1 || snap.Accepted != 2 {
		t.Fatalf("Snapshot dropped the new fields: %+v", snap)
	}
	if !strings.Contains(snap.String(), "rejected_capacity=1") {
		t.Fatalf("Snapshot.String hid RejectedCapacity: %q", snap.String())
	}
}

func TestCountRejectionReasons(t *testing.T) {
	counters := new(Counters)
	countRejection(nil, knock.ReasonLength) // must not panic
	countRejection(counters, knock.ReasonLength)
	countRejection(counters, knock.ReasonRateLimited)
	countRejection(counters, knock.ReasonUnauthenticated)
	countRejection(counters, knock.ReasonReplay)
	countRejection(counters, knock.ReasonCapacity)
	countRejection(counters, knock.ReasonTCPUnauthorized)
	countRejection(counters, "not-a-real-reason")
	snap := counters.Snapshot()
	if snap.RejectedLength != 1 ||
		snap.RejectedRateLimited != 1 ||
		snap.RejectedUnauthenticated != 1 ||
		snap.RejectedReplay != 1 ||
		snap.RejectedCapacity != 1 {
		t.Fatalf("named reasons not counted: %+v", snap)
	}
	if snap.RejectedUnclassified != 2 {
		t.Fatalf("RejectedUnclassified = %d, want 2 (tcp_unauthorized + unknown)",
			snap.RejectedUnclassified)
	}
}
