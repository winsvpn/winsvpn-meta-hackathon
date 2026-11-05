//go:build linux

package main

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Round CM3 Turn 6 (GPT-6 Sol OI-CM3-1) on a real kernel: is a rule dump
// taken while the rule set changes ever read as complete when it is not?

// dumpAttempt is one rule-then-route dump on a fresh socket, no retries.
func dumpAttempt(open func() (nlTransport, error)) ([]routingSelector, error) {
	tr, err := open()
	if err != nil {
		return nil, err
	}
	defer tr.close()
	var out []routingSelector
	for i, typ := range []uint16{rtmGetRule, rtmGetRoute} {
		sel, err := nlDump(tr, typ, uint32(i+1))
		if err != nil {
			return nil, err
		}
		out = append(out, sel...)
	}
	return out, nil
}

type dumpTally struct {
	withMark, withoutMark, intr, changed, other int
	otherErr                                    string
	kind                                        string // the stable selector kind counted
}

// stableMarkRules is how many fwmark rules never change during the churn.
const stableMarkRules = 200

func countMarkRules(sel []routingSelector) int { return countKind(sel, "fwmark rule") }

// countKind counts distinct selectors of kind (a dump that lists one twice is
// over-reporting, not incomplete).
func countKind(sel []routingSelector, kind string) int {
	seen := map[string]bool{}
	for _, s := range sel {
		if s.Kind == kind {
			seen[fmt.Sprintf("%+v", s)] = true
		}
	}
	return len(seen)
}

func (d *dumpTally) add(sel []routingSelector, err error) {
	switch {
	case err == nil && countKind(sel, d.kind) == stableMarkRules:
		d.withMark++
	case err == nil:
		d.withoutMark++
	case strings.Contains(err.Error(), "NLM_F_DUMP_INTR"):
		d.intr++
	case strings.Contains(err.Error(), "routing state changed"):
		d.changed++
	default:
		d.other++
		d.otherErr = err.Error()
	}
}

func (d dumpTally) String() string {
	return fmt.Sprintf("complete with all 200 stable selectors %d, COMPLETE WITH FEWER %d, NLM_F_DUMP_INTR %d, change notification %d, other %d %s",
		d.withMark, d.withoutMark, d.intr, d.changed, d.other, d.otherErr)
}

// 200 fwmark rules that never change are interleaved with 200 filler rules
// (preferences 1000, 1002, ... and 1001, 1003, ...), so the rule dump is
// multi-part and every position boundary has a stable rule next to it.
// Another process deletes and re-adds 100 of the filler rules in a loop. A
// dump that reports fewer than 200 fwmark rules without an error is the
// defect class Sol named (an incomplete dump read as complete).
func TestEgressNetnsDumpUnderRuleChurn(t *testing.T) {
	requireEgressNetns(t)
	const ns = "l80churn"
	policyNetns(t, ns)
	var fill, del, add strings.Builder
	for i := range stableMarkRules {
		fmt.Fprintf(&fill, "rule add pref %d fwmark %d lookup 100\n", 1000+2*i, i+1)
		fmt.Fprintf(&fill, "rule add pref %d from 10.200.%d.%d lookup 100\n", 1001+2*i, i/250, i%250)
	}
	for i := range 100 {
		fmt.Fprintf(&del, "rule del pref %d\n", 1001+2*i)
		fmt.Fprintf(&add, "rule add pref %d from 10.200.%d.%d lookup 100\n", 1001+2*i, i/250, i%250)
	}
	batch := func(script string) error {
		cmd := exec.Command("ip", "-n", ns, "-batch", "-")
		cmd.Stdin = strings.NewReader(script)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}
		return nil
	}
	if err := batch(fill.String()); err != nil {
		t.Fatal(err)
	}

	// Quiet: both socket kinds read it whole.
	inNetns(t, ns, func() {
		for _, open := range []func() (nlTransport, error){openRouteTransport, openDumpTransport} {
			sel, err := dumpAttempt(open)
			if err != nil || countMarkRules(sel) != stableMarkRules {
				t.Errorf("quiet dump: %d fwmark rules, err %v", countMarkRules(sel), err)
			}
		}
	})

	var stop atomic.Bool
	churnErr := make(chan error, 1)
	rounds := 0
	go func() {
		for !stop.Load() {
			if err := batch(del.String()); err != nil {
				churnErr <- err
				return
			}
			if err := batch(add.String()); err != nil {
				churnErr <- err
				return
			}
			rounds++
		}
		churnErr <- nil
	}()
	plain, grouped := dumpTally{kind: "fwmark rule"}, dumpTally{kind: "fwmark rule"}
	var retried atomic.Int64
	inNetns(t, ns, func() {
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			plain.add(dumpAttempt(openRouteTransport))
			grouped.add(dumpAttempt(openDumpTransport))
			// The production path, with its retries.
			sel, err := listRoutingSelectors()
			if err == nil && countMarkRules(sel) != stableMarkRules {
				t.Errorf("listRoutingSelectors returned a complete dump with %d of %d fwmark rules", countMarkRules(sel), stableMarkRules)
			}
			if err != nil {
				retried.Add(1)
			}
		}
	})
	stop.Store(true)
	if err := <-churnErr; err != nil {
		t.Fatal(err)
	}
	t.Logf("churn rounds (100 deletes + 100 adds each): %d", rounds)
	t.Logf("fresh socket, answer checks only:        %s", plain)
	t.Logf("fresh socket joined to rule/route groups: %s", grouped)
	t.Logf("listRoutingSelectors failed closed after its retries: %d times", retried.Load())
	if grouped.withoutMark != 0 {
		t.Fatalf("a dump socket joined to the change groups read an incomplete rule set as complete %d times", grouped.withoutMark)
	}
	if grouped.withMark == 0 {
		t.Fatal("no dump completed under churn: the measurement says nothing")
	}
	// The change notifications themselves are what discards those attempts
	// (recv names them), not a later check that happens to catch them too.
	if grouped.changed == 0 {
		t.Fatalf("no attempt was discarded for a change notification under churn: %s", grouped)
	}
	if rounds == 0 {
		t.Fatal("no churn happened")
	}
}

// The 250 ms bound against real dump sizes: how long listRoutingSelectors
// takes with n routes, and at what size it stops fitting (a host carrying a
// full routing table would then refuse, fail closed).
func TestEgressNetnsDumpTime(t *testing.T) {
	requireEgressNetns(t)
	const ns = "l80dumpt"
	policyNetns(t, ns)
	have := 0
	for _, n := range []int{0, 1000, 10000, 100000, 300000} {
		if n > have {
			var s strings.Builder
			for i := have; i < n; i++ {
				fmt.Fprintf(&s, "route add %d.%d.%d.0/24 dev ts2 table 200\n", 11+i/65536, (i/256)%256, i%256)
			}
			cmd := exec.Command("ip", "-n", ns, "-batch", "-")
			cmd.Stdin = strings.NewReader(s.String())
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("adding routes to %d: %v %s", n, err, out)
			}
			have = n
		}
		var best, worst time.Duration
		var lastErr error
		inNetns(t, ns, func() {
			for i := range 5 {
				start := time.Now()
				_, err := listRoutingSelectors()
				el := time.Since(start)
				if i == 0 || el < best {
					best = el
				}
				if el > worst {
					worst = el
				}
				lastErr = err
			}
		})
		t.Logf("%6d routes in table 200: listRoutingSelectors best %v worst %v (5 runs), last result err=%v",
			n, best, worst, lastErr)
		if n <= 10000 && lastErr != nil {
			t.Fatalf("%d routes: %v", n, lastErr)
		}
		if lastErr != nil && !errors.Is(lastErr, errNetlinkIncomplete) {
			t.Fatalf("%d routes: a failure that is not incomplete: %v", n, lastErr)
		}
	}
}

// The same for the route dump: 200 routes keyed on tos never change and are
// interleaved with 200 plain routes, 100 of which another process deletes and
// re-adds. A tos route missing from a dump read as complete would let a
// sweep clear egress_routing_unaccountable.
func TestEgressNetnsDumpUnderRouteChurn(t *testing.T) {
	requireEgressNetns(t)
	const ns = "l80rchurn"
	policyNetns(t, ns)
	var fill, del, add strings.Builder
	for i := range stableMarkRules {
		fmt.Fprintf(&fill, "route add 45.%d.%d.0/24 tos 0x10 dev ts1 table 100\n", i/128, (2*i)%256)
		fmt.Fprintf(&fill, "route add 45.%d.%d.0/24 dev ts1 table 100\n", i/128, (2*i+1)%256)
	}
	for i := range 100 {
		fmt.Fprintf(&del, "route del 45.%d.%d.0/24 dev ts1 table 100\n", i/128, (2*i+1)%256)
		fmt.Fprintf(&add, "route add 45.%d.%d.0/24 dev ts1 table 100\n", i/128, (2*i+1)%256)
	}
	batch := func(script string) error {
		cmd := exec.Command("ip", "-n", ns, "-batch", "-")
		cmd.Stdin = strings.NewReader(script)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}
		return nil
	}
	if err := batch(fill.String()); err != nil {
		t.Fatal(err)
	}
	inNetns(t, ns, func() {
		sel, err := dumpAttempt(openDumpTransport)
		if err != nil || countKind(sel, "tos route") != stableMarkRules {
			t.Errorf("quiet dump: %d tos routes, err %v", countKind(sel, "tos route"), err)
		}
	})
	var stop atomic.Bool
	churnErr := make(chan error, 1)
	rounds := 0
	go func() {
		for !stop.Load() {
			if err := batch(del.String()); err != nil {
				churnErr <- err
				return
			}
			if err := batch(add.String()); err != nil {
				churnErr <- err
				return
			}
			rounds++
		}
		churnErr <- nil
	}()
	plain, grouped := dumpTally{kind: "tos route"}, dumpTally{kind: "tos route"}
	inNetns(t, ns, func() {
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			plain.add(dumpAttempt(openRouteTransport))
			grouped.add(dumpAttempt(openDumpTransport))
			sel, err := listRoutingSelectors()
			if err == nil && countKind(sel, "tos route") != stableMarkRules {
				t.Errorf("listRoutingSelectors returned a complete dump with %d of %d tos routes", countKind(sel, "tos route"), stableMarkRules)
			}
		}
	})
	stop.Store(true)
	if err := <-churnErr; err != nil {
		t.Fatal(err)
	}
	t.Logf("route churn rounds (100 deletes + 100 adds each): %d", rounds)
	t.Logf("fresh socket, answer checks only:        %s", plain)
	t.Logf("fresh socket joined to rule/route groups: %s", grouped)
	if grouped.withoutMark != 0 {
		t.Fatalf("a dump socket joined to the change groups read an incomplete route set as complete %d times", grouped.withoutMark)
	}
	if grouped.withMark == 0 || rounds == 0 {
		t.Fatalf("no complete dump (%d) or no churn (%d): the measurement says nothing", grouped.withMark, rounds)
	}
}
