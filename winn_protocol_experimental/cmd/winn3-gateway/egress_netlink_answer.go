package main

import (
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"
)

// Complete answers only (Round CM3 Turn 5, GPT-6 Sol OI-CM3-1: "parseSelectorDump
// treats NLMSG_DONE with NLM_F_DUMP_INTR as a successful, potentially empty
// selector dump"; lane L80). This file is the request/answer layer every
// egress question goes through: the startup probes, the per-client lookup,
// the device MTU and the rule and route dumps. It is portable, over the
// nlTransport interface, so its failure handling is tested on every platform
// with synthetic datagrams; egress_mtu_linux.go supplies the socket.
//
// An answer that is not known to be complete is errNetlinkIncomplete. The
// question is asked again on a fresh socket, netlinkAttempts times in all,
// and every discarded answer is counted (egress_netlink_incomplete). After
// the last attempt the error stands and each caller fails CLOSED:
//
//   - startup refuses (checkEgressMTU, checkRoutingAccountable);
//   - the per-client guard refuses a new client and the sweep closes an
//     established one (lookupSaysNoRoute is false);
//   - the sweep treats routing as unaccountable: every session closed, every
//     new client refused, until a complete dump shows no selector.
//
// A complete answer that says "no route" (ENETUNREACH, EHOSTUNREACH, EACCES
// for prohibit) is not incomplete; see clientEgressGuard.check.

// errNetlinkIncomplete is an answer that is truncated, interrupted,
// overrun, foreign, malformed, late or otherwise not known to be whole.
var errNetlinkIncomplete = errors.New("incomplete rtnetlink answer")

func incompleteAnswer(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errNetlinkIncomplete, fmt.Sprintf(format, a...))
}

// netlinkAttempts is how many times one question is asked before an
// incomplete answer fails closed.
const netlinkAttempts = 3

// netlinkAnswerBound bounds one whole answer: a route or link reply, or a
// dump from its request through NLMSG_DONE. A variable only so a test can
// shorten it.
var netlinkAnswerBound = 250 * time.Millisecond

// netlinkIncompleteAnswers counts every discarded answer, retried or not
// (posture egress_netlink_incomplete).
var netlinkIncompleteAnswers atomic.Uint64

// nlTransport is one rtnetlink request socket. recv returns one datagram the
// KERNEL sent to this socket before deadline; a truncated datagram, one from
// another sender, and no datagram by the deadline are errNetlinkIncomplete.
type nlTransport interface {
	port() uint32
	send(req []byte) error
	recv(deadline time.Time) ([]byte, error)
	close()
}

// withNetlinkRetries runs op until it returns something other than an
// incomplete answer, at most netlinkAttempts times.
func withNetlinkRetries[T any](op func() (T, error)) (T, error) {
	var v T
	var err error
	for attempt := 1; attempt <= netlinkAttempts; attempt++ {
		v, err = op()
		if !errors.Is(err, errNetlinkIncomplete) {
			return v, err
		}
		netlinkIncompleteAnswers.Add(1)
	}
	return v, fmt.Errorf("%w (%d attempts)", err, netlinkAttempts)
}

func nlSend(t nlTransport, req []byte) error {
	if err := t.send(req); err != nil {
		return incompleteAnswer("send: %v", err)
	}
	return nil
}

// nlRouteGet asks one RTM_GETROUTE question and reads its one answer.
func nlRouteGet(t nlTransport, seq uint32, dst netip.AddrPort, lookup egressLookup) (routeReply, error) {
	req, err := encodeRouteGetRequest(seq, dst, lookup)
	if err != nil {
		return routeReply{}, err
	}
	if err := nlSend(t, req); err != nil {
		return routeReply{}, err
	}
	b, err := t.recv(time.Now().Add(netlinkAnswerBound))
	if err != nil {
		return routeReply{}, err
	}
	return parseRouteReply(b, seq, t.port())
}

// nlLinkGet asks for one device's name and MTU by index.
func nlLinkGet(t nlTransport, seq uint32, index int) (string, int, error) {
	if err := nlSend(t, encodeLinkGetRequest(seq, index)); err != nil {
		return "", 0, err
	}
	b, err := t.recv(time.Now().Add(netlinkAnswerBound))
	if err != nil {
		return "", 0, err
	}
	return parseLinkReply(b, seq, t.port(), index)
}

// nlDump runs one IPv4 dump (rtmGetRule or rtmGetRoute) through NLMSG_DONE,
// all within netlinkAnswerBound.
func nlDump(t nlTransport, typ uint16, seq uint32) ([]routingSelector, error) {
	want := uint16(rtmNewRoute)
	if typ == rtmGetRule {
		want = rtmNewRule
	}
	if err := nlSend(t, encodeDumpRequest(typ, seq)); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(netlinkAnswerBound)
	var out []routingSelector
	for {
		if !time.Now().Before(deadline) {
			return nil, incompleteAnswer("no NLMSG_DONE within %v", netlinkAnswerBound)
		}
		b, err := t.recv(deadline)
		if err != nil {
			return nil, err
		}
		sel, done, err := parseSelectorDump(b, seq, t.port(), want)
		if err != nil {
			return nil, err
		}
		out = append(out, sel...)
		if done {
			return out, nil
		}
	}
}

// measureRouteVia answers the egress question for one destination: the
// route, then the device it names, both on one fresh socket per attempt.
func measureRouteVia(open func() (nlTransport, error), lookup egressLookup, dst netip.AddrPort) (egressRoute, error) {
	return withNetlinkRetries(func() (egressRoute, error) {
		t, err := open()
		if err != nil {
			return egressRoute{}, err
		}
		defer t.close()
		reply, err := nlRouteGet(t, 1, dst, lookup)
		if err != nil {
			return egressRoute{}, err
		}
		name, mtu, err := nlLinkGet(t, 2, reply.OIF)
		if err != nil {
			return egressRoute{}, err
		}
		r := egressFromReply(dst.Addr(), reply, name, mtu)
		r.DestPort = dst.Port()
		return r, nil
	})
}

// listSelectorsVia dumps the IPv4 rules and then the IPv4 routes on one fresh
// socket per attempt and returns every selector the lookup cannot account for.
func listSelectorsVia(open func() (nlTransport, error)) ([]routingSelector, error) {
	return withNetlinkRetries(func() ([]routingSelector, error) {
		t, err := open()
		if err != nil {
			return nil, err
		}
		defer t.close()
		var out []routingSelector
		for i, typ := range []uint16{rtmGetRule, rtmGetRoute} {
			sel, err := nlDump(t, typ, uint32(i+1))
			if err != nil {
				return nil, err
			}
			out = append(out, sel...)
		}
		return out, nil
	})
}
