//go:build linux

package main

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Round CM3 Turn 6 on a real kernel: the receive side of every egress
// question. These run as whatever user runs the test.

// The codec's Turn 6 constants against golang.org/x/sys/unix. x/sys v0.47.0
// ends the FRA_* list at FRA_DPORT_RANGE (24); FRA_DSCP (25), FRA_SPORT_MASK
// (28), FRA_DPORT_MASK (29) and FRA_DSCP_MASK (30) are from the kernel's
// include/uapi/linux/fib_rules.h (read 2026-09-27) and are held there by the
// allowlist test instead.
func TestNetlinkAnswerConstantsMatchXSys(t *testing.T) {
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"NLMSG_DONE", nlmsgDone, unix.NLMSG_DONE},
		{"NLMSG_OVERRUN", nlmsgOverrun, unix.NLMSG_OVERRUN},
		{"NLM_F_DUMP_INTR", nlmFDumpIntr, unix.NLM_F_DUMP_INTR},
		{"NLM_F_DUMP", nlmFDump, unix.NLM_F_DUMP},
		{"RTM_NEWRULE", rtmNewRule, unix.RTM_NEWRULE},
		{"RTM_GETRULE", rtmGetRule, unix.RTM_GETRULE},
		{"RTM_NEWLINK", rtmNewLink, unix.RTM_NEWLINK},
		{"RTM_GETLINK", rtmGetLink, unix.RTM_GETLINK},
		{"ifinfomsg", ifInfomsgLen, unix.SizeofIfInfomsg},
		{"IFLA_IFNAME", iflaIfname, unix.IFLA_IFNAME},
		{"IFLA_MTU", iflaMTU, unix.IFLA_MTU},
		{"FRA_DST", fraDst, unix.FRA_DST},
		{"FRA_SRC", fraSrc, unix.FRA_SRC},
		{"FRA_IIFNAME", fraIifname, unix.FRA_IIFNAME},
		{"FRA_GOTO", fraGoto, unix.FRA_GOTO},
		{"FRA_PRIORITY", fraPriority, unix.FRA_PRIORITY},
		{"FRA_FWMARK", fraFwmark, unix.FRA_FWMARK},
		{"FRA_FLOW", fraFlow, unix.FRA_FLOW},
		{"FRA_TUN_ID", fraTunID, unix.FRA_TUN_ID},
		{"FRA_SUPPRESS_IFGROUP", fraSuppressIfgroup, unix.FRA_SUPPRESS_IFGROUP},
		{"FRA_SUPPRESS_PREFIXLEN", fraSuppressPrefixlen, unix.FRA_SUPPRESS_PREFIXLEN},
		{"FRA_TABLE", fraTable, unix.FRA_TABLE},
		{"FRA_FWMASK", fraFwmask, unix.FRA_FWMASK},
		{"FRA_OIFNAME", fraOifname, unix.FRA_OIFNAME},
		{"FRA_PAD", fraPad, unix.FRA_PAD},
		{"FRA_L3MDEV", fraL3mdev, unix.FRA_L3MDEV},
		{"FRA_UID_RANGE", fraUIDRange, unix.FRA_UID_RANGE},
		{"FRA_PROTOCOL", fraProtocol, unix.FRA_PROTOCOL},
		{"FRA_IP_PROTO", fraIPProto, unix.FRA_IP_PROTO},
		{"FRA_SPORT_RANGE", fraSportRange, unix.FRA_SPORT_RANGE},
		{"FRA_DPORT_RANGE", fraDportRange, unix.FRA_DPORT_RANGE},
		{"FIB_RULE_INVERT", fibRuleInvert, unix.FIB_RULE_INVERT},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d here, %d in x/sys/unix", c.name, c.got, c.want)
		}
	}
}

// Every answer the real kernel gives on this host passes the strict checks:
// its sequence number, the socket's port id, no stray flags. (If the kernel
// answered with another port id, every egress question would fail closed.)
func TestRealKernelAnswersPassTheStrictChecks(t *testing.T) {
	sock, err := openRouteSocket()
	if err != nil {
		t.Fatal(err)
	}
	defer sock.close()
	if sock.port() == 0 {
		t.Fatal("no port id")
	}
	name, mtu, err := nlLinkGet(sock, 7, 1)
	if err != nil || name != "lo" || mtu < minDeviceMTU {
		t.Fatalf("link 1: %q %d %v", name, mtu, err)
	}
	for i, typ := range []uint16{rtmGetRule, rtmGetRoute} {
		if _, err := nlDump(sock, typ, uint32(10+i)); err != nil {
			t.Fatalf("dump %d: %v", typ, err)
		}
	}
	t.Logf("uid %d: port id %d, link 1 = %s mtu %d; rule and route dumps complete", os.Getuid(), sock.port(), name, mtu)
}

// MSG_TRUNC: a datagram longer than the buffer is incomplete, never the
// part that fit. The kernel's route dump of this host is more than 64 bytes.
func TestTruncatedDatagramIsIncomplete(t *testing.T) {
	sock, err := openRouteSocket()
	if err != nil {
		t.Fatal(err)
	}
	defer sock.close()
	sock.buf = sock.buf[:64]
	_, err = nlDump(sock, rtmGetRoute, 1)
	if !errors.Is(err, errNetlinkIncomplete) || !strings.Contains(err.Error(), "MSG_TRUNC") {
		t.Fatalf("64-byte buffer: %v, want an incomplete answer naming MSG_TRUNC", err)
	}
}

// A datagram another process sends to the socket is not the kernel's answer.
// Without CAP_NET_ADMIN the kernel refuses such a unicast (NETLINK_ROUTE does
// not allow unprivileged sends to a port); with it, recv rejects it.
func TestForeignSenderIsNotTheKernel(t *testing.T) {
	sock, err := openRouteSocket()
	if err != nil {
		t.Fatal(err)
	}
	defer sock.close()
	other, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(other) }()
	if err := unix.Bind(other, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	// A forged, otherwise perfect NLMSG_DONE for the socket's next dump.
	forged := nlMsgFull(nlmsgDone, 0, 1, sock.port(), u32(0))
	serr := unix.Sendto(other, forged, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: sock.port()})
	if serr != nil {
		if os.Geteuid() == 0 || !errors.Is(serr, unix.EPERM) {
			t.Fatalf("uid %d: send to port %d: %v", os.Getuid(), sock.port(), serr)
		}
		t.Logf("uid %d: the kernel refused the forged unicast: %v", os.Getuid(), serr)
		return
	}
	_, err = sock.recv(time.Now().Add(netlinkAnswerBound))
	if !errors.Is(err, errNetlinkIncomplete) || !strings.Contains(err.Error(), "not the kernel") {
		t.Fatalf("uid %d: a forged NLMSG_DONE from another socket: %v", os.Getuid(), err)
	}
	t.Logf("uid %d: forged unicast delivered and rejected: %v", os.Getuid(), err)
}

// No answer within the bound: a socket nobody asked anything is silent.
func TestSilentKernelIsIncompleteWithinTheBound(t *testing.T) {
	sock, err := openRouteSocket()
	if err != nil {
		t.Fatal(err)
	}
	defer sock.close()
	start := time.Now()
	_, err = sock.recv(start.Add(40 * time.Millisecond))
	el := time.Since(start)
	if !errors.Is(err, errNetlinkIncomplete) || el < 30*time.Millisecond || el > 500*time.Millisecond {
		t.Fatalf("silent socket: %v after %v", err, el)
	}
}
