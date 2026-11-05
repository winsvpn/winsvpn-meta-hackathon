// Command spaprobe is a TEST-ONLY helper for the SPA integration test. It is
// not shipped and is not part of any node's runtime.
//
// It stands in for the service behind the gate (AmneziaWG on udp/9110) and for
// a client probing it, so the integration test can answer one question with no
// ambiguity: can this source address reach that port right now?
//
// Modes:
//
//	echo    -listen ADDR          reply "PONG" to every datagram (the service)
//	probe   -target ADDR          one datagram from a fresh socket; exit 0 on reply
//	persist -target ADDR -pause D probe, wait, probe again on the SAME socket
//	sustain -target ADDR -duration D -interval D
//	                              hold ONE socket and exchange continuously
//
// "persist" exists to prove the conntrack exemption: the gate is installed
// during the pause, and a flow that was already established must survive it.
//
// "sustain" exists because a repeated one-shot "probe" opens a NEW source port
// every time, so every packet is conntrack state NEW and a `ct state
// established` rule never matches it. A real AmneziaWG tunnel is the opposite:
// one long-lived 5-tuple with bidirectional traffic, which conntrack promotes
// to ESTABLISHED. Only "sustain" reproduces that, and it is what the rule
// ordering question turns on.
package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fail("usage: spaprobe echo|probe|persist|sustain [flags]")
	}
	mode := os.Args[1]
	args := os.Args[2:]

	switch mode {
	case "echo":
		runEcho(stringFlag(args, "-listen", ":9110"))
	case "probe":
		ok, err := runProbe(
			mustDial(stringFlag(args, "-target", "")),
			durationFlag(args, "-timeout", 2*time.Second),
		)
		if err != nil {
			fail("%v", err)
		}
		if ok {
			fmt.Println("REACHABLE")
			os.Exit(0)
		}
		fmt.Println("BLOCKED")
		os.Exit(1)
	case "persist":
		conn := mustDial(stringFlag(args, "-target", ""))
		timeout := durationFlag(args, "-timeout", 2*time.Second)
		pause := durationFlag(args, "-pause", 5*time.Second)
		before, err := runProbe(conn, timeout)
		if err != nil {
			fail("before: %v", err)
		}
		fmt.Printf("BEFORE=%s\n", reachability(before))
		time.Sleep(pause)
		after, err := runProbe(conn, timeout)
		if err != nil {
			fail("after: %v", err)
		}
		fmt.Printf("AFTER=%s\n", reachability(after))
		if before && after {
			os.Exit(0)
		}
		os.Exit(1)
	case "sustain":
		runSustain(
			mustDial(stringFlag(args, "-target", "")),
			durationFlag(args, "-duration", 60*time.Second),
			durationFlag(args, "-interval", 500*time.Millisecond),
			durationFlag(args, "-timeout", time.Second),
		)
	default:
		fail("unknown mode %q", mode)
	}
}

// runSustain holds one socket for the whole run, so the kernel sees a single
// 5-tuple carrying traffic in both directions and promotes it to ESTABLISHED.
func runSustain(conn net.Conn, duration, interval, timeout time.Duration) {
	deadline := time.Now().Add(duration)
	sent, received := 0, 0
	for time.Now().Before(deadline) {
		sent++
		ok, err := runProbe(conn, timeout)
		if err != nil {
			fail("%v", err)
		}
		if ok {
			received++
		}
		time.Sleep(interval)
	}
	fmt.Printf("SENT=%d RECEIVED=%d\n", sent, received)
	if received == 0 {
		os.Exit(1)
	}
}

func runEcho(listen string) {
	conn, err := net.ListenPacket("udp", listen)
	if err != nil {
		fail("listen %s: %v", listen, err)
	}
	defer conn.Close()
	fmt.Printf("echo listening on %s\n", conn.LocalAddr())
	buffer := make([]byte, 2048)
	for {
		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			fail("read: %v", err)
		}
		_ = n
		if _, err := conn.WriteTo([]byte("PONG"), addr); err != nil {
			fmt.Fprintf(os.Stderr, "echo write: %v\n", err)
		}
	}
}

// runProbe sends one datagram and reports whether a reply came back inside the
// timeout. No reply is exactly what a gated port looks like from outside.
// A local write or deadline error is a tool failure, not BLOCKED: treating it
// as BLOCKED makes a broken probe look like a working gate.
func runProbe(conn net.Conn, timeout time.Duration) (bool, error) {
	if _, err := conn.Write([]byte("PING")); err != nil {
		return false, fmt.Errorf("write: %w", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return false, fmt.Errorf("deadline: %w", err)
	}
	buffer := make([]byte, 64)
	n, err := conn.Read(buffer)
	if err != nil {
		return false, nil
	}
	return n > 0, nil
}

func mustDial(target string) net.Conn {
	if target == "" {
		fail("-target is required")
	}
	conn, err := net.Dial("udp", target)
	if err != nil {
		fail("dial %s: %v", target, err)
	}
	return conn
}

func reachability(ok bool) string {
	if ok {
		return "REACHABLE"
	}
	return "BLOCKED"
}

func stringFlag(args []string, name, fallback string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return fallback
}

func durationFlag(args []string, name string, fallback time.Duration) time.Duration {
	raw := stringFlag(args, name, "")
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		fail("%s: %v", name, err)
	}
	return value
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "spaprobe: "+format+"\n", args...)
	os.Exit(2)
}
