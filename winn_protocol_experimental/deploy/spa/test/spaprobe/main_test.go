package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestStringFlag(t *testing.T) {
	if got := stringFlag([]string{"-listen", "127.0.0.1:9"}, "-listen", ":9110"); got != "127.0.0.1:9" {
		t.Fatalf("found: got %q", got)
	}
	if got := stringFlag(nil, "-listen", ":9110"); got != ":9110" {
		t.Fatalf("fallback: got %q", got)
	}
	// First match wins; a trailing flag with no value is ignored.
	if got := stringFlag([]string{"-target", "a", "-target", "b", "-timeout"}, "-target", ""); got != "a" {
		t.Fatalf("first-wins: got %q", got)
	}
}

func TestDurationFlag(t *testing.T) {
	if got := durationFlag(nil, "-timeout", 2*time.Second); got != 2*time.Second {
		t.Fatalf("fallback: got %v", got)
	}
	if got := durationFlag([]string{"-timeout", "250ms"}, "-timeout", time.Second); got != 250*time.Millisecond {
		t.Fatalf("parsed: got %v", got)
	}
}

func TestReachability(t *testing.T) {
	if got := reachability(true); got != "REACHABLE" {
		t.Fatalf("true: got %q", got)
	}
	if got := reachability(false); got != "BLOCKED" {
		t.Fatalf("false: got %q", got)
	}
}

func TestRunProbeReachable(t *testing.T) {
	addr, stop := startTestEcho(t, []byte("PONG"))
	defer stop()
	conn := mustDial(addr)
	defer conn.Close()
	ok, err := runProbe(conn, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("runProbe: %v", err)
	}
	if !ok {
		t.Fatal("expected REACHABLE against local echo")
	}
}

func TestRunProbeAnyReplyCounts(t *testing.T) {
	addr, stop := startTestEcho(t, []byte("X"))
	defer stop()
	conn := mustDial(addr)
	defer conn.Close()
	ok, err := runProbe(conn, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("runProbe: %v", err)
	}
	if !ok {
		t.Fatal("any n>0 reply must count as reachable; this is the documented contract")
	}
}

func TestRunProbeBlocked(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	conn := mustDial(addr)
	defer conn.Close()
	ok, err := runProbe(conn, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("timeout is BLOCKED, not a tool error; got %v", err)
	}
	if ok {
		t.Fatal("expected BLOCKED against a closed port")
	}
}

func TestRunProbeWriteError(t *testing.T) {
	injected := errors.New("injected write error")
	ok, err := runProbe(&errConn{writeErr: injected}, time.Second)
	if ok {
		t.Fatal("write error must not look reachable")
	}
	if err == nil {
		t.Fatal("write error must not look like BLOCKED (nil error)")
	}
	if !strings.Contains(err.Error(), "write") {
		t.Fatalf("want write error, got %v", err)
	}
	if !errors.Is(err, injected) {
		t.Fatalf("want wrapped injected error, got %v", err)
	}
}

func TestRunProbeDeadlineError(t *testing.T) {
	injected := errors.New("injected deadline error")
	ok, err := runProbe(&errConn{deadErr: injected}, time.Second)
	if ok {
		t.Fatal("deadline error must not look reachable")
	}
	if err == nil {
		t.Fatal("deadline error must not look like BLOCKED (nil error)")
	}
	if !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("want deadline error, got %v", err)
	}
	if !errors.Is(err, injected) {
		t.Fatalf("want wrapped injected error, got %v", err)
	}
}

func TestPersistSameSocketTwice(t *testing.T) {
	addr, stop := startTestEcho(t, []byte("PONG"))
	defer stop()
	conn := mustDial(addr)
	defer conn.Close()
	before, err := runProbe(conn, 500*time.Millisecond)
	if err != nil || !before {
		t.Fatalf("before: ok=%v err=%v", before, err)
	}
	after, err := runProbe(conn, 500*time.Millisecond)
	if err != nil || !after {
		t.Fatalf("after: ok=%v err=%v", after, err)
	}
}

func TestCLINoArgsUsageMentionsSustain(t *testing.T) {
	stdout, stderr, code := runCLI(t)
	if code != 2 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "sustain") {
		t.Fatalf("usage must mention sustain, stderr=%q", stderr)
	}
}

func TestCLIUnknownMode(t *testing.T) {
	_, stderr, code := runCLI(t, "not-a-mode")
	if code != 2 {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "unknown mode") {
		t.Fatalf("stderr=%q", stderr)
	}
}

func TestCLIProbeReachableAndBlocked(t *testing.T) {
	echo := cliCommand(t, "echo", "-listen", "127.0.0.1:0")
	stdoutPipe, err := echo.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := echo.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = echo.Process.Kill()
		_ = echo.Wait()
	}()
	line, err := bufio.NewReader(stdoutPipe).ReadString('\n')
	if err != nil {
		t.Fatalf("echo banner: %v", err)
	}
	addr := strings.TrimSpace(strings.TrimPrefix(line, "echo listening on "))
	if addr == "" || addr == line {
		t.Fatalf("could not parse echo address from %q", line)
	}

	out, errb, code := runCLI(t, "probe", "-target", addr, "-timeout", "500ms")
	if code != 0 {
		t.Fatalf("reachable probe exit=%d stdout=%q stderr=%q", code, out, errb)
	}
	if strings.TrimSpace(out) != "REACHABLE" {
		t.Fatalf("stdout=%q", out)
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := pc.LocalAddr().String()
	_ = pc.Close()
	out, errb, code = runCLI(t, "probe", "-target", closed, "-timeout", "200ms")
	if code != 1 {
		t.Fatalf("blocked probe exit=%d stdout=%q stderr=%q", code, out, errb)
	}
	if strings.TrimSpace(out) != "BLOCKED" {
		t.Fatalf("stdout=%q", out)
	}
}

func TestCLIPersistAndSustain(t *testing.T) {
	echo := cliCommand(t, "echo", "-listen", "127.0.0.1:0")
	stdoutPipe, err := echo.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := echo.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = echo.Process.Kill()
		_ = echo.Wait()
	}()
	line, err := bufio.NewReader(stdoutPipe).ReadString('\n')
	if err != nil {
		t.Fatalf("echo banner: %v", err)
	}
	addr := strings.TrimSpace(strings.TrimPrefix(line, "echo listening on "))

	out, errb, code := runCLI(t, "persist", "-target", addr, "-timeout", "500ms", "-pause", "50ms")
	if code != 0 {
		t.Fatalf("persist exit=%d stdout=%q stderr=%q", code, out, errb)
	}
	if !strings.Contains(out, "BEFORE=REACHABLE") || !strings.Contains(out, "AFTER=REACHABLE") {
		t.Fatalf("persist stdout=%q", out)
	}

	out, errb, code = runCLI(t, "sustain", "-target", addr, "-duration", "250ms", "-interval", "80ms", "-timeout", "200ms")
	if code != 0 {
		t.Fatalf("sustain exit=%d stdout=%q stderr=%q", code, out, errb)
	}
	if !strings.Contains(out, "SENT=") || !strings.Contains(out, "RECEIVED=") {
		t.Fatalf("sustain stdout=%q", out)
	}
	if strings.Contains(out, "RECEIVED=0") {
		t.Fatalf("sustain got no replies: %q", out)
	}
}

func TestCLIEchoRepliesPONG(t *testing.T) {
	echo := cliCommand(t, "echo", "-listen", "127.0.0.1:0")
	stdoutPipe, err := echo.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := echo.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = echo.Process.Kill()
		_ = echo.Wait()
	}()
	line, err := bufio.NewReader(stdoutPipe).ReadString('\n')
	if err != nil {
		t.Fatalf("echo banner: %v", err)
	}
	addr := strings.TrimSpace(strings.TrimPrefix(line, "echo listening on "))
	conn := mustDial(addr)
	defer conn.Close()
	if _, err := conn.Write([]byte("PING")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read PONG: %v", err)
	}
	if got := string(buf[:n]); got != "PONG" {
		t.Fatalf("echo payload: got %q want PONG", got)
	}
}

func TestCLIMissingTarget(t *testing.T) {
	_, stderr, code := runCLI(t, "probe")
	if code != 2 {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "-target is required") {
		t.Fatalf("stderr=%q", stderr)
	}
}

func TestHelperSpaprobe(t *testing.T) {
	if os.Getenv("SPAPROBE_TEST_AS_MAIN") != "1" {
		t.Skip("helper process")
	}
	args := []string{"spaprobe"}
	seenDash := false
	for _, a := range os.Args[1:] {
		if !seenDash {
			if a == "--" {
				seenDash = true
			}
			continue
		}
		args = append(args, a)
	}
	os.Args = args
	main()
}

func startTestEcho(t *testing.T, reply []byte) (addr string, stop func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			_, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteTo(reply, from); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().String(), func() {
		_ = pc.Close()
		<-done
	}
}

func cliCommand(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	cmdArgs := append([]string{"-test.run=^TestHelperSpaprobe$", "--"}, args...)
	cmd := exec.Command(os.Args[0], cmdArgs...)
	cmd.Env = append(os.Environ(), "SPAPROBE_TEST_AS_MAIN=1")
	return cmd
}

func runCLI(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := cliCommand(t, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	code = 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run CLI %v: %v", args, err)
		}
	}
	return outBuf.String(), errBuf.String(), code
}

type dummyAddr struct{}

func (dummyAddr) Network() string { return "udp" }
func (dummyAddr) String() string  { return "127.0.0.1:0" }

type errConn struct {
	writeErr error
	deadErr  error
}

func (e *errConn) Read([]byte) (int, error) { return 0, io.EOF }
func (e *errConn) Write(b []byte) (int, error) {
	if e.writeErr != nil {
		return 0, e.writeErr
	}
	return len(b), nil
}
func (e *errConn) Close() error                     { return nil }
func (e *errConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (e *errConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (e *errConn) SetDeadline(time.Time) error      { return nil }
func (e *errConn) SetReadDeadline(time.Time) error  { return e.deadErr }
func (e *errConn) SetWriteDeadline(time.Time) error { return nil }
