package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// Round W's server path is off by default (-tcp-ingress,
// WINN3_GATEWAY_TCP_INGRESS). See tcp_ingress_flag.go.

type tcpIngressLogSpy struct {
	mu    sync.Mutex
	lines []string
}

func spyTCPIngressLog(t *testing.T) *tcpIngressLogSpy {
	t.Helper()
	saved := logTCPIngress
	t.Cleanup(func() { logTCPIngress = saved })
	spy := &tcpIngressLogSpy{}
	logTCPIngress = func(line string) {
		spy.mu.Lock()
		spy.lines = append(spy.lines, line)
		spy.mu.Unlock()
	}
	return spy
}

func (s *tcpIngressLogSpy) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.lines...)
}

// state returns "on" or "off" when exactly one state line was logged.
func (s *tcpIngressLogSpy) state(t *testing.T) string {
	t.Helper()
	lines := s.snapshot()
	if len(lines) != 1 {
		t.Fatalf("TCP ingress state logged %d times, want once: %q", len(lines), lines)
	}
	switch {
	case strings.Contains(lines[0], "TCP ingress on"):
		return "on"
	case strings.Contains(lines[0], "TCP ingress off"):
		return "off"
	}
	t.Fatalf("TCP ingress line states neither on nor off: %q", lines[0])
	return ""
}

func TestResolveTCPIngress(t *testing.T) {
	for _, tc := range []struct {
		flag    bool
		env     string
		want    bool
		wantErr bool
	}{
		{flag: false, env: "", want: false},
		{flag: false, env: "0", want: false},
		{flag: false, env: "1", want: true},
		{flag: true, env: "", want: true},
		{flag: true, env: "0", want: true}, // the flag is set; env is read only at the default
		{flag: true, env: "1", want: true},
		{flag: false, env: "true", wantErr: true},
		{flag: false, env: "yes", wantErr: true},
		{flag: false, env: "01", wantErr: true},
		{flag: false, env: " 1", wantErr: true},
		{flag: false, env: "1\n", wantErr: true},
		{flag: true, env: "on", wantErr: true}, // refused whatever the flag says
	} {
		got, err := resolveTCPIngress(tc.flag, tc.env)
		if tc.wantErr {
			if err == nil || !strings.Contains(err.Error(), "WINN3_GATEWAY_TCP_INGRESS") {
				t.Errorf("flag %t env %q: got (%t, %v), want a refusal naming the variable", tc.flag, tc.env, got, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("flag %t env %q: got (%t, %v), want %t", tc.flag, tc.env, got, err, tc.want)
		}
	}
}

// ingressGateway is one runServe on a loopback port with plan udp,tcp.
type ingressGateway struct {
	endpoint string
	dir      string
	out      *safeBuffer
	done     chan error
	once     sync.Once
	err      error
}

// ingressStopGrace is how long past opts.runFor the cleanup waits for
// runServe. runServe takes no context and stops only on its -for timer or a
// process-wide signal, so the wait is bounded instead: a start that never
// listened fails the test in seconds, not at the 10 minute go test timeout.
const ingressStopGrace = 5 * time.Second

func startIngressGateway(t *testing.T, opts serveOptions) *ingressGateway {
	t.Helper()
	g := &ingressGateway{out: &safeBuffer{}, done: make(chan error, 1), dir: filepath.Dir(opts.staticPath)}
	// waitListening gets its own copy of the result: the value it receives
	// on an early exit would otherwise be gone before wait reads g.done.
	early := make(chan error, 1)
	go func() {
		err := runServe(opts, g.out)
		early <- err
		g.done <- err
	}()
	t.Cleanup(func() { g.waitBounded(t, opts.runFor+ingressStopGrace) })
	g.endpoint = waitListening(t, g.out, early, 5*time.Second)
	return g
}

func (g *ingressGateway) wait() error {
	g.once.Do(func() { g.err = <-g.done })
	return g.err
}

// waitBounded is wait for cleanup. Past limit it reports the runServe that is
// still running and returns, leaving that goroutine to the test binary.
func (g *ingressGateway) waitBounded(t *testing.T, limit time.Duration) {
	t.Helper()
	exited := make(chan struct{})
	go func() { _ = g.wait(); close(exited) }()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case <-exited:
	case <-timer.C:
		t.Errorf("runServe still running %s after cleanup began; not waiting for it:\n%s", limit, g.out.snapshot())
	}
}

// stopped waits for runServe to return and gives its final status line.
func (g *ingressGateway) stopped(t *testing.T) serveStatus {
	t.Helper()
	if err := g.wait(); err != nil {
		t.Fatalf("runServe: %v", err)
	}
	var final serveStatus
	found := false
	for _, line := range bytes.Split(g.out.snapshot(), []byte("\n")) {
		var st serveStatus
		if json.Unmarshal(bytes.TrimSpace(line), &st) == nil && st.Event == "stopped" {
			final, found = st, true
		}
	}
	if !found {
		t.Fatalf("no stopped status:\n%s", g.out.snapshot())
	}
	return final
}

func ingressOptions(t *testing.T, runFor time.Duration) serveOptions {
	t.Helper()
	opts := operatorValueOptions(t)
	opts.plan = "udp,tcp"
	opts.maxSessions = 4
	opts.runFor = runFor
	return opts
}

// tcpAttemptCarries runs one Round W client (TCP first flight) against
// endpoint and reports whether it reached carrying within the window.
func tcpAttemptCarries(t *testing.T, endpoint, dir string, window time.Duration) bool {
	t.Helper()
	sizing, err := driver.NewSizing(testPathMTU, carrier.ClassUDP, carrier.ClassTCP)
	if err != nil {
		t.Fatal(err)
	}
	client := newCarrierClientForTest(t, t.Context(), dir, sizing,
		tcpCarrierForTest(t, endpoint, dir, sizing))
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		if client.loop.Tunnel().Gate().State() == tun.StateCarrying {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// With -tcp-ingress off (the default), a v3-over-TCP client on the gateway's
// TCP port never gets a session and the gateway builds and admits none. The
// same client against the same configuration with the flag on carries, so the
// attempt is a real Round W client and the off result is the flag's doing.
func TestTCPIngressOffByDefaultBuildsNoSessionOverTCP(t *testing.T) {
	spy := spyTCPIngressLog(t)
	opts := ingressOptions(t, 5*time.Second)
	off := startIngressGateway(t, opts)
	if got := spy.state(t); got != "off" {
		t.Fatalf("default gateway logged TCP ingress %s, want off", got)
	}
	if tcpAttemptCarries(t, off.endpoint, off.dir, 3*time.Second) {
		t.Fatal("with -tcp-ingress off, a v3-over-TCP client reached carrying")
	}
	st := off.stopped(t)
	if st.Admitted != 0 || st.Built != 0 || st.Sessions != 0 || st.BuildFailures != 0 {
		t.Fatalf("with -tcp-ingress off: admitted=%d built=%d sessions=%d build_failures=%d, want all 0",
			st.Admitted, st.Built, st.Sessions, st.BuildFailures)
	}

	// Control: flag on, same options otherwise.
	spy = spyTCPIngressLog(t)
	opts.tcpIngress = true
	on := startIngressGateway(t, opts)
	if got := spy.state(t); got != "on" {
		t.Fatalf("-tcp-ingress gateway logged TCP ingress %s, want on", got)
	}
	if !tcpAttemptCarries(t, on.endpoint, on.dir, 4*time.Second) {
		t.Fatal("control: with -tcp-ingress on, the same v3-over-TCP client did not carry")
	}
	if st := on.stopped(t); st.Admitted != 1 || st.Built != 1 {
		t.Fatalf("control: admitted=%d built=%d, want 1 and 1", st.Admitted, st.Built)
	}
}

// coverProbeReplies collects what a non-v3 peer gets from the gateway's TCP
// port: the decoy's reply to non-TLS bytes and to a truncated TLS record, and
// the cover HTTPS answer to GET / with the cover SNI.
func coverProbeReplies(t *testing.T, endpoint string) map[string]string {
	t.Helper()
	replies := map[string]string{}
	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{"garbage", bytes.Repeat([]byte{0}, 64)},
		{"cleartext HTTP", []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")},
	} {
		got, _, _ := observedDecoyReply(t, endpoint, tc.wire, 0)
		replies[tc.name] = string(withoutDate(got))
	}

	conn, err := net.Dial("tcp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write([]byte{0x16, 0x03, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	partial, err := io.ReadAll(conn)
	_ = conn.Close()
	if err != nil && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatal(err)
	}
	replies["partial TLS record"] = fmt.Sprintf("%x", partial)

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"http/1.1"},
				ServerName:         labCoverName,
			},
		},
	}
	defer client.CloseIdleConnections()
	resp, err := client.Get("https://" + endpoint + "/")
	if err != nil {
		t.Fatalf("GET / through cover HTTPS: %v", err)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	resp.Header.Del("Date")
	var head bytes.Buffer
	_ = resp.Header.Write(&head)
	var issuer string
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		issuer = resp.TLS.PeerCertificates[0].Issuer.CommonName
	}
	replies["cover HTTPS GET /"] = fmt.Sprintf("%s %s issuer=%q\n%s\n%s",
		resp.Proto, resp.Status, issuer, head.String(), body)
	if resp.StatusCode != http.StatusOK || issuer != labCoverIssuer {
		t.Fatalf("cover HTTPS: status %d issuer %q, want 200 from %q", resp.StatusCode, issuer, labCoverIssuer)
	}
	return replies
}

// The cover side of the TCP port is the same with -tcp-ingress off as on.
// TestTCPIngressPreservesPristineDecoyBytes holds "on" to the pre-W decoy for
// the same probes; the lane's lab compares "off" with a 13f002a build.
func TestTCPIngressOffLeavesTheCoverRepliesUnchanged(t *testing.T) {
	opts := ingressOptions(t, 9*time.Second)
	spy := spyTCPIngressLog(t)
	off := startIngressGateway(t, opts)
	if got := spy.state(t); got != "off" {
		t.Fatalf("TCP ingress %s, want off", got)
	}
	offReplies := coverProbeReplies(t, off.endpoint)
	_ = off.stopped(t)

	opts.tcpIngress = true
	spy = spyTCPIngressLog(t)
	on := startIngressGateway(t, opts)
	if got := spy.state(t); got != "on" {
		t.Fatalf("TCP ingress %s, want on", got)
	}
	onReplies := coverProbeReplies(t, on.endpoint)
	_ = on.stopped(t)

	for name, want := range onReplies {
		if got := offReplies[name]; got != want {
			t.Errorf("%s: -tcp-ingress off replied\n%q\nwant (on)\n%q", name, got, want)
		}
		t.Logf("%s: %d bytes, equal off and on", name, len(want))
	}
	if len(offReplies) != 4 || len(onReplies) != 4 {
		t.Fatalf("probe sets differ: off %d on %d", len(offReplies), len(onReplies))
	}
}

func TestRunServeTCPIngressFromTheEnvironment(t *testing.T) {
	for _, tc := range []struct {
		env    string
		want   string
		refuse bool
	}{
		{env: "0", want: "off"},
		{env: "1", want: "on"},
		{env: "true", refuse: true},
		{env: "2", refuse: true},
	} {
		t.Run(tc.env, func(t *testing.T) {
			spy := spyTCPIngressLog(t)
			opts := operatorValueOptions(t)
			t.Setenv("WINN3_GATEWAY_TCP_INGRESS", tc.env)
			err := runServe(opts, new(bytes.Buffer))
			if tc.refuse {
				if err == nil || !strings.Contains(err.Error(), "WINN3_GATEWAY_TCP_INGRESS") || len(spy.snapshot()) != 0 {
					t.Fatalf("env %q: err=%v lines=%q, want a refusal before the listener exists",
						tc.env, err, spy.snapshot())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := spy.state(t); got != tc.want {
				t.Fatalf("env %q: TCP ingress %s, want %s", tc.env, got, tc.want)
			}
		})
	}
}

// The flag reaches runServe through run's own parser.
func TestRunParsesTheTCPIngressFlag(t *testing.T) {
	for _, withFlag := range []bool{false, true} {
		spy := spyTCPIngressLog(t)
		o := operatorValueOptions(t)
		args := []string{"-mode", "serve",
			"-listen", o.listen, "-static", o.staticPath, "-admission", o.admission,
			"-gateway-id", o.gatewayID, "-inner-v4", o.innerV4, "-router-v4", o.routerV4,
			"-plan", o.plan, "-path-mtu", fmt.Sprint(o.pathMTU), "-max-sessions", fmt.Sprint(o.maxSessions),
			"-for", o.runFor.String(),
			"-cert", o.certPath, "-key", o.keyPath, "-cover-cert", o.coverCertPath,
			"-cover-key", o.coverKeyPath, "-ech-keys", o.echKeysPath}
		want := "off"
		if withFlag {
			args = append(args, "-tcp-ingress")
			want = "on"
		}
		if err := run(args, new(bytes.Buffer)); err != nil {
			t.Fatalf("-tcp-ingress %t: %v", withFlag, err)
		}
		if got := spy.state(t); got != want {
			t.Fatalf("-tcp-ingress %t: TCP ingress %s", withFlag, got)
		}
	}
}
