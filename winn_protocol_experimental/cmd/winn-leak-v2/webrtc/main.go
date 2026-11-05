//go:build unix

// Command winn-webrtc-v2 launches a real Chromium process, drives an actual
// RTCPeerConnection through the Chrome DevTools Protocol, and writes strict
// ICE-candidate evidence. It deliberately has no synthetic/fake-browser mode:
// inability to launch and interrogate Chromium is an acceptance failure.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/websocket"
)

const evidenceVersion = "winn-webrtc-evidence/v2"

type config struct {
	runID        string
	family       string
	browser      string
	stunServer   netip.AddrPort
	expected     netip.Addr
	allowedHosts map[netip.Addr]struct{}
	forbidden    map[netip.Addr]struct{}
	output       string
	timeout      time.Duration
}

type iceCandidate struct {
	Candidate      string `json:"candidate"`
	Address        string `json:"address,omitempty"`
	Port           uint16 `json:"port,omitempty"`
	Protocol       string `json:"protocol,omitempty"`
	Type           string `json:"type,omitempty"`
	RelatedAddress string `json:"related_address,omitempty"`
	RelatedPort    uint16 `json:"related_port,omitempty"`
}

type browserResult struct {
	UserAgent      string         `json:"user_agent"`
	GatheringState string         `json:"gathering_state"`
	ElapsedMS      float64        `json:"elapsed_ms"`
	Candidates     []iceCandidate `json:"candidates"`
}

type evidence struct {
	Version             string         `json:"version"`
	RunID               string         `json:"run_id"`
	Family              string         `json:"family"`
	StartedAt           string         `json:"started_at"`
	CompletedAt         string         `json:"completed_at"`
	EffectiveUID        int            `json:"effective_uid"`
	BrowserPath         string         `json:"browser_path"`
	BrowserResolvedPath string         `json:"browser_resolved_path"`
	BrowserVersion      string         `json:"browser_version,omitempty"`
	BrowserSHA256       string         `json:"browser_sha256,omitempty"`
	RunnerSHA256        string         `json:"runner_sha256,omitempty"`
	BrowserPID          int            `json:"browser_pid,omitempty"`
	BrowserPGID         int            `json:"browser_pgid,omitempty"`
	ProcessGroupGone    bool           `json:"process_group_gone"`
	ProfileRemoved      bool           `json:"profile_removed"`
	STUNServer          string         `json:"stun_server"`
	ExpectedEgress      string         `json:"expected_egress"`
	AllowedHosts        []string       `json:"allowed_host_addresses"`
	Forbidden           []string       `json:"forbidden_addresses"`
	Browser             *browserResult `json:"browser,omitempty"`
	ChromiumStderr      string         `json:"chromium_stderr,omitempty"`
	Passed              bool           `json:"passed"`
	Failure             string         `json:"failure,omitempty"`
}

func main() {
	cfg, err := parseConfig(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	result := run(cfg)
	if err := writeEvidence(cfg.output, result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if !result.Passed {
		fmt.Fprintln(os.Stderr, result.Failure)
		os.Exit(1)
	}
}

func parseConfig(args []string) (config, error) {
	flags := flag.NewFlagSet("winn-webrtc-v2", flag.ContinueOnError)
	runID := flags.String("run-id", "", "lowercase 32-hex run identifier")
	family := flags.String("family", "", "v4 or v6")
	browser := flags.String("browser", "", "absolute Chromium/Chrome executable")
	stunServer := flags.String("stun-server", "", "controlled IP-literal STUN address:port")
	expected := flags.String("expected-egress", "", "expected gateway egress IP")
	allowed := flags.String(
		"allowed-host-addresses", "",
		"comma-separated tunnel host IPs allowed as literal host candidates",
	)
	forbidden := flags.String(
		"forbidden-addresses", "",
		"comma-separated physical, ISP, and pre-tunnel IPs that must never appear",
	)
	output := flags.String("output", "", "exclusive absolute JSON evidence path")
	timeout := flags.Duration("timeout", 25*time.Second, "hard Chromium/CDP timeout")
	if err := flags.Parse(args); err != nil {
		return config{}, err
	}
	if flags.NArg() != 0 {
		return config{}, errors.New("unexpected positional arguments")
	}
	if !lowerHex(*runID, 16) || (*family != "v4" && *family != "v6") {
		return config{}, errors.New("run-id must be lowercase 32-hex and family must be v4 or v6")
	}
	if err := requireAbsoluteClean(*browser, "browser"); err != nil {
		return config{}, err
	}
	if err := requireAbsoluteClean(*output, "output"); err != nil {
		return config{}, err
	}
	stun, err := netip.ParseAddrPort(*stunServer)
	if err != nil || stun.Port() == 0 || stun.Addr().IsUnspecified() {
		return config{}, errors.New("stun-server must be a usable IP-literal address:port")
	}
	egress, err := netip.ParseAddr(*expected)
	if err != nil || egress.IsUnspecified() {
		return config{}, errors.New("expected-egress must be a usable IP literal")
	}
	isV4 := *family == "v4"
	if stun.Addr().Is4() != isV4 || egress.Is4() != isV4 {
		return config{}, errors.New("STUN server and expected egress must match the selected family")
	}
	allowedSet, err := parseAddressSet(*allowed)
	if err != nil {
		return config{}, fmt.Errorf("allowed-host-addresses: %w", err)
	}
	forbiddenSet, err := parseAddressSet(*forbidden)
	if err != nil {
		return config{}, fmt.Errorf("forbidden-addresses: %w", err)
	}
	if len(forbiddenSet) == 0 {
		return config{}, errors.New("forbidden-addresses must include pre-tunnel addresses")
	}
	for address := range allowedSet {
		if _, exists := forbiddenSet[address]; exists {
			return config{}, fmt.Errorf("address %s is both allowed and forbidden", address)
		}
	}
	if _, exists := forbiddenSet[egress.Unmap()]; exists {
		return config{}, errors.New("expected gateway egress is marked forbidden")
	}
	if *timeout < 10*time.Second || *timeout > time.Minute {
		return config{}, errors.New("timeout must be between 10s and 1m")
	}
	return config{
		runID: *runID, family: *family, browser: *browser,
		stunServer: stun, expected: egress.Unmap(),
		allowedHosts: allowedSet, forbidden: forbiddenSet,
		output: *output, timeout: *timeout,
	}, nil
}

func run(cfg config) evidence {
	result := evidence{
		Version: evidenceVersion, RunID: cfg.runID, Family: cfg.family,
		StartedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		EffectiveUID: os.Geteuid(),
		BrowserPath:  cfg.browser, STUNServer: cfg.stunServer.String(),
		ExpectedEgress: cfg.expected.String(),
		AllowedHosts:   sortedAddresses(cfg.allowedHosts),
		Forbidden:      sortedAddresses(cfg.forbidden),
	}
	finish := func(err error) evidence {
		result.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if err != nil {
			result.Failure = err.Error()
			result.Passed = false
		} else {
			result.Passed = true
		}
		return result
	}
	if runtime.GOOS != "linux" {
		return finish(errors.New("real Chromium acceptance runner is Linux-only"))
	}
	if os.Geteuid() == 0 {
		return finish(errors.New("refusing to weaken the Chromium sandbox by running as root"))
	}
	resolvedBrowser, err := filepath.EvalSymlinks(cfg.browser)
	if err != nil {
		return finish(fmt.Errorf("resolve browser executable: %w", err))
	}
	if err := requireAbsoluteClean(resolvedBrowser, "resolved browser"); err != nil {
		return finish(err)
	}
	cfg.browser = resolvedBrowser
	result.BrowserResolvedPath = resolvedBrowser
	info, err := secureRegularFile(cfg.browser, true)
	if err != nil {
		return finish(fmt.Errorf("browser executable: %w", err))
	}
	if info.Mode().Perm()&0o111 == 0 {
		return finish(errors.New("browser file is not executable"))
	}
	result.BrowserSHA256, err = sha256File(cfg.browser)
	if err != nil {
		return finish(fmt.Errorf("hash browser: %w", err))
	}
	executable, err := os.Executable()
	if err != nil {
		return finish(fmt.Errorf("locate runner: %w", err))
	}
	result.RunnerSHA256, err = sha256File(executable)
	if err != nil {
		return finish(fmt.Errorf("hash runner: %w", err))
	}

	versionContext, versionCancel := context.WithTimeout(context.Background(), 3*time.Second)
	versionOutput, err := runCommandOutput(versionContext, cfg.browser, "--version")
	versionCancel()
	if err != nil {
		return finish(fmt.Errorf("query Chromium version: %w", err))
	}
	result.BrowserVersion = strings.TrimSpace(string(versionOutput))
	if !isChromiumVersion(result.BrowserVersion) {
		return finish(fmt.Errorf("browser did not identify as Chromium/Chrome: %q", result.BrowserVersion))
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()
	profile, err := os.MkdirTemp("", "winn-webrtc-v2-*")
	if err != nil {
		return finish(fmt.Errorf("create Chromium profile: %w", err))
	}
	// #nosec G302 -- a private directory requires its owner execute bit.
	if err := os.Chmod(profile, 0o700); err != nil {
		_ = os.RemoveAll(profile)
		return finish(fmt.Errorf("protect Chromium profile: %w", err))
	}
	var stderr limitedBuffer
	process, err := startChromium(ctx, cfg.browser, profile, &stderr)
	if err != nil {
		_ = os.RemoveAll(profile)
		result.ChromiumStderr = stderr.String()
		return finish(fmt.Errorf("start Chromium: %w", err))
	}
	result.BrowserPID = process.command.Process.Pid
	result.BrowserPGID = process.pgid
	var connection *websocket.Conn
	cleaned := false
	cleanup := func() error {
		if cleaned {
			return nil
		}
		cleaned = true
		var closeErr error
		if connection != nil {
			closeErr = connection.Close()
		}
		stopErr := process.stop()
		result.ProcessGroupGone = !process.groupAlive()
		removeErr := os.RemoveAll(profile)
		if _, statErr := os.Lstat(profile); !os.IsNotExist(statErr) {
			if statErr == nil {
				removeErr = errors.Join(removeErr, errors.New("chromium profile residue remained"))
			} else {
				removeErr = errors.Join(removeErr, statErr)
			}
		} else {
			result.ProfileRemoved = true
		}
		if !result.ProcessGroupGone {
			stopErr = errors.Join(
				stopErr,
				errors.New("chromium process group residue remained"),
			)
		}
		return errors.Join(closeErr, stopErr, removeErr)
	}
	defer cleanup()
	fail := func(runErr error) evidence {
		return finish(errors.Join(runErr, cleanup()))
	}

	port, err := waitDevTools(ctx, profile, process)
	if err != nil {
		result.ChromiumStderr = stderr.String()
		return fail(err)
	}
	pageURL, err := pageWebSocketURL(ctx, port)
	if err != nil {
		result.ChromiumStderr = stderr.String()
		return fail(err)
	}
	connection, err = dialLoopbackWebSocket(pageURL, port)
	if err != nil {
		result.ChromiumStderr = stderr.String()
		return fail(fmt.Errorf("connect to Chromium DevTools: %w", err))
	}
	client := &cdpClient{connection: connection}
	var evaluated struct {
		Result struct {
			Type        string          `json:"type"`
			Value       json.RawMessage `json:"value"`
			Description string          `json:"description"`
		} `json:"result"`
		ExceptionDetails json.RawMessage `json:"exceptionDetails"`
	}
	expression, err := rtcExpression("stun:" + cfg.stunServer.String())
	if err != nil {
		return fail(err)
	}
	if err := client.call(ctx, "Runtime.evaluate", map[string]any{
		"expression": expression, "awaitPromise": true, "returnByValue": true,
		"userGesture": true,
	}, &evaluated); err != nil {
		result.ChromiumStderr = stderr.String()
		return fail(fmt.Errorf("evaluate RTCPeerConnection: %w", err))
	}
	if len(evaluated.ExceptionDetails) != 0 &&
		string(evaluated.ExceptionDetails) != "null" {
		return fail(fmt.Errorf("RTCPeerConnection exception: %s", evaluated.ExceptionDetails))
	}
	if evaluated.Result.Type != "object" {
		return fail(fmt.Errorf(
			"RTCPeerConnection returned %s: %s",
			evaluated.Result.Type, evaluated.Result.Description,
		))
	}
	var browser browserResult
	if err := json.Unmarshal(evaluated.Result.Value, &browser); err != nil {
		return fail(fmt.Errorf("decode RTCPeerConnection result: %w", err))
	}
	result.Browser = &browser
	result.ChromiumStderr = stderr.String()
	validationErr := validateCandidates(cfg, browser)
	return finish(errors.Join(validationErr, cleanup()))
}

func validateCandidates(cfg config, result browserResult) error {
	if result.GatheringState != "complete" {
		return fmt.Errorf("ice gathering ended in state %q", result.GatheringState)
	}
	if len(result.Candidates) == 0 {
		return errors.New("chromium returned no ICE candidates")
	}
	foundExpected := false
	for index := range result.Candidates {
		candidate := &result.Candidates[index]
		fillCandidateFields(candidate)
		address := strings.Trim(candidate.Address, "[]")
		if address == "" {
			return fmt.Errorf("ICE candidate %d omitted its address", index)
		}
		if strings.HasSuffix(strings.ToLower(address), ".local") {
			if candidate.Type != "host" {
				return fmt.Errorf("non-host candidate %d used an mDNS name", index)
			}
			continue
		}
		parsed, err := netip.ParseAddr(address)
		if err != nil {
			return fmt.Errorf("ICE candidate %d used an unparseable address %q", index, address)
		}
		parsed = parsed.Unmap()
		if _, forbidden := cfg.forbidden[parsed]; forbidden {
			return fmt.Errorf("ICE candidate exposed forbidden pre-tunnel address %s", parsed)
		}
		switch candidate.Type {
		case "srflx":
			if parsed != cfg.expected {
				return fmt.Errorf(
					"server-reflexive candidate %s did not equal gateway egress %s",
					parsed, cfg.expected,
				)
			}
			if parsed.Is4() != (cfg.family == "v4") {
				return errors.New("server-reflexive candidate family mismatch")
			}
			foundExpected = true
		case "host":
			if _, allowed := cfg.allowedHosts[parsed]; !allowed {
				return fmt.Errorf("literal host candidate %s was not explicitly allowed", parsed)
			}
		default:
			return fmt.Errorf("unexpected ICE candidate type %q", candidate.Type)
		}
		if candidate.RelatedAddress != "" {
			related, err := netip.ParseAddr(strings.Trim(candidate.RelatedAddress, "[]"))
			if err != nil {
				return fmt.Errorf("candidate %d has invalid related address", index)
			}
			related = related.Unmap()
			if related.IsUnspecified() {
				if candidate.Type != "srflx" ||
					candidate.RelatedPort != 0 ||
					related.Is4() != (cfg.family == "v4") {
					return fmt.Errorf(
						"candidate %d used an invalid redacted related endpoint",
						index,
					)
				}
				continue
			}
			if _, forbidden := cfg.forbidden[related]; forbidden {
				return fmt.Errorf("ICE related address exposed forbidden address %s", related)
			}
			if related != cfg.expected {
				if _, allowed := cfg.allowedHosts[related]; !allowed {
					return fmt.Errorf("ICE related address %s was not explicitly allowed", related)
				}
			}
		}
	}
	if !foundExpected {
		return fmt.Errorf("no server-reflexive candidate matched gateway egress %s", cfg.expected)
	}
	return nil
}

func fillCandidateFields(candidate *iceCandidate) {
	if candidate.Address != "" && candidate.Type != "" {
		return
	}
	fields := strings.Fields(candidate.Candidate)
	if len(fields) < 8 || !strings.HasPrefix(fields[0], "candidate:") ||
		fields[6] != "typ" {
		return
	}
	if candidate.Protocol == "" {
		candidate.Protocol = strings.ToLower(fields[2])
	}
	if candidate.Address == "" {
		candidate.Address = fields[4]
	}
	if candidate.Port == 0 {
		if value, err := strconv.ParseUint(fields[5], 10, 16); err == nil {
			candidate.Port = uint16(value)
		}
	}
	if candidate.Type == "" {
		candidate.Type = fields[7]
	}
	for index := 8; index+1 < len(fields); index += 2 {
		if fields[index] == "raddr" && candidate.RelatedAddress == "" {
			candidate.RelatedAddress = fields[index+1]
		}
		if fields[index] == "rport" && candidate.RelatedPort == 0 {
			if value, err := strconv.ParseUint(
				fields[index+1], 10, 16,
			); err == nil {
				candidate.RelatedPort = uint16(value)
			}
		}
	}
}

func rtcExpression(stunURL string) (string, error) {
	encoded, err := json.Marshal(stunURL)
	if err != nil {
		return "", err
	}
	return `(async () => {
  const pc = new RTCPeerConnection({
    iceServers: [{urls: [` + string(encoded) + `]}],
    iceTransportPolicy: "all",
    iceCandidatePoolSize: 0
  });
  const candidates = [];
  const started = performance.now();
  let timer;
  try {
    const complete = new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new Error("ICE gathering timed out")), 15000);
      pc.onicecandidate = event => {
        if (event.candidate) {
          const c = event.candidate;
          candidates.push({
            candidate: c.candidate,
            address: c.address || "",
            port: c.port || 0,
            protocol: c.protocol || "",
            type: c.type || "",
            related_address: c.relatedAddress || "",
            related_port: c.relatedPort || 0
          });
        } else {
          resolve();
        }
      };
      pc.onicegatheringstatechange = () => {
        if (pc.iceGatheringState === "complete") resolve();
      };
    });
    pc.createDataChannel("winn-acceptance");
    await pc.setLocalDescription(await pc.createOffer());
    await complete;
    return {
      user_agent: navigator.userAgent,
      gathering_state: pc.iceGatheringState,
      elapsed_ms: performance.now() - started,
      candidates
    };
  } finally {
    clearTimeout(timer);
    pc.close();
  }
})()`, nil
}

type cdpClient struct {
	connection *websocket.Conn
	nextID     uint64
}

func (client *cdpClient) call(
	ctx context.Context,
	method string,
	params any,
	result any,
) error {
	client.nextID++
	id := client.nextID
	request := map[string]any{"id": id, "method": method, "params": params}
	if deadline, ok := ctx.Deadline(); ok {
		_ = client.connection.SetDeadline(deadline)
	}
	if err := websocket.JSON.Send(client.connection, request); err != nil {
		return err
	}
	for {
		var response struct {
			ID     uint64          `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := websocket.JSON.Receive(client.connection, &response); err != nil {
			return err
		}
		if response.ID != id {
			continue
		}
		if response.Error != nil {
			return fmt.Errorf("CDP %d: %s", response.Error.Code, response.Error.Message)
		}
		if result != nil {
			return json.Unmarshal(response.Result, result)
		}
		return nil
	}
}

type chromiumProcess struct {
	command  *exec.Cmd
	pgid     int
	done     chan struct{}
	mu       sync.Mutex
	err      error
	stopOnce sync.Once
	stopErr  error
}

func startChromium(
	ctx context.Context,
	browser string,
	profile string,
	stderr io.Writer,
) (*chromiumProcess, error) {
	args := []string{
		browser,
		"--headless=new",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-background-networking",
		"--disable-component-update",
		"--disable-default-apps",
		"--disable-extensions",
		"--disable-sync",
		"--metrics-recording-only",
		"--remote-allow-origins=http://localhost",
		"--remote-debugging-address=127.0.0.1",
		"--remote-debugging-port=0",
		"--user-data-dir=" + profile,
		"about:blank",
	}
	command := &exec.Cmd{
		Path: browser, Args: args, Stdout: io.Discard, Stderr: stderr,
		SysProcAttr: &syscall.SysProcAttr{Setpgid: true},
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	pgid, err := syscall.Getpgid(command.Process.Pid)
	if err != nil || pgid != command.Process.Pid {
		_ = terminateExactGroup(command.Process.Pid)
		_ = command.Process.Kill()
		_ = command.Wait()
		if err != nil {
			return nil, fmt.Errorf("resolve Chromium process group: %w", err)
		}
		return nil, errors.New("chromium did not own its dedicated process group")
	}
	process := &chromiumProcess{
		command: command, pgid: pgid, done: make(chan struct{}),
	}
	go func() {
		err := command.Wait()
		process.mu.Lock()
		process.err = err
		process.mu.Unlock()
		close(process.done)
	}()
	context.AfterFunc(ctx, func() { _ = process.stop() })
	return process, nil
}

func (process *chromiumProcess) exited() (bool, error) {
	select {
	case <-process.done:
		process.mu.Lock()
		defer process.mu.Unlock()
		return true, process.err
	default:
		return false, nil
	}
}

func (process *chromiumProcess) stop() error {
	process.stopOnce.Do(func() {
		if process.groupAlive() {
			if err := syscall.Kill(-process.pgid, syscall.SIGTERM); !errors.Is(err, syscall.ESRCH) {
				process.stopErr = err
			}
		}
		parentTimer := time.NewTimer(3 * time.Second)
		select {
		case <-process.done:
			if !parentTimer.Stop() {
				select {
				case <-parentTimer.C:
				default:
				}
			}
		case <-parentTimer.C:
			killErr := syscall.Kill(-process.pgid, syscall.SIGKILL)
			if errors.Is(killErr, syscall.ESRCH) {
				killErr = nil
			}
			process.stopErr = errors.Join(
				process.stopErr,
				killErr,
			)
			<-process.done
		}
		deadline := time.Now().Add(2 * time.Second)
		for process.groupAlive() && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		if process.groupAlive() {
			killErr := syscall.Kill(-process.pgid, syscall.SIGKILL)
			if errors.Is(killErr, syscall.ESRCH) {
				killErr = nil
			}
			time.Sleep(50 * time.Millisecond)
			if process.groupAlive() {
				process.stopErr = errors.Join(
					process.stopErr, killErr,
					errors.New("chromium process group residue remained"),
				)
			}
		}
	})
	return process.stopErr
}

func (process *chromiumProcess) groupAlive() bool {
	err := syscall.Kill(-process.pgid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func waitDevTools(
	ctx context.Context,
	profile string,
	process *chromiumProcess,
) (uint16, error) {
	root, err := os.OpenRoot(profile)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		data, readErr := root.ReadFile("DevToolsActivePort")
		if readErr == nil {
			line, _, _ := strings.Cut(string(data), "\n")
			port, parseErr := strconv.ParseUint(strings.TrimSpace(line), 10, 16)
			if parseErr != nil || port == 0 {
				return 0, errors.New("chromium emitted an invalid DevTools port")
			}
			return uint16(port), nil
		}
		if exited, exitErr := process.exited(); exited {
			return 0, fmt.Errorf("chromium exited before DevTools readiness: %w", exitErr)
		}
		select {
		case <-ctx.Done():
			return 0, context.Cause(ctx)
		case <-ticker.C:
		}
	}
}

func pageWebSocketURL(ctx context.Context, port uint16) (string, error) {
	dialer := net.Dialer{}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodGet, devToolsListURL(port), nil,
	)
	if err != nil {
		return "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("list chromium DevTools targets: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("chromium DevTools target list returned %s", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var targets []struct {
		Type      string `json:"type"`
		WebSocket string `json:"webSocketDebuggerUrl"`
	}
	if err := json.Unmarshal(body, &targets); err != nil {
		return "", err
	}
	for _, target := range targets {
		if target.Type == "page" && target.WebSocket != "" {
			return target.WebSocket, nil
		}
	}
	return "", errors.New("chromium exposed no page DevTools target")
}

func devToolsListURL(port uint16) string {
	return "http://" + net.JoinHostPort(
		"127.0.0.1", strconv.Itoa(int(port)),
	) + "/json/list"
}

func dialLoopbackWebSocket(raw string, expectedPort uint16) (*websocket.Conn, error) {
	location, err := url.Parse(raw)
	if err != nil || location.Scheme != "ws" {
		return nil, errors.New("chromium returned an invalid DevTools WebSocket URL")
	}
	host, portText, err := net.SplitHostPort(location.Host)
	if err != nil {
		return nil, fmt.Errorf(
			"chromium DevTools WebSocket host was invalid: %w", err,
		)
	}
	if !loopbackWebSocketHost(host) {
		return nil, fmt.Errorf(
			"chromium DevTools WebSocket was not loopback: %q", host,
		)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || uint16(port) != expectedPort {
		return nil, errors.New("chromium DevTools WebSocket port changed")
	}
	configuration, err := websocket.NewConfig(raw, "http://localhost")
	if err != nil {
		return nil, err
	}
	return websocket.DialConfig(configuration)
}

func loopbackWebSocketHost(host string) bool {
	if host == "localhost" {
		return true
	}
	address, err := netip.ParseAddr(host)
	return err == nil && address.IsLoopback()
}

func runCommandOutput(ctx context.Context, path string, args ...string) ([]byte, error) {
	command := &exec.Cmd{
		Path: path, Args: append([]string{path}, args...),
		SysProcAttr: &syscall.SysProcAttr{Setpgid: true},
	}
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, output.String())
	}
	pgid, err := syscall.Getpgid(command.Process.Pid)
	if err != nil || pgid != command.Process.Pid {
		_ = terminateExactGroup(command.Process.Pid)
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, errors.Join(
			errors.New("version command did not own an exact process group"),
			err,
		)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err = <-done:
	case <-ctx.Done():
		groupErr := terminateExactGroup(pgid)
		waitErr := <-done
		err = errors.Join(context.Cause(ctx), groupErr, waitErr)
	}
	if !waitProcessGroupGone(pgid, 500*time.Millisecond) {
		err = errors.Join(
			err, terminateExactGroup(pgid),
			errors.New("version command left process-group residue"),
		)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, output.String())
	}
	return output.Bytes(), nil
}

func processGroupAlive(pgid int) bool {
	err := syscall.Kill(-pgid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func waitProcessGroupGone(pgid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for processGroupAlive(pgid) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	return !processGroupAlive(pgid)
}

func terminateExactGroup(pgid int) error {
	if pgid <= 1 {
		return errors.New("refusing to signal an unsafe process group")
	}
	var result error
	if processGroupAlive(pgid) {
		if err := syscall.Kill(-pgid, syscall.SIGTERM); !errors.Is(err, syscall.ESRCH) {
			result = errors.Join(result, err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for processGroupAlive(pgid) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if processGroupAlive(pgid) {
		if err := syscall.Kill(-pgid, syscall.SIGKILL); !errors.Is(err, syscall.ESRCH) {
			result = errors.Join(result, err)
		}
	}
	deadline = time.Now().Add(time.Second)
	for processGroupAlive(pgid) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if processGroupAlive(pgid) {
		result = errors.Join(result, errors.New("process group remained after SIGKILL"))
	}
	return result
}

type limitedBuffer struct {
	data []byte
}

func (buffer *limitedBuffer) Write(value []byte) (int, error) {
	const limit = 64 << 10
	remaining := limit - len(buffer.data)
	if remaining > 0 {
		if remaining > len(value) {
			remaining = len(value)
		}
		buffer.data = append(buffer.data, value[:remaining]...)
	}
	return len(value), nil
}

func (buffer *limitedBuffer) String() string {
	return string(buffer.data)
}

func writeEvidence(path string, value evidence) error {
	if err := requireAbsoluteClean(path, "output"); err != nil {
		return err
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
		info.Mode().Perm()&0o077 != 0 {
		return errors.New("evidence parent must be a private real directory")
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return err
	}
	defer root.Close()
	file, err := root.OpenFile(
		filepath.Base(path),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0o600,
	)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	writeErr := encoder.Encode(value)
	return errors.Join(writeErr, file.Sync(), file.Close())
}

func sha256File(path string) (string, error) {
	file, err := openSecureRegular(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func secureRegularFile(path string, allowExecutable bool) (os.FileInfo, error) {
	file, err := openSecureRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("path is not a regular file")
	}
	if !allowExecutable && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("file must deny group and other access")
	}
	return info, nil
}

func openSecureRegular(path string) (*os.File, error) {
	if err := requireAbsoluteClean(path, "file"); err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	if err := requireAbsoluteClean(resolved, "resolved file"); err != nil {
		return nil, err
	}
	path = resolved
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("file parent must be a real directory")
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, err
	}
	file, openErr := root.Open(filepath.Base(path))
	closeErr := root.Close()
	if openErr != nil {
		return nil, openErr
	}
	if closeErr != nil {
		_ = file.Close()
		return nil, closeErr
	}
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, errors.New("file is not regular")
	}
	return file, nil
}

func parseAddressSet(value string) (map[netip.Addr]struct{}, error) {
	result := make(map[netip.Addr]struct{})
	if strings.TrimSpace(value) == "" {
		return result, nil
	}
	for _, part := range strings.Split(value, ",") {
		address, err := netip.ParseAddr(strings.TrimSpace(part))
		if err != nil || address.IsUnspecified() {
			return nil, fmt.Errorf("invalid address %q", part)
		}
		result[address.Unmap()] = struct{}{}
	}
	return result, nil
}

func sortedAddresses(value map[netip.Addr]struct{}) []string {
	result := make([]string, 0, len(value))
	for address := range value {
		result = append(result, address.String())
	}
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j] < result[i] {
				result[i], result[j] = result[j], result[i]
			}
		}
	}
	return result
}

func requireAbsoluteClean(path, name string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%s path must be absolute and clean", name)
	}
	return nil
}

func isChromiumVersion(value string) bool {
	return strings.Contains(value, "Chromium") ||
		strings.Contains(value, "Google Chrome") ||
		strings.Contains(value, "Chrome for Testing")
}

func lowerHex(value string, bytes int) bool {
	if len(value) != bytes*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == bytes
}
