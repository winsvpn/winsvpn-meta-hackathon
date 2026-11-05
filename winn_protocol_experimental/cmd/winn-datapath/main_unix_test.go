//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/datapath"
	"winsvpn.local/winnprotocol/datapath/duplex"
)

// TestSubprocessAdoptsAnInheritedDescriptor is the closest in-repo analogue of
// the Android hand-off that can run on a developer machine: the parent opens
// the outer UDP socket (on Android it would call VpnService.protect on it
// here), the child inherits it as descriptor 3, and the engine is told to use
// that descriptor and nothing else. allow_own_socket stays false throughout, so
// a regression that made the engine fall back to its own socket would fail.
func TestSubprocessAdoptsAnInheritedDescriptor(t *testing.T) {
	binary := buildBinary(t)
	gateway := newGateway(t)

	carrier, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1), Port: 0,
	})
	if err != nil {
		t.Fatalf("listen carrier socket: %v", err)
	}
	carrierAddr, ok := carrier.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatal("carrier socket has no UDP address")
	}
	inherited, err := carrier.File()
	if err != nil {
		t.Fatalf("duplicate carrier socket: %v", err)
	}

	command := exec.Command(binary, "-transport", "stdio", "-udp-fd", "3")
	command.ExtraFiles = []*os.File{inherited}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	// The child holds its own duplicate now; the parent's copies would
	// otherwise steal datagrams from the socket the child is reading.
	_ = inherited.Close()
	_ = carrier.Close()
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = command.Wait()
		if stderr.Len() > 0 {
			t.Logf("winn-datapath stderr: %s", stderr.String())
		}
	})

	reader := duplex.NewReader(stdout, true)
	writer := duplex.NewWriter(stdin)
	expect := func(want duplex.Opcode) []byte {
		t.Helper()
		opcode, payload, err := reader.Read()
		if err != nil {
			t.Fatalf("expecting %s: %v (stderr: %s)", want, err, stderr.String())
		}
		if opcode != want {
			t.Fatalf("got %s (%q), want %s", opcode, payload, want)
		}
		return append([]byte(nil), payload...)
	}
	// There is no banner frame; the host speaks first.
	config := []byte(`{"contract":"` + datapath.ContractVersion +
		`","payload":"` + datapath.PayloadAWGDatagram +
		`","carrier":"` + datapath.CarrierDirectAWG +
		`","gateway_endpoint":"` + gateway.LocalAddr().String() +
		`","session_id":"inherited-descriptor"}`)
	if err := writer.Write(duplex.OpCreate, config); err != nil {
		t.Fatalf("write open: %v", err)
	}
	var ready datapath.Status
	if err := json.Unmarshal(expect(duplex.OpCreateAck), &ready); err != nil {
		t.Fatalf("decode ready: %v", err)
	}
	if ready.SocketOwnedByEngine {
		t.Fatal("engine claims to own a socket it was handed")
	}
	if ready.LocalEndpoint != carrierAddr.String() {
		t.Fatalf("engine bound %s, want the inherited %s",
			ready.LocalEndpoint, carrierAddr)
	}

	payload := []byte("inherited-descriptor-host-to-gateway")
	if err := writer.Write(duplex.OpInbound, payload); err != nil {
		t.Fatalf("write inbound: %v", err)
	}
	buffer := make([]byte, 2048)
	_ = gateway.SetReadDeadline(time.Now().Add(20 * time.Second))
	count, from, err := gateway.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("gateway read: %v (stderr: %s)", err, stderr.String())
	}
	if !bytes.Equal(buffer[:count], payload) {
		t.Fatalf("gateway got %q, want %q", buffer[:count], payload)
	}
	if from.Port != carrierAddr.Port {
		t.Fatalf("datagram arrived from port %d, want the inherited %d",
			from.Port, carrierAddr.Port)
	}

	reply := []byte("inherited-descriptor-gateway-to-host")
	if _, err := gateway.WriteToUDP(reply, from); err != nil {
		t.Fatalf("gateway write: %v", err)
	}
	if got := expect(duplex.OpOutbound); !bytes.Equal(got, reply) {
		t.Fatalf("outbound frame = %q, want %q", got, reply)
	}
}

// TestSubprocessReceivesADescriptorOverAControlSocket exercises the exact
// mechanism the Android lane needs: SCM_RIGHTS over a unix stream socket,
// carrying the protected UDP socket, with the frames flowing over the same
// socket afterwards.
func TestSubprocessReceivesADescriptorOverAControlSocket(t *testing.T) {
	binary := buildBinary(t)
	gateway := newGateway(t)

	controlPath := shortSocketPath(t)
	listener, err := net.Listen("unix", controlPath)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer func() { _ = listener.Close() }()

	carrier, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1), Port: 0,
	})
	if err != nil {
		t.Fatalf("listen carrier socket: %v", err)
	}
	carrierAddr, ok := carrier.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatal("carrier socket has no UDP address")
	}
	handOver, err := carrier.File()
	if err != nil {
		t.Fatalf("duplicate carrier socket: %v", err)
	}
	defer func() { _ = handOver.Close() }()

	command := exec.Command(binary,
		"-transport", "unix", "-control", controlPath, "-receive-fd")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = command.Wait() })

	accepted, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept control connection: %v", err)
	}
	defer func() { _ = accepted.Close() }()
	control, ok := accepted.(*net.UnixConn)
	if !ok {
		t.Fatal("accepted connection is not a unix socket")
	}

	rights := syscall.UnixRights(int(handOver.Fd()))
	if _, _, err := control.WriteMsgUnix([]byte{0}, rights, nil); err != nil {
		t.Fatalf("send descriptor: %v", err)
	}
	_ = carrier.Close()

	reader := duplex.NewReader(control, true)
	writer := duplex.NewWriter(control)
	expect := func(want duplex.Opcode) []byte {
		t.Helper()
		_ = control.SetReadDeadline(time.Now().Add(20 * time.Second))
		opcode, payload, err := reader.Read()
		if err != nil {
			t.Fatalf("expecting %s: %v (stderr: %s)", want, err, stderr.String())
		}
		if opcode != want {
			t.Fatalf("got %s (%q), want %s", opcode, payload, want)
		}
		return append([]byte(nil), payload...)
	}
	// There is no banner frame; the host speaks first.
	config := []byte(`{"contract":"` + datapath.ContractVersion +
		`","payload":"` + datapath.PayloadAWGDatagram +
		`","carrier":"` + datapath.CarrierDirectAWG +
		`","gateway_endpoint":"` + gateway.LocalAddr().String() +
		`","session_id":"scm-rights"}`)
	if err := writer.Write(duplex.OpCreate, config); err != nil {
		t.Fatalf("write open: %v", err)
	}
	var ready datapath.Status
	if err := json.Unmarshal(expect(duplex.OpCreateAck), &ready); err != nil {
		t.Fatalf("decode ready: %v", err)
	}
	if ready.SocketOwnedByEngine {
		t.Fatal("engine claims to own the socket it received over SCM_RIGHTS")
	}
	if ready.LocalEndpoint != carrierAddr.String() {
		t.Fatalf("engine bound %s, want the passed %s",
			ready.LocalEndpoint, carrierAddr)
	}

	payload := []byte("scm-rights-host-to-gateway")
	if err := writer.Write(duplex.OpInbound, payload); err != nil {
		t.Fatalf("write inbound: %v", err)
	}
	buffer := make([]byte, 2048)
	_ = gateway.SetReadDeadline(time.Now().Add(20 * time.Second))
	count, from, err := gateway.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("gateway read: %v (stderr: %s)", err, stderr.String())
	}
	if !bytes.Equal(buffer[:count], payload) {
		t.Fatalf("gateway got %q, want %q", buffer[:count], payload)
	}
	if from.Port != carrierAddr.Port {
		t.Fatalf("datagram arrived from port %d, want the passed %d",
			from.Port, carrierAddr.Port)
	}

	reply := []byte("scm-rights-gateway-to-host")
	if _, err := gateway.WriteToUDP(reply, from); err != nil {
		t.Fatalf("gateway write: %v", err)
	}
	if got := expect(duplex.OpOutbound); !bytes.Equal(got, reply) {
		t.Fatalf("outbound frame = %q, want %q", got, reply)
	}
	if err := writer.Write(duplex.OpClose, nil); err != nil {
		t.Fatalf("write close: %v", err)
	}
	if payload := expect(duplex.OpCloseAck); len(payload) != 0 {
		t.Fatalf("close-ack carried %d bytes, must be empty", len(payload))
	}
}

func TestReceiveFdAndUdpFdAreMutuallyExclusive(t *testing.T) {
	if err := run(context.Background(), []string{
		"-transport", "unix", "-control", "/nonexistent-winn-control",
		"-receive-fd", "-udp-fd", "3",
	}); err == nil {
		t.Fatal("-receive-fd with -udp-fd was accepted")
	}
}

// TestWinn1StdioStillDiesOnSIGTERM is the negative control for the desktop-v3
// signal handler. NotifyContext in main() would swallow SIGTERM while
// duplex.Serve is blocked on stdin, and the process would hang — which is
// worse than the original silent kill. winn/1 and frame mode still use the
// default Go signal death; only -winn3-profile installs a handler.
func TestWinn1StdioStillDiesOnSIGTERM(t *testing.T) {
	binary := buildBinary(t)
	cmd := exec.Command(binary)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	time.Sleep(200 * time.Millisecond)
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case waitErr := <-done:
		if waitErr == nil {
			t.Fatal("winn/1 stdio exited 0 on SIGTERM; a NotifyContext in main swallowed the signal")
		}
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("winn/1 stdio ignored SIGTERM for 2s: NotifyContext in main() with no Serve cancel hangs the process")
	}
}

// shortSocketPath keeps the unix socket path inside the sun_path limit, which
// t.TempDir() on macOS can otherwise exceed.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "winn")
	if err != nil {
		t.Fatalf("temp directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory + "/c"
}
