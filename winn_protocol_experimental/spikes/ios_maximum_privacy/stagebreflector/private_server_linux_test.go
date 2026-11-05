//go:build linux

package stagebreflector

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

const privateLinuxHelperEnvironment = "WINN_PRIVATE_NETNS_HELPER"

// TestPrivateLinuxNetNSVethConfinement exercises the real Linux pktinfo path
// across a network-namespace boundary. It skips when iproute2 or the privileges
// needed to create an ephemeral namespace/veth pair are unavailable.
func TestPrivateLinuxNetNSVethConfinement(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root or equivalent network-namespace capability")
	}
	ipPath, err := exec.LookPath("ip")
	if err != nil {
		t.Skip("iproute2 is unavailable")
	}

	suffix := strconv.Itoa(os.Getpid() % 100000)
	namespace := "wvpns" + suffix
	hostInterface := "wvph" + suffix
	peerInterface := "wvpp" + suffix
	wrongHostInterface := "wvwh" + suffix
	wrongPeerInterface := "wvwp" + suffix
	hostAddress := "10.253.203.1"
	peerAddress := "10.253.203.2"
	wrongHostAddress := "10.253.204.1"
	wrongPeerAddress := "10.253.204.2"

	if output, commandErr := exec.Command(ipPath, "netns", "add", namespace).CombinedOutput(); commandErr != nil {
		t.Skipf("network namespace unavailable: %v (%s)", commandErr, strings.TrimSpace(string(output)))
	}
	t.Cleanup(func() {
		_ = exec.Command(ipPath, "netns", "del", namespace).Run()
		_ = exec.Command(ipPath, "link", "del", hostInterface).Run()
		_ = exec.Command(ipPath, "link", "del", wrongHostInterface).Run()
	})
	runIP := func(arguments ...string) {
		t.Helper()
		if output, commandErr := exec.Command(ipPath, arguments...).CombinedOutput(); commandErr != nil {
			t.Fatalf("ip %s: %v (%s)", strings.Join(arguments, " "), commandErr, strings.TrimSpace(string(output)))
		}
	}
	runIP("link", "add", hostInterface, "type", "veth", "peer", "name", peerInterface)
	runIP("link", "set", peerInterface, "netns", namespace)
	runIP("addr", "add", hostAddress+"/30", "dev", hostInterface)
	runIP("link", "set", hostInterface, "up")
	runIP("-n", namespace, "link", "set", "lo", "up")
	runIP("-n", namespace, "addr", "add", peerAddress+"/30", "dev", peerInterface)
	runIP("-n", namespace, "link", "set", peerInterface, "up")
	runIP("link", "add", wrongHostInterface, "type", "veth", "peer", "name", wrongPeerInterface)
	runIP("link", "set", wrongPeerInterface, "netns", namespace)
	runIP("addr", "add", wrongHostAddress+"/30", "dev", wrongHostInterface)
	runIP("link", "set", wrongHostInterface, "up")
	runIP("-n", namespace, "addr", "add", wrongPeerAddress+"/30", "dev", wrongPeerInterface)
	runIP("-n", namespace, "link", "set", wrongPeerInterface, "up")

	portProbe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	port := portProbe.LocalAddr().(*net.UDPAddr).Port
	_ = portProbe.Close()

	request := deterministicRequest()
	server, err := ListenPrivateInterfaceUDP(
		netip.AddrPortFrom(netip.MustParseAddr(hostAddress), uint16(port)).String(),
		hostInterface,
		peerAddress+"/32",
		publicKey(),
		4,
		privateClock(request.IssuedAtUnixMilliseconds),
		SystemInterfaceAddressResolver,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runClient := func(expectResponse bool) {
		t.Helper()
		command := exec.Command(
			ipPath, "netns", "exec", namespace, executable,
			"-test.run=^TestPrivateLinuxNetNSClientHelper$",
			"-test.count=1",
		)
		command.Env = append(
			os.Environ(),
			privateLinuxHelperEnvironment+"=1",
			"WINN_PRIVATE_LOCAL="+peerAddress,
			fmt.Sprintf("WINN_PRIVATE_TARGET=%s:%d", hostAddress, port),
			"WINN_PRIVATE_EXPECT_RESPONSE="+strconv.FormatBool(expectResponse),
		)
		if output, commandErr := command.CombinedOutput(); commandErr != nil {
			t.Fatalf("namespace client: %v (%s)", commandErr, strings.TrimSpace(string(output)))
		}
	}

	// Keep the exact allowed source address, but route it through the second
	// veth. This distinguishes ingress-interface confinement from source-IP
	// allowlisting.
	runIP(
		"-n", namespace, "route", "replace", hostAddress+"/32",
		"via", wrongHostAddress, "dev", wrongPeerInterface, "src", peerAddress,
	)
	wrongContext, cancelWrong := context.WithTimeout(context.Background(), time.Second)
	wrongServed := make(chan error, 1)
	go func() { wrongServed <- server.ServeOne(wrongContext) }()
	runClient(false)
	cancelWrong()
	wrongErr := <-wrongServed
	if wrongErr != nil && !errors.Is(wrongErr, ErrCancelled) {
		t.Fatalf("wrong-ingress server result: %v", wrongErr)
	}
	if server.reflector.cache.Len() != 0 {
		t.Fatal("wrong-ingress request consumed replay state")
	}
	runIP("-n", namespace, "route", "del", hostAddress+"/32")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- server.ServeOne(ctx) }()
	runClient(true)
	if serveErr := <-served; serveErr != nil {
		t.Fatalf("server: %v", serveErr)
	}
}

func TestPrivateLinuxNetNSClientHelper(t *testing.T) {
	if os.Getenv(privateLinuxHelperEnvironment) != "1" {
		t.Skip("namespace helper")
	}
	local := netip.MustParseAddr(os.Getenv("WINN_PRIVATE_LOCAL"))
	target := netip.MustParseAddrPort(os.Getenv("WINN_PRIVATE_TARGET"))
	connection, err := net.ListenUDP(
		"udp4",
		net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0)),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	expectResponse, err := strconv.ParseBool(
		os.Getenv("WINN_PRIVATE_EXPECT_RESPONSE"),
	)
	if err != nil {
		t.Fatal(err)
	}
	readTimeout := 3 * time.Second
	if !expectResponse {
		readTimeout = 500 * time.Millisecond
	}
	if err := connection.SetDeadline(time.Now().Add(readTimeout)); err != nil {
		t.Fatal(err)
	}
	request := deterministicRequest()
	encoded, err := EncodeRequest(publicKey(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.WriteToUDPAddrPort(encoded, target); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, ResponseLength)
	n, source, err := connection.ReadFromUDPAddrPort(response)
	if !expectResponse {
		if err == nil {
			t.Fatalf("wrong-ingress request received %d bytes from %s", n, source)
		}
		if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
			t.Fatalf("wrong-ingress read: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if n != ResponseLength || source != target {
		t.Fatalf("response length/source = %d/%s", n, source)
	}
	verified, err := VerifyRequest(
		encoded,
		publicKey(),
		request.IssuedAtUnixMilliseconds,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyResponseCodec(
		response,
		publicKey(),
		request,
		verified.Tag,
	); err != nil {
		t.Fatal(err)
	}
}
