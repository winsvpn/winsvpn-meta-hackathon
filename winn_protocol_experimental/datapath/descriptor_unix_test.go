//go:build unix

package datapath

import (
	"bytes"
	"net"
	"syscall"
	"testing"
	"time"
)

// borrowUDPDescriptor produces a bound UDP descriptor that NOTHING in the test
// process owns, so handing it to Open transfers ownership cleanly.
//
// (*net.UDPConn).File duplicates the descriptor into an os.File that the
// os.File owns; syscall.Dup then makes a second, unowned copy and the os.File
// is closed. Skipping that second dup and passing f.Fd() directly would leave
// the os.File finalizer holding a descriptor number the engine had already
// closed and the kernel may have reissued — a real double-close, not a
// theoretical one.
func borrowUDPDescriptor(t *testing.T) (int, *net.UDPAddr) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1), Port: 0,
	})
	if err != nil {
		t.Fatalf("listen for descriptor: %v", err)
	}
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = conn.Close()
		t.Fatal("loopback listener has no UDP address")
	}
	file, err := conn.File()
	if err != nil {
		_ = conn.Close()
		t.Fatalf("duplicate descriptor: %v", err)
	}
	_ = conn.Close()
	descriptor, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		_ = file.Close()
		t.Fatalf("dup descriptor: %v", err)
	}
	syscall.CloseOnExec(descriptor)
	if err := file.Close(); err != nil {
		t.Fatalf("release intermediate descriptor: %v", err)
	}
	return descriptor, local
}

// TestOpenAdoptsSuppliedDescriptorAndOpensNoSocket is the Android contract in
// one test: a host-supplied (in production, VpnService.protect'ed) descriptor
// is adopted, real datagrams move over it in both directions, and the engine
// never reaches its socket-creation seam.
func TestOpenAdoptsSuppliedDescriptorAndOpensNoSocket(t *testing.T) {
	attempts := withSocketOpenerGuard(t)

	adopted := 0
	originalAdopt := descriptorAdopted
	descriptorAdopted = func() { adopted++ }
	t.Cleanup(func() { descriptorAdopted = originalAdopt })

	gateway := newLoopbackGateway(t)
	descriptor, local := borrowUDPDescriptor(t)

	blob := []byte(`{"contract":"` + ContractVersion +
		`","payload":"` + PayloadAWGDatagram +
		`","carrier":"` + CarrierDirectAWG +
		`","gateway_endpoint":"` + gateway.LocalAddr().String() +
		`","session_id":"adopted-descriptor"}`)

	engine, err := Open(blob, descriptor)
	if err != nil {
		t.Fatalf("Open with descriptor %d: %v", descriptor, err)
	}
	if adopted != 1 {
		t.Fatalf("descriptor adoption ran %d times, want 1", adopted)
	}
	if engine.Status().SocketOwnedByEngine {
		t.Fatal("socket_owned_by_engine is true for an adopted descriptor")
	}
	// The adopted socket really is the one the host bound: same local port.
	if got := engine.conn.LocalAddr().String(); got != local.String() {
		t.Fatalf("engine bound %s, want the adopted socket %s", got, local)
	}

	outbound := []byte("adopted-descriptor-host-to-gateway")
	if _, err := engine.WriteInbound(outbound); err != nil {
		t.Fatalf("WriteInbound: %v", err)
	}
	buffer := make([]byte, 2048)
	_ = gateway.SetReadDeadline(time.Now().Add(5 * time.Second))
	count, from, err := gateway.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("gateway read over adopted descriptor: %v", err)
	}
	if !bytes.Equal(buffer[:count], outbound) {
		t.Fatalf("gateway got %q, want %q", buffer[:count], outbound)
	}
	if from.Port != local.Port {
		t.Fatalf("datagram arrived from port %d, want the adopted %d",
			from.Port, local.Port)
	}

	inbound := []byte("adopted-descriptor-gateway-to-host")
	if _, err := gateway.WriteToUDP(inbound, from); err != nil {
		t.Fatalf("gateway write: %v", err)
	}
	count, err = engine.ReadOutboundTimeout(buffer, 5*time.Second)
	if err != nil {
		t.Fatalf("ReadOutbound over adopted descriptor: %v", err)
	}
	if !bytes.Equal(buffer[:count], inbound) {
		t.Fatalf("ReadOutbound returned %q, want %q", buffer[:count], inbound)
	}

	if err := engine.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := attempts.Load(); got != 0 {
		t.Fatalf("%d socket-creation attempts with a supplied descriptor", got)
	}

	// Ownership transferred: after Close the host's descriptor number no
	// longer names the socket the host handed over. Either it is invalid, or
	// the kernel reissued it for something else; what must not happen is that
	// it still names a UDP socket on the original port.
	var sockaddr syscall.Sockaddr
	sockaddr, err = syscall.Getsockname(descriptor)
	if err == nil {
		if inet, ok := sockaddr.(*syscall.SockaddrInet4); ok &&
			inet.Port == local.Port {
			t.Fatalf("descriptor %d still names the adopted socket on port %d "+
				"after Close; ownership was not transferred",
				descriptor, local.Port)
		}
	}
}

func TestOpenRejectsANonSocketDescriptor(t *testing.T) {
	file, err := syscall.Open("/dev/null", syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	gateway := newLoopbackGateway(t)
	blob := []byte(`{"contract":"` + ContractVersion +
		`","payload":"` + PayloadAWGDatagram +
		`","carrier":"` + CarrierDirectAWG +
		`","gateway_endpoint":"` + gateway.LocalAddr().String() + `"}`)
	engine, err := Open(blob, file)
	if engine != nil {
		_ = engine.Close()
		t.Fatal("a non-socket descriptor produced an engine")
	}
	if err == nil {
		t.Fatal("a non-socket descriptor was accepted")
	}
	// Open consumed the descriptor either way; do not close it again here.
}

func TestOpenRejectsANegativeDescriptorThroughAdoption(t *testing.T) {
	if _, err := adoptUDPDescriptor(-1); err == nil {
		t.Fatal("adoptUDPDescriptor accepted a negative descriptor")
	}
}
