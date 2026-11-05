//go:build linux

// Command engine is a DEVICE VERIFICATION INSTRUMENT, not the Winn Protocol
// engine. It is packaged as libwinnengine.so into a throwaway debug harness APK
// so that the REAL Android host code
// (android/app/src/main/kotlin/org/winsvpn/app/WinnAndroidEngineHost.kt,
// WinnProtocolFraming.kt, WinnTunnelBridge.kt) can be executed unmodified on
// real hardware.
//
// It speaks exactly the contract the Kotlin host implements today:
//
//	argv[1] == "tunnel"
//	env WINN_ENGINE_CHANNEL=<name>, dialled as the abstract AF_UNIX name "@<name>"
//	frames: 1 byte type + 3 byte big-endian length + payload
//	HELLO(0x01) carries the config JSON and exactly one SCM_RIGHTS descriptor
//
// What it proves, and reports back in the READY status JSON:
//
//  1. the descriptor really arrived over SCM_RIGHTS;
//  2. it refers to the SAME kernel socket as the parent's, evidenced by the
//     /proc/<pid>/fd inode, the bound port, SO_COOKIE, and the socket's
//     domain/type/protocol;
//  3. SO_MARK -- the mark VpnService.protect() sets on the struct sock --
//     is readable on the received descriptor, i.e. the protection travelled;
//  4. the descriptor is usable: a real DNS query is sent out of it to a real
//     remote server and the answer is read back.
//
// After READY it acts as a minimal IPv4/UDP DNS relay so the host's tun pumps
// can be exercised with real packets. That relay is NOT the Winn protocol; it
// exists only to move real bytes through the real host datapath.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"winsvpn.local/devicecheck/engine/wirefmt"
)

const (
	typeHello         = 0x01
	typeReady         = 0x02
	typeInbound       = 0x03
	typeOutbound      = 0x04
	typeStatusRequest = 0x05
	typeStatus        = 0x06
	typeShutdown      = 0x07
	typeError         = 0x08
)

const (
	soMark     = 36 // SO_MARK
	soProtocol = 38 // SO_PROTOCOL
	soDomain   = 39 // SO_DOMAIN
	soCookie   = 57 // SO_COOKIE
)

type config struct {
	// Upstream DNS server reached over the handed-over socket.
	Upstream string `json:"upstream"`
	// Loopback host port the child sends one datagram to, so the parent can
	// observe the source port of the socket it handed over.
	EchoPort int `json:"echo_port"`
	// Address the tun's DNS server appears to have, used when rewriting relayed
	// replies back into IP packets.
	TunDNS string `json:"tun_dns"`
	Probe  string `json:"probe_name"`
	// Server the child probes from a socket IT opened itself, which carries no
	// protect mark. This is the dead-loop premise in WinnEngineTransport.kt:
	// an engine-opened socket must NOT be able to reach the network.
	BareProbe string `json:"bare_probe"`
}

type identity struct {
	Received        bool   `json:"received"`
	FD              int    `json:"fd"`
	PID             int    `json:"pid"`
	UID             int    `json:"uid"`
	ProcFDLink      string `json:"proc_fd_link"`
	Inode           string `json:"inode"`
	BoundPort       int    `json:"bound_port"`
	BoundAddr       string `json:"bound_addr"`
	Domain          int    `json:"so_domain"`
	SockType        int    `json:"so_type"`
	Protocol        int    `json:"so_protocol"`
	Mark            int    `json:"so_mark"`
	MarkErr         string `json:"so_mark_error,omitempty"`
	Cookie          uint64 `json:"so_cookie"`
	CookieErr       string `json:"so_cookie_error,omitempty"`
	EgressOK        bool   `json:"egress_ok"`
	EgressDetail    string `json:"egress_detail"`
	EgressRTTMillis int64  `json:"egress_rtt_ms"`
	EchoSent        bool   `json:"echo_sent"`
	EchoErr         string `json:"echo_error,omitempty"`
	BareOK          bool   `json:"bare_socket_reached_network"`
	BareDetail      string `json:"bare_socket_detail"`
	BareMark        int    `json:"bare_socket_mark"`
	Executable      string `json:"executable"`
	Argv            string `json:"argv"`
	Relayed         int    `json:"relayed_queries"`
	RelayErrors     int    `json:"relay_errors"`
	InboundFrames   int    `json:"inbound_frames"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "devicecheck-engine: %v\n", err)
		os.Exit(1)
	}
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "devicecheck-engine: "+format+"\n", args...)
}

func run() error {
	if len(os.Args) < 2 || os.Args[1] != "tunnel" {
		return fmt.Errorf("expected argv[1]=\"tunnel\", got %q", os.Args[1:])
	}
	name := os.Getenv("WINN_ENGINE_CHANNEL")
	if name == "" {
		return errors.New("WINN_ENGINE_CHANNEL is empty")
	}
	exe, _ := os.Executable()
	logf("start argv=%q channel=%q exe=%q pid=%d uid=%d",
		os.Args, name, exe, os.Getpid(), os.Getuid())

	chanFD, err := dialAbstract(name)
	if err != nil {
		return fmt.Errorf("dial abstract @%s: %w", name, err)
	}
	defer syscall.Close(chanFD)
	logf("connected to abstract socket @%s on fd %d", name, chanFD)

	engine := &engineState{chanFD: chanFD}
	engine.ident.Executable = exe
	engine.ident.Argv = strings.Join(os.Args, " ")
	engine.ident.PID = os.Getpid()
	engine.ident.UID = os.Getuid()

	// The HELLO frame and its SCM_RIGHTS descriptor arrive in one sendmsg, so
	// they must be collected with one recvmsg.
	frame, leftover, udpFD, err := engine.recvFirstFrame()
	if err != nil {
		engine.writeFrame(typeError, []byte("first frame: "+err.Error()))
		return err
	}
	if frame.kind != typeHello {
		err := fmt.Errorf("first frame was type 0x%02x, expected HELLO", frame.kind)
		engine.writeFrame(typeError, []byte(err.Error()))
		return err
	}

	var cfg config
	if err := json.Unmarshal(frame.payload, &cfg); err != nil {
		logf("config JSON did not parse (%v); continuing with defaults", err)
	}
	if cfg.Upstream == "" {
		cfg.Upstream = "8.8.8.8:53"
	}
	engine.cfg = cfg
	logf("HELLO received: %d config bytes, descriptor=%d", len(frame.payload), udpFD)

	engine.inspect(udpFD)
	// BEFORE READY, on purpose: the host does not start its tun pumps until
	// READY arrives, so nothing is draining the tun and a socket with no
	// protect mark has no way out. Running this after READY would let our own
	// relay answer the query and hide the result.
	engine.probeOwnSocket()
	engine.probeEgress(udpFD)
	engine.echoToParent(udpFD)

	status, _ := json.Marshal(&engine.ident)
	if err := engine.writeFrame(typeReady, status); err != nil {
		return fmt.Errorf("write READY: %w", err)
	}
	logf("READY sent: %s", string(status))

	engine.udpFD = udpFD
	return engine.serve(leftover)
}

// dialAbstract connects to a Linux abstract-namespace AF_UNIX stream socket.
// Go's SockaddrUnix turns a leading '@' into the leading NUL byte the kernel
// uses for the abstract namespace, which is what LocalServerSocket binds.
func dialAbstract(name string) (int, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return -1, err
	}
	if err := syscall.Connect(fd, &syscall.SockaddrUnix{Name: "@" + name}); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

type frame struct {
	kind    byte
	payload []byte
}

type engineState struct {
	chanFD int
	udpFD  int
	cfg    config
	ident  identity

	writeMu sync.Mutex
	udpMu   sync.Mutex
	outMu   sync.Mutex
}

// recvFirstFrame performs the single recvmsg that must collect both the HELLO
// frame and the SCM_RIGHTS descriptor. Any bytes read past the end of the frame
// are returned so the ordinary reader can continue from them.
func (e *engineState) recvFirstFrame() (frame, []byte, int, error) {
	buf := make([]byte, 128*1024)
	oob := make([]byte, syscall.CmsgSpace(4*4))
	n, oobn, _, _, err := syscall.Recvmsg(e.chanFD, buf, oob, 0)
	if err != nil {
		return frame{}, nil, -1, fmt.Errorf("recvmsg: %w", err)
	}
	if n < 4 {
		return frame{}, nil, -1, fmt.Errorf("first recvmsg returned %d bytes, need at least a 4 byte header", n)
	}

	fds, err := parseRights(oob[:oobn])
	if err != nil {
		return frame{}, nil, -1, err
	}
	if len(fds) != 1 {
		for _, extra := range fds {
			syscall.Close(extra)
		}
		return frame{}, nil, -1, fmt.Errorf("expected exactly one SCM_RIGHTS descriptor, got %d", len(fds))
	}
	udpFD := fds[0]
	e.ident.Received = true

	kind := buf[0]
	length := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
	if 4+length > n {
		// The whole frame was not in this datagram; read the rest normally.
		payload := make([]byte, length)
		copy(payload, buf[4:n])
		if _, err := io.ReadFull(&fdReader{fd: e.chanFD}, payload[n-4:]); err != nil {
			return frame{}, nil, udpFD, fmt.Errorf("read HELLO body: %w", err)
		}
		return frame{kind: kind, payload: payload}, nil, udpFD, nil
	}
	payload := make([]byte, length)
	copy(payload, buf[4:4+length])
	leftover := make([]byte, n-(4+length))
	copy(leftover, buf[4+length:n])
	return frame{kind: kind, payload: payload}, leftover, udpFD, nil
}

func parseRights(oob []byte) ([]int, error) {
	if len(oob) == 0 {
		return nil, errors.New("no ancillary data: the descriptor did not arrive")
	}
	messages, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, fmt.Errorf("parse control message: %w", err)
	}
	var out []int
	for i := range messages {
		got, err := syscall.ParseUnixRights(&messages[i])
		if err != nil {
			continue
		}
		out = append(out, got...)
	}
	return out, nil
}

// inspect records everything about the received descriptor that a reviewer can
// compare against the parent's own view of the socket it handed over.
func (e *engineState) inspect(fd int) {
	e.ident.FD = fd

	link, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		e.ident.ProcFDLink = "readlink failed: " + err.Error()
	} else {
		e.ident.ProcFDLink = link
		if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
			e.ident.Inode = link[len("socket:[") : len(link)-1]
		}
	}

	if sa, err := syscall.Getsockname(fd); err == nil {
		switch a := sa.(type) {
		case *syscall.SockaddrInet6:
			e.ident.BoundPort = a.Port
			e.ident.BoundAddr = net.IP(a.Addr[:]).String()
		case *syscall.SockaddrInet4:
			e.ident.BoundPort = a.Port
			e.ident.BoundAddr = net.IP(a.Addr[:]).String()
		}
	} else {
		e.ident.BoundAddr = "getsockname failed: " + err.Error()
	}

	e.ident.Domain, _ = syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, soDomain)
	e.ident.SockType, _ = syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
	e.ident.Protocol, _ = syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, soProtocol)

	if mark, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, soMark); err != nil {
		e.ident.MarkErr = err.Error()
	} else {
		e.ident.Mark = mark
	}

	if cookie, err := getsockoptUint64(fd, syscall.SOL_SOCKET, soCookie); err != nil {
		e.ident.CookieErr = err.Error()
	} else {
		e.ident.Cookie = cookie
	}

	logf("descriptor identity: fd=%d link=%q port=%d addr=%s domain=%d type=%d proto=%d mark=%d(%s) cookie=%d",
		fd, e.ident.ProcFDLink, e.ident.BoundPort, e.ident.BoundAddr,
		e.ident.Domain, e.ident.SockType, e.ident.Protocol,
		e.ident.Mark, e.ident.MarkErr, e.ident.Cookie)
}

func getsockoptUint64(fd, level, opt int) (uint64, error) {
	var value uint64
	length := uint32(8)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd), uintptr(level), uintptr(opt),
		uintptr(unsafe.Pointer(&value)), uintptr(unsafe.Pointer(&length)), 0,
	)
	if errno != 0 {
		return 0, errno
	}
	return value, nil
}

// probeEgress sends a real DNS query out of the handed-over descriptor to a
// real remote server. While the VPN is established and this process's uid is
// inside the tunnel, a reply can only come back if the mark VpnService.protect()
// set on the socket survived the SCM_RIGHTS transfer.
func (e *engineState) probeEgress(fd int) {
	host, port, err := wirefmt.SplitHostPort(e.cfg.Upstream)
	if err != nil {
		e.ident.EgressDetail = "bad upstream: " + err.Error()
		return
	}
	name := e.cfg.Probe
	if name == "" {
		name = "dns.google"
	}
	query := wirefmt.DNSQuery(0x5741, name)

	sa, err := sockaddrFor(fd, host, port)
	if err != nil {
		e.ident.EgressDetail = "sockaddr: " + err.Error()
		return
	}

	timeout := syscall.Timeval{Sec: 5}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout)

	started := time.Now()
	if err := syscall.Sendto(fd, query, 0, sa); err != nil {
		e.ident.EgressDetail = "sendto: " + err.Error()
		logf("egress probe sendto failed: %v", err)
		return
	}
	reply := make([]byte, 1500)
	n, _, err := syscall.Recvfrom(fd, reply, 0)
	if err != nil {
		e.ident.EgressDetail = "recvfrom: " + err.Error()
		logf("egress probe recvfrom failed: %v", err)
		return
	}
	e.ident.EgressRTTMillis = time.Since(started).Milliseconds()
	if n >= 4 && reply[0] == 0x57 && reply[1] == 0x41 {
		e.ident.EgressOK = true
		e.ident.EgressDetail = fmt.Sprintf(
			"%d byte DNS reply from %s for %s, transaction id matched", n, e.cfg.Upstream, name)
	} else {
		e.ident.EgressDetail = fmt.Sprintf("%d bytes back but transaction id did not match", n)
	}
	logf("egress probe: ok=%v %s (%d ms)", e.ident.EgressOK, e.ident.EgressDetail, e.ident.EgressRTTMillis)
}

// echoToParent sends one datagram out of the handed-over descriptor to a
// loopback port the parent is listening on, so the parent can observe the
// source port and confirm behaviourally that this is its own socket.
func (e *engineState) echoToParent(fd int) {
	if e.cfg.EchoPort <= 0 {
		return
	}
	sa, err := sockaddrFor(fd, "127.0.0.1", e.cfg.EchoPort)
	if err != nil {
		e.ident.EchoErr = err.Error()
		return
	}
	payload := []byte(fmt.Sprintf("winn-devicecheck child pid=%d fd=%d inode=%s",
		os.Getpid(), fd, e.ident.Inode))
	if err := syscall.Sendto(fd, payload, 0, sa); err != nil {
		e.ident.EchoErr = err.Error()
		logf("loopback echo failed: %v", err)
		return
	}
	e.ident.EchoSent = true
	logf("loopback echo sent to 127.0.0.1:%d", e.cfg.EchoPort)
}

// probeOwnSocket tests the premise the whole hand-off design rests on: a socket
// the engine opens for itself carries no protect mark, so with the tunnel up it
// must NOT be able to reach the network. If it can, the hand-off is not load
// bearing on this configuration and that has to be said out loud.
func (e *engineState) probeOwnSocket() {
	if e.cfg.BareProbe == "" {
		e.ident.BareDetail = "not requested"
		return
	}
	host, port, err := wirefmt.SplitHostPort(e.cfg.BareProbe)
	if err != nil {
		e.ident.BareDetail = "bad bare_probe: " + err.Error()
		return
	}
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, 0)
	if err != nil {
		e.ident.BareDetail = "socket: " + err.Error()
		return
	}
	defer syscall.Close(fd)
	e.ident.BareMark, _ = syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, soMark)

	sa, err := sockaddrFor(fd, host, port)
	if err != nil {
		e.ident.BareDetail = "sockaddr: " + err.Error()
		return
	}
	// Short, because this runs inside the host's 10s READY deadline.
	timeout := syscall.Timeval{Sec: 2}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout)
	if err := syscall.Sendto(fd, wirefmt.DNSQuery(0x4241, "dns.quad9.net"), 0, sa); err != nil {
		e.ident.BareDetail = "sendto refused: " + err.Error()
		logf("bare socket probe: sendto refused: %v", err)
		return
	}
	reply := make([]byte, 1500)
	n, _, err := syscall.Recvfrom(fd, reply, 0)
	if err != nil {
		e.ident.BareDetail = "no reply: " + err.Error()
		logf("bare socket probe: no reply (%v) -- the hand-off IS load bearing", err)
		return
	}
	e.ident.BareOK = true
	e.ident.BareDetail = fmt.Sprintf("reached %s and got %d bytes back", e.cfg.BareProbe, n)
	logf("bare socket probe: REACHED THE NETWORK with mark=%d (%d bytes)", e.ident.BareMark, n)
}

func sockaddrFor(fd int, host string, port int) (syscall.Sockaddr, error) {
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("not an IP literal: %q", host)
	}
	domain, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, soDomain)
	if err != nil {
		domain = syscall.AF_INET6
	}
	if domain == syscall.AF_INET6 {
		// A java.net.DatagramSocket on Android is a dual-stack AF_INET6 socket,
		// so an IPv4 destination has to be written as v4-mapped.
		sa := &syscall.SockaddrInet6{Port: port}
		copy(sa.Addr[:], ip.To16())
		return sa, nil
	}
	v4 := ip.To4()
	if v4 == nil {
		return nil, fmt.Errorf("%s is not an IPv4 address but the socket is AF_INET", host)
	}
	sa := &syscall.SockaddrInet4{Port: port}
	copy(sa.Addr[:], v4)
	return sa, nil
}

// ---------------------------------------------------------------------------
// frame I/O
// ---------------------------------------------------------------------------

type fdReader struct{ fd int }

func (r *fdReader) Read(p []byte) (int, error) {
	for {
		n, err := syscall.Read(r.fd, p)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, io.EOF
		}
		return n, nil
	}
}

func (e *engineState) writeFrame(kind byte, payload []byte) error {
	if len(payload) > 0xFFFFFF {
		return errors.New("payload too large")
	}
	buf := make([]byte, 4+len(payload))
	buf[0] = kind
	buf[1] = byte(len(payload) >> 16)
	buf[2] = byte(len(payload) >> 8)
	buf[3] = byte(len(payload))
	copy(buf[4:], payload)

	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	for written := 0; written < len(buf); {
		n, err := syscall.Write(e.chanFD, buf[written:])
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		written += n
	}
	return nil
}

func (e *engineState) serve(leftover []byte) error {
	var source io.Reader = &fdReader{fd: e.chanFD}
	if len(leftover) > 0 {
		source = io.MultiReader(strings.NewReader(string(leftover)), source)
	}
	reader := bufio.NewReaderSize(source, 64*1024)

	header := make([]byte, 4)
	for {
		if _, err := io.ReadFull(reader, header); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				logf("channel closed by host")
				return nil
			}
			return err
		}
		kind := header[0]
		length := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
		payload := make([]byte, length)
		if length > 0 {
			if _, err := io.ReadFull(reader, payload); err != nil {
				return err
			}
		}
		switch kind {
		case typeInbound:
			e.ident.InboundFrames++
			go e.relay(payload)
		case typeStatusRequest:
			status, _ := json.Marshal(&e.ident)
			if err := e.writeFrame(typeStatus, status); err != nil {
				return err
			}
		case typeShutdown:
			logf("SHUTDOWN received; exiting")
			return nil
		default:
			logf("ignoring frame type 0x%02x (%d bytes)", kind, length)
		}
	}
}

// ---------------------------------------------------------------------------
// minimal IPv4/UDP DNS relay, so the host's tun pumps can be exercised with
// real packets against a real remote server.
// ---------------------------------------------------------------------------

func (e *engineState) relay(packet []byte) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return
	}
	ihl := int(packet[0]&0x0F) * 4
	if len(packet) < ihl+8 || packet[9] != 17 {
		return
	}
	srcIP := packet[12:16]
	dstIP := packet[16:20]
	udp := packet[ihl:]
	srcPort := binary.BigEndian.Uint16(udp[0:2])
	dstPort := binary.BigEndian.Uint16(udp[2:4])
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if dstPort != 53 || udpLen < 8 || len(udp) < udpLen {
		return
	}
	question := udp[8:udpLen]

	host, port, err := wirefmt.SplitHostPort(e.cfg.Upstream)
	if err != nil {
		e.ident.RelayErrors++
		return
	}
	answer, err := e.roundTrip(question, host, port)
	if err != nil {
		e.ident.RelayErrors++
		logf("relay round trip failed: %v", err)
		return
	}
	e.ident.Relayed++

	reply := wirefmt.BuildUDPv4(dstIP, srcIP, dstPort, srcPort, answer)
	e.outMu.Lock()
	err = e.writeFrame(typeOutbound, reply)
	e.outMu.Unlock()
	if err != nil {
		logf("relay OUTBOUND write failed: %v", err)
		return
	}
	logf("relayed a %d byte DNS query, wrote a %d byte OUTBOUND packet", len(question), len(reply))
}

func (e *engineState) roundTrip(question []byte, host string, port int) ([]byte, error) {
	e.udpMu.Lock()
	defer e.udpMu.Unlock()

	sa, err := sockaddrFor(e.udpFD, host, port)
	if err != nil {
		return nil, err
	}
	timeout := syscall.Timeval{Sec: 5}
	_ = syscall.SetsockoptTimeval(e.udpFD, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout)
	if err := syscall.Sendto(e.udpFD, question, 0, sa); err != nil {
		return nil, fmt.Errorf("sendto: %w", err)
	}
	buf := make([]byte, 1500)
	n, _, err := syscall.Recvfrom(e.udpFD, buf, 0)
	if err != nil {
		return nil, fmt.Errorf("recvfrom: %w", err)
	}
	return buf[:n], nil
}
