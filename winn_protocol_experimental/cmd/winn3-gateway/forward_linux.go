//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// sharedGatewayTun is the ONE real kernel TUN interface every session shares
// when -forward is enabled. See forward.go's package doc for the design this
// implements and driver.Loop.SendInner's doc for why it exists at all.
//
// # Ownership and teardown -- the fail-closed property this type leans on
//
// The descriptor below is opened WITHOUT ever calling TUNSETPERSIST. That is
// the single most load-bearing line in this file: an ordinary Linux tun
// device is destroyed by the KERNEL ITSELF the instant the last reference to
// its file descriptor closes -- ordinary exit, panic, SIGKILL, an OOM kill,
// all alike. So "teardown that leaves the host exactly as it found it" for
// the INTERFACE ITSELF is a kernel guarantee this file only has to not
// override, not a sequence of steps it has to get right under every failure
// mode. Close below is a PROMPT backstop for the graceful-shutdown path, not
// the only path to a clean state.
//
// What this guarantee does NOT cover: the sysctl and iptables state the
// install script applies (net.ipv4.ip_forward, the WINN3GW-* NAT/forward
// chains). Those are host-wide and outlive this process on purpose -- a
// gateway restart must not flap NAT for whoever else's connections are
// riding the same forwarding path -- and are reversed by the install
// script's own --teardown-forwarding, never by this binary exiting.
type sharedGatewayTun struct {
	files []*os.File
	file  *os.File
	name  string
	mtu   int

	table *forwardTable

	writeMu []sync.Mutex

	reads       atomic.Uint64
	delivered   atomic.Uint64
	unknownDest atomic.Uint64
	malformed   atomic.Uint64
	sendRefused atomic.Uint64

	// writeErrLogs bounds writeQueue's diagnostic. A kernel that refuses
	// every write (the interface deleted under the process, a driver fault)
	// refuses one per uplink packet, and an unbounded line per refusal is a
	// journal fill at line rate; forward.table.write_failed carries the count.
	writeErrLogs atomic.Uint64

	// deviceGone latches true when run gives up after
	// maxConsecutiveDeviceReadErrors. It never resets: this device is done
	// once this is true, and the process needs a restart (which rebuilds a
	// fresh interface; see the type doc) to get a working return path again.
	deviceGone atomic.Bool

	// async is nil unless enableAsyncWrites ran (-forward-async-write). See
	// forward_async.go.
	async *tunWriteQueues

	// vnetHdr is -tun-gso: every queue was opened with IFF_VNET_HDR, so every
	// read starts with a virtio_net_hdr and every write must carry one
	// (tun_gso.go). raws are the queues' raw descriptors for writev.
	vnetHdr bool
	raws    []syscall.RawConn
}

// tunOptions are the construction choices newSharedGatewayTunOpts takes.
type tunOptions struct {
	// vnetHdr opens every queue with IFF_VNET_HDR (-tun-gso). TUNSETOFFLOAD
	// is deliberately NOT called: the kernel then never hands this process
	// a segmentation-offloaded or checksum-partial packet on a read, so the
	// return path keeps its MTU-sized reads, while writes may carry
	// VIRTIO_NET_HDR_GSO_TCPV4 super packets (tun_get_user accepts those
	// whatever the device's offload features are).
	vnetHdr bool
	// queues bounds the queue count; zero means runtime.NumCPU(), as before.
	queues int
}

var (
	_ innerWriter   = (*sharedGatewayTun)(nil)
	_ trackedWriter = (*sharedGatewayTun)(nil)
)

// newSharedGatewayTun creates name EXCLUSIVELY, addresses it, sizes it to
// mtu, brings it up, and returns a handle whose return-path pump has not
// been started yet -- call run in its own goroutine once the caller's
// context exists.
//
// addr/prefixLen become "addr/prefixLen" on the interface (e.g.
// 10.64.0.1/24), which is what makes the WHOLE subnet a connected route
// through this device -- not just the gateway's own /32 -- so that however
// many distinct client inner addresses land inside it, kernel return traffic
// for any of them arrives here rather than being dropped for want of a
// route. See -forward-cidr's flag help in main.go for the coordination this
// implies with whatever assigns client inner_v4 values, which this process
// does not do and cannot see.
func newSharedGatewayTun(name string, addr netip.Addr, prefixLen, mtu int, table *forwardTable) (*sharedGatewayTun, error) {
	return newSharedGatewayTunOpts(name, addr, prefixLen, mtu, table, tunOptions{})
}

// newSharedGatewayTunOpts is newSharedGatewayTun with construction options.
func newSharedGatewayTunOpts(name string, addr netip.Addr, prefixLen, mtu int, table *forwardTable, opts tunOptions) (*sharedGatewayTun, error) {
	if !addr.Is4() {
		return nil, fmt.Errorf("gateway forwarding interface address %s is not IPv4; -forward carries IPv4 only", addr)
	}
	if prefixLen < 0 || prefixLen > 32 {
		return nil, fmt.Errorf("gateway forwarding interface prefix length %d is not 0..32", prefixLen)
	}
	if mtu <= 0 {
		return nil, fmt.Errorf("gateway forwarding interface MTU %d must be positive", mtu)
	}

	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		// The failure modes here read alike in a journal and have opposite
		// causes, so name them apart instead of offering one generic list.
		// Measured on Ubuntu 24.04 / systemd 255 (2026-08-12): the shipped
		// unit failed ENOENT and the hint below sent the operator to
		// CAP_NET_ADMIN and `lsmod`, both of which were fine, while the real
		// cause was the unit's own private /dev. That cost real debugging
		// time, which is what this switch exists to prevent.
		hint := fmt.Sprintf(
			"needs CAP_NET_ADMIN, and the host's tun kernel module: "+
				"`ip link show %s` and `lsmod | grep ^tun` are the first two things to check",
			name)
		switch {
		case errors.Is(err, unix.ENOENT):
			hint = "the node is ABSENT from this process's view of /dev, which is NOT a " +
				"permission problem -- granting a capability will not fix it. On the host, " +
				"check `ls -l /dev/net/tun` and `lsmod | grep ^tun`. If this process runs " +
				"under systemd, suspect the unit's own sandbox FIRST: PrivateDevices=yes " +
				"mounts a private /dev holding only the standard minimal node set, with no " +
				"/dev/net in it. DeviceAllow= does NOT add one -- it is a cgroup " +
				"device-controller ACL over nodes that already exist. BindPaths=/dev/net/tun " +
				"is the directive that exposes the node (keep DeviceAllow beside it; it is " +
				"what then permits access)"
		case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
			hint = "the node EXISTS but access was denied. Check CAP_NET_ADMIN first. Under " +
				"systemd also check the unit's cgroup device policy: PrivateDevices=yes " +
				"implies DevicePolicy=closed, so DeviceAllow=/dev/net/tun rw is required " +
				"alongside it or an otherwise-present node is refused"
		}
		return nil, fmt.Errorf("open /dev/net/tun: %w (%s)", err, hint)
	}
	request, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("interface name %q: %w", name, err)
	}
	numQueues := runtime.NumCPU()
	if opts.queues > 0 {
		numQueues = opts.queues
	}
	var vnet uint16
	if opts.vnetHdr {
		vnet = unix.IFF_VNET_HDR
	}
	if numQueues > maxGatewayTunQueues {
		numQueues = maxGatewayTunQueues
	}
	if numQueues < 1 {
		numQueues = 1
	}

	// Try IFF_MULTI_QUEUE first; fall back to single queue if kernel returns EINVAL.
	multiQueue := true
	request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_TUN_EXCL | unix.IFF_MULTI_QUEUE | vnet)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil {
		multiQueue = false
		request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_TUN_EXCL | vnet)
		if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil {
			_ = unix.Close(fd)
			if errors.Is(err, unix.EBUSY) || errors.Is(err, unix.EEXIST) {
				return nil, fmt.Errorf(
					"TUNSETIFF %q: an interface of this name already exists and IFF_TUN_EXCL refuses "+
						"to adopt it (check `ip link show %s` by hand before retrying): %w", name, name, err)
			}
			return nil, fmt.Errorf("TUNSETIFF %q: %w", name, err)
		}
	}
	// No TUNSETPERSIST call. See the type doc.
	// O_NONBLOCK before os.NewFile, and it is load-bearing. os.NewFile
	// classifies a BLOCKING descriptor as non-pollable, and RawConn.Read on a
	// non-pollable descriptor fails at the first park with "waiting for
	// unsupported file type" instead of waiting. runQueue's vectorised drain
	// is built on RawConn.Read, so without this the return path does not start.
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("set %s queue 0 non-blocking: %w", name, err)
	}
	files := []*os.File{os.NewFile(uintptr(fd), "/dev/net/tun")}
	if multiQueue && numQueues > 1 {
		for q := 1; q < numQueues; q++ {
			qFd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
			if err != nil {
				break
			}
			qReq, err := unix.NewIfreq(name)
			if err != nil {
				_ = unix.Close(qFd)
				break
			}
			qReq.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_MULTI_QUEUE | vnet)
			if err := unix.IoctlIfreq(qFd, unix.TUNSETIFF, qReq); err != nil {
				_ = unix.Close(qFd)
				break
			}
			if err := unix.SetNonblock(qFd, true); err != nil {
				_ = unix.Close(qFd)
				break
			}
			files = append(files, os.NewFile(uintptr(qFd), "/dev/net/tun"))
		}
	}

	cidr := fmt.Sprintf("%s/%d", addr, prefixLen)
	steps := [][]string{
		{"ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu)},
		{"ip", "addr", "add", cidr, "dev", name},
		{"ip", "link", "set", "dev", name, "txqueuelen", "10000"},
		{"ip", "link", "set", "dev", name, "up"},
	}
	for _, step := range steps {
		cmd := exec.Command(step[0], step[1:]...) //nolint:gosec // fixed argv; addr/prefixLen/mtu/name are operator-supplied flags, not attacker input
		if out, cmdErr := cmd.CombinedOutput(); cmdErr != nil {
			for _, f := range files {
				_ = f.Close()
			}
			return nil, fmt.Errorf("%v: %w: %s", step, cmdErr, out)
		}
	}

	kernelMTU, err := gatewayInterfaceMTU(name)
	if err != nil {
		for _, f := range files {
			_ = f.Close()
		}
		return nil, fmt.Errorf("read back %s's MTU: %w", name, err)
	}
	if kernelMTU != mtu {
		for _, f := range files {
			_ = f.Close()
		}
		return nil, fmt.Errorf(
			"asked the kernel for MTU %d on %s, it reports %d; refusing an interface whose MTU "+
				"does not match the plan floor rather than carry traffic sized wrong", mtu, name, kernelMTU)
	}

	s := &sharedGatewayTun{
		files:   files,
		file:    files[0],
		name:    name,
		mtu:     kernelMTU,
		table:   table,
		writeMu: make([]sync.Mutex, len(files)),
		vnetHdr: opts.vnetHdr,
	}
	if opts.vnetHdr {
		for _, f := range files {
			raw, err := f.SyscallConn()
			if err != nil {
				for _, f := range files {
					_ = f.Close()
				}
				return nil, fmt.Errorf("%s: raw descriptor for -tun-gso: %w", name, err)
			}
			s.raws = append(s.raws, raw)
		}
	}
	return s, nil
}

// gatewayInterfaceMTU reads SIOCGIFMTU for name, mirroring
// cmd/winn-datapath's winn3InterfaceMTU: the MTU this type reports is read
// back from the kernel, never merely asserted by the `ip link set mtu` call
// that was supposed to set it.
func gatewayInterfaceMTU(name string) (int, error) {
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, fmt.Errorf("open ioctl socket: %w", err)
	}
	defer func() { _ = unix.Close(sock) }()
	request, err := unix.NewIfreq(name)
	if err != nil {
		return 0, fmt.Errorf("interface name %q: %w", name, err)
	}
	if err := unix.IoctlIfreq(sock, unix.SIOCGIFMTU, request); err != nil {
		return 0, fmt.Errorf("read MTU of %q: %w", name, err)
	}
	return int(request.Uint32()), nil
}

// write sends one already-validated inner packet to the kernel.
//
// The mutex is defensive rather than load-bearing, for the reason the original
// note gives: Linux hands each write(2) on a tun character device to the
// driver as one complete packet. What changed is that ONE lock over ONE
// descriptor made every session's forward direction serialise behind every
// other session's, on a device the kernel gave us four queues for.
//
// Queue selection hashes the inner SOURCE, never round robin. Each queue is an
// independent injection point into the same netdev, so spreading one flow
// across them lets two writes land out of order, which inner TCP reads as loss
// and answers with duplicate ACKs and a halved window. Hashing the source pins
// every packet of one session to one queue and one lock, which is the ordering
// property the single descriptor had by accident and this keeps on purpose.
func (s *sharedGatewayTun) write(pkt []byte) (int, error) {
	return s.writeQueue(s.queueFor(pkt), pkt)
}

// queueFor is write's queue selection, shared with -forward-async-write so
// that both paths pin a flow to the same queue.
func (s *sharedGatewayTun) queueFor(pkt []byte) int {
	idx := 0
	if len(s.files) > 1 {
		if src, _, ok := ipv4SourceDestination(pkt); ok && src.Is4() {
			a := src.As4()
			idx = int(a[3]) % len(s.files)
			if len(pkt) >= 28 && (pkt[9] == 6 || pkt[9] == 17) {
				ihl := int(pkt[0]&0x0f) * 4
				if len(pkt) >= ihl+4 {
					srcPort := int(pkt[ihl])<<8 | int(pkt[ihl+1])
					dstPort := int(pkt[ihl+2])<<8 | int(pkt[ihl+3])
					h := int(a[3]) ^ (srcPort >> 2) ^ dstPort
					if h < 0 {
						h = -h
					}
					idx = h % len(s.files)
				}
			}
		}
	}
	return idx
}

// writeQueue writes one packet to queue idx. Under -tun-gso the descriptor
// expects a virtio_net_hdr first: a zero header (no offload asked) goes out
// with the packet in one writev, and n counts the packet bytes only.
func (s *sharedGatewayTun) writeQueue(idx int, pkt []byte) (int, error) {
	s.writeMu[idx].Lock()
	var n int
	var err error
	if s.vnetHdr {
		n, err = s.writevQueueLocked(idx, zeroVnetHdr[:], pkt)
		n = max(0, n-vnetHdrLen)
	} else {
		n, err = s.files[idx].Write(pkt)
	}
	s.writeMu[idx].Unlock()
	if err != nil {
		if c := s.writeErrLogs.Add(1); c <= maxRefusalLogs {
			fmt.Fprintf(os.Stderr, "winn3-gateway: tun write queue %d error: len=%d err=%v\n", idx, len(pkt), err)
			if c == maxRefusalLogs {
				fmt.Fprintf(os.Stderr, "winn3-gateway: further tun write errors will not be logged; see forward.table.write_failed\n")
			}
		}
		return n, fmt.Errorf("%w: %s", tun.ErrDeviceWrite, err)
	}
	return n, nil
}

// writevQueueLocked writes bufs as one TUN frame with writev on queue idx,
// parking on the poller when the descriptor is not writable. Callers hold
// writeMu[idx].
func (s *sharedGatewayTun) writevQueueLocked(idx int, bufs ...[]byte) (int, error) {
	var n int
	var werr error
	err := s.raws[idx].Write(func(fd uintptr) bool {
		n, werr = unix.Writev(int(fd), bufs)
		return !errors.Is(werr, unix.EAGAIN)
	})
	if err != nil {
		return 0, err
	}
	return n, werr
}

// writeGSOFrame writes one prebuilt frame (virtio_net_hdr plus a TCPv4 super
// packet from buildGSO) to queue idx. It reports the frame's bytes written.
func (s *sharedGatewayTun) writeGSOFrame(idx int, frame []byte) (int, error) {
	s.writeMu[idx].Lock()
	n, err := s.writevQueueLocked(idx, frame)
	s.writeMu[idx].Unlock()
	if err != nil {
		return n, fmt.Errorf("%w: %s", tun.ErrDeviceWrite, err)
	}
	return n, nil
}

// enableAsyncWrites starts one writer goroutine per queue descriptor and
// routes every later write through them (-forward-async-write). Call it once,
// before any session exists. Close stops the writers.
func (s *sharedGatewayTun) enableAsyncWrites() {
	if s.async != nil {
		return
	}
	s.async = newTunWriteQueues(len(s.files), tunWriteQueueDepth, s.mtu, s.writeQueue, func() {
		s.table.countRefusal(refusalWriteFailed)
	})
	if s.vnetHdr {
		s.async.enableGSO(s.writeGSOFrame)
	}
}

func (s *sharedGatewayTun) asyncWrites() bool { return s.async != nil }

// writeTracked queues pkt for the queue write would have used. See
// forward_async.go for the ordering, backpressure and teardown contract.
func (s *sharedGatewayTun) writeTracked(pending *atomic.Int64, pkt []byte) (int, error) {
	if s.async == nil {
		return s.write(pkt)
	}
	return s.async.submit(s.queueFor(pkt), pending, pkt)
}

// gatewayTunBatchSize bounds one vectorised drain of one queue.
// 256 matches wire-speed burst batching.
const gatewayTunBatchSize = 256

// tunQueueBatch is one queue goroutine's reusable staging. It allocates once,
// at queue start, and is never handed to another goroutine.
//
// Slots are mtu+1 bytes rather than tun.MaxIPPacket for two reasons. The
// sentinel byte means a read that somehow exceeds the interface MTU cannot
// masquerade as a valid short read, which is the same trick
// WinnV3AndroidIpPacketSeam's reader uses for the same reason. And 32 slots of
// 65535 bytes per queue is 8 MiB of resident memory across four queues to hold
// packets that can never exceed the MTU the constructor already verified
// against the kernel.
type tunQueueBatch struct {
	slotSize int
	storage  []byte
	pkts     [][]byte
	loops    []*driver.Loop
}

func newTunQueueBatch(mtu int) *tunQueueBatch {
	return newTunQueueBatchSlot(mtu + 1)
}

// newTunQueueBatchSlot is newTunQueueBatch with an explicit slot size: under
// -tun-gso each read carries a virtio_net_hdr ahead of the packet.
func newTunQueueBatchSlot(slot int) *tunQueueBatch {
	return &tunQueueBatch{
		slotSize: slot,
		storage:  make([]byte, gatewayTunBatchSize*slot),
		pkts:     make([][]byte, 0, gatewayTunBatchSize),
		loops:    make([]*driver.Loop, 0, gatewayTunBatchSize),
	}
}

func (b *tunQueueBatch) slot(i int) []byte {
	return b.storage[i*b.slotSize : (i+1)*b.slotSize]
}

// maxConsecutiveDeviceReadErrors bounds how many back-to-back Read failures
// run tolerates before it gives up on the device entirely.
//
// It exists to correct a claim an earlier version of this file's comment
// made without tracing it: that a persistently failing Read still blocks,
// so retrying without a bound is not a busy loop. That is wrong. read(2)
// blocks only while the answer is still "no data yet"; once the kernel has
// an actual errno to report :  which is exactly what "the device is gone"
// looks like, for instance an operator or a conflicting tool running
// `ip link del winn3gw0` out from under this process, or the interface
// detaching for any other reason :  every subsequent call returns
// IMMEDIATELY, forever. An unbounded retry loop around that is a
// CPU-pinning spin, not a throttled wait, and this unit has no CPUQuota to
// contain one. deviceReadErrorBackoff keeps even the bounded run from
// spinning; the bound itself is what stops it running forever.
const maxConsecutiveDeviceReadErrors = 20

// deviceReadErrorBackoff is the pause between retries once a Read has
// failed, so the bounded retry run above spends its time waiting rather
// than spinning.
const deviceReadErrorBackoff = 100 * time.Millisecond

// run reads the shared device until ctx ends or the device fails
// persistently. This IS the return path in its entirety: everything
// winn3/tun's Outbound direction would have validated and delivered for a
// point-to-point tunnel, this does instead by table lookup and
// driver.Loop.SendInner, for the reason SendInner's own doc gives. Run it in
// its own goroutine; it blocks until one of its stop conditions.
//
// A persistent failure stops ONLY this pump, not the server: every
// established session's FORWARD direction (client -> device, via
// gatewayForwardDevice.WritePacket and winn3/tun.Tunnel.Inbound, entirely
// unaffected by this method) keeps working, and DeviceGone below is this
// pump's own honest signal that the RETURN direction has stopped, which the
// status document surfaces rather than folding into Malformed: a counter
// that means "packets arrived and didn't parse" is not the same fact as "the
// interface is gone", and conflating them was the first thing wrong with
// this method before 2026-08-12's review.
func (s *sharedGatewayTun) run(ctx context.Context) {
	var wg sync.WaitGroup
	for i, f := range s.files {
		wg.Add(1)
		go func(queueIdx int, qFile *os.File) {
			defer wg.Done()
			s.runQueue(ctx, queueIdx, qFile)
		}(i, f)
	}
	wg.Wait()
}

func (s *sharedGatewayTun) runQueue(ctx context.Context, queueIdx int, qFile *os.File) {
	raw, err := qFile.SyscallConn()
	if err != nil {
		// Not a device failure and not recoverable by retrying: the descriptor
		// is not one the runtime poller will serve, so the drain below can
		// never park. Say so once and stop this queue, exactly as a persistent
		// read failure does.
		s.deviceGone.Store(true)
		fmt.Fprintf(os.Stderr,
			"winn3-gateway: %s (queue %d): descriptor is not raw-readable (%v); the return "+
				"path cannot start (forward-direction traffic is unaffected)\n",
			s.name, queueIdx, err)
		return
	}
	batch := newTunQueueBatch(s.mtu)
	if s.vnetHdr {
		batch = newTunQueueBatchSlot(s.mtu + 1 + vnetHdrLen)
	}
	var consecutive int
	for {
		if ctx.Err() != nil {
			return
		}
		n, err := s.drainQueue(raw, batch)
		// Dispatch BEFORE handling the error. A read that failed after the
		// batch already held packets must not discard them: they are valid and
		// already accounted in reads.
		if n > 0 {
			s.dispatch(batch)
			consecutive = 0
		}
		if err == nil {
			continue
		}
		if ctx.Err() != nil || errors.Is(err, os.ErrClosed) {
			return
		}
		s.malformed.Add(1)
		consecutive++
		if consecutive >= maxConsecutiveDeviceReadErrors {
			s.deviceGone.Store(true)
			fmt.Fprintf(os.Stderr,
				"winn3-gateway: %s (queue %d): %d consecutive read errors, most recently %v; giving up on "+
					"the return path (forward-direction traffic is unaffected; see forward.device_gone)\n",
				s.name, queueIdx, consecutive, err)
			return
		}
		// See maxConsecutiveDeviceReadErrors doc: a genuinely failing device
		// does not block here on its own, so this wait is load-bearing.
		select {
		case <-ctx.Done():
			return
		case <-time.After(deviceReadErrorBackoff):
		}
	}
}

// drainQueue collects every packet the queue can hand over without blocking,
// parking the goroutine on the runtime poller until at least one arrives.
//
// The read syscall is still one per packet: a tun character device delivers
// exactly one packet per read(2) and has no vectorised read. What this
// amortises is everything AROUND the syscall, which dispatch then spends once
// per run of packets instead of once per packet.
func (s *sharedGatewayTun) drainQueue(raw syscall.RawConn, batch *tunQueueBatch) (int, error) {
	batch.pkts = batch.pkts[:0]
	var readErr error
	ctrlErr := raw.Read(func(fd uintptr) bool {
		for len(batch.pkts) < gatewayTunBatchSize {
			slot := batch.slot(len(batch.pkts))
			n, err := unix.Read(int(fd), slot)
			switch {
			case errors.Is(err, unix.EINTR):
				continue
			case errors.Is(err, unix.EAGAIN):
				// Nothing more is ready. Returning false parks and retries,
				// which is only correct while the batch is still empty.
				return len(batch.pkts) > 0
			case err != nil:
				readErr = err
				return true
			}
			if n <= 0 {
				return len(batch.pkts) > 0
			}
			s.reads.Add(1)
			if s.vnetHdr {
				// No TUNSETOFFLOAD was granted, so the kernel completes
				// checksums and segments before this read: a header asking
				// for either is not a packet this path can forward.
				if n < vnetHdrLen || slot[1] != vnetHdrGSONone || slot[0]&vnetHdrFNeedsCsum != 0 {
					s.malformed.Add(1)
					continue
				}
				n -= vnetHdrLen
				slot = slot[vnetHdrLen:]
			}
			if n > s.mtu {
				// Larger than the MTU this constructor read back from the
				// kernel. The slot sentinel caught it; forwarding a truncated
				// packet would be undetectable corruption at the next layer.
				s.malformed.Add(1)
				continue
			}
			batch.pkts = append(batch.pkts, slot[:n])
		}
		return true
	})
	if ctrlErr != nil {
		return len(batch.pkts), ctrlErr
	}
	return len(batch.pkts), readErr
}

// dispatch routes one drained batch, holding each destination session's lock
// once per RUN of consecutive packets rather than once per packet.
//
// Runs, not a map. A download is one flow to one peer, so the common case is a
// single run covering the whole batch, and a mixed batch costs one extra
// SendInnerBatch per change of destination instead of an allocation per drain.
// Neither form can mis-attribute a packet: the table lookup stays per packet,
// because that lookup IS the authority SendInner's doc says the caller must be.
func (s *sharedGatewayTun) dispatch(batch *tunQueueBatch) {
	batch.loops = batch.loops[:0]
	for _, pkt := range batch.pkts {
		_, dst, ok := ipv4SourceDestination(pkt)
		if !ok {
			s.malformed.Add(1)
			batch.loops = append(batch.loops, nil)
			continue
		}
		loop, ok, capped := s.table.lookupPacketDecision(dst, len(pkt))
		if !ok {
			if !capped {
				s.unknownDest.Add(1)
			}
			batch.loops = append(batch.loops, nil)
			continue
		}
		batch.loops = append(batch.loops, loop)
	}
	for i := 0; i < len(batch.pkts); {
		loop := batch.loops[i]
		if loop == nil {
			i++
			continue
		}
		j := i + 1
		for j < len(batch.pkts) && batch.loops[j] == loop {
			j++
		}
		// SendInnerBatch copies every packet (session.Driver.EnqueueBatch
		// contract, driver.go:773), so the slots are reusable on the next
		// drain without copying first. The refusal count IS the error
		// handling here, exactly as it was for the per-packet SendInner.
		sent, _ := loop.SendInnerBatch(batch.pkts[i:j])
		if sent < j-i {
			for retry := 0; retry < 10 && sent < j-i; retry++ {
				runtime.Gosched()
				extra, _ := loop.SendInnerBatch(batch.pkts[i+sent : j])
				if extra > 0 {
					sent += extra
				}
				if sent >= j-i {
					break
				}
			}
		}
		if sent > 0 {
			s.delivered.Add(uint64(sent))
		}
		if refused := (j - i) - sent; refused > 0 {
			s.sendRefused.Add(uint64(refused))
		}
		i = j
	}
}

// Close destroys the shared interface. See the type doc: the kernel does
// this on the last close of fd regardless of whether this method ever runs,
// so this is a prompt backstop for graceful shutdown, not the only path to a
// clean state.
func (s *sharedGatewayTun) Close() error {
	// Writers first: they write to the descriptors closed below.
	if s.async != nil {
		s.async.close()
	}
	// Each descriptor is closed under its queue's write lock (revision
	// 3.3): a write already in progress finishes first, and every later
	// write, inline or synchronous, fails cleanly with os.ErrClosed instead
	// of being cut off mid-write.
	var firstErr error
	for i, f := range s.files {
		s.writeMu[i].Lock()
		err := f.Close()
		s.writeMu[i].Unlock()
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// sharedGatewayTunStats is a snapshot for the status document.
type sharedGatewayTunStats struct {
	Interface   string `json:"interface"`
	MTU         int    `json:"mtu"`
	Queues      int    `json:"queues"`
	Reads       uint64 `json:"reads"`
	Delivered   uint64 `json:"delivered"`
	UnknownDest uint64 `json:"unknown_dest"`
	Malformed   uint64 `json:"malformed"`
	SendRefused uint64 `json:"send_refused"`

	// DeviceGone is true once run has given up on the device after
	// maxConsecutiveDeviceReadErrors: the honest, distinct signal that the
	// RETURN path has stopped, separate from Malformed.
	DeviceGone bool `json:"device_gone"`

	// AsyncWrites and the embedded counters report -forward-async-write. All
	// are omitted when the flag is off, so the document is unchanged there.
	AsyncWrites bool `json:"async_writes,omitempty"`
	tunWriteQueueStats
}

func (s *sharedGatewayTun) Stats() sharedGatewayTunStats {
	return sharedGatewayTunStats{
		Interface:   s.name,
		MTU:         s.mtu,
		Queues:      len(s.files),
		Reads:       s.reads.Load(),
		Delivered:   s.delivered.Load(),
		UnknownDest: s.unknownDest.Load(),
		Malformed:   s.malformed.Load(),
		SendRefused: s.sendRefused.Load(),
		DeviceGone:  s.deviceGone.Load(),

		AsyncWrites:        s.async != nil,
		tunWriteQueueStats: s.async.stats(),
	}
}
