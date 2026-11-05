package netlab

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"time"
)

// ErrDeviceClosed is what a Device's blocking read returns once the host has
// closed it. tun.Device deliberately has no Close: the device lifecycle is the
// host's, which is why driver.Loop.Run starts the outbound pump and does not
// wait for it.
var ErrDeviceClosed = errors.New("winn3/netlab: host device closed")

// ErrDeviceFull is what WritePacket returns when the host-side output queue
// is at capacity. It is a sentinel so a caller can distinguish a full queue
// from a closed device; the previous anonymous errors.New could not be
// errors.Is'd, and the drop counter that moved beside it was never readable.
var ErrDeviceFull = errors.New("winn3/netlab: host device output is full")

// Device stands in for utun, VpnService and WinTun.
//
// It honours the real contract rather than a convenient one: ReadPacket BLOCKS
// and unblocks only when the host closes the device. A fake that returned
// io.EOF on an empty queue would let a rig's pump exit on its own, which is
// exactly the lifecycle the loop's teardown proof turns on.
type Device struct {
	mtu int
	in  chan []byte
	out chan []byte

	closeOnce sync.Once
	closed    chan struct{}

	mu       sync.Mutex
	writeErr uint64
}

// NewDevice builds a host device with the given interface MTU.
func NewDevice(mtu int) *Device {
	return &Device{
		mtu:    mtu,
		in:     make(chan []byte, 4096),
		out:    make(chan []byte, 8192),
		closed: make(chan struct{}),
	}
}

// ReadPacket implements tun.Device.
func (d *Device) ReadPacket(buf []byte) (int, error) {
	select {
	case p := <-d.in:
		return copy(buf, p), nil
	case <-d.closed:
		return 0, ErrDeviceClosed
	}
}

// WritePacket implements tun.Device. It never blocks: the caller holds a tun
// gate read-hold, and a blocked hold wedges a teardown.
func (d *Device) WritePacket(pkt []byte) (int, error) {
	select {
	case <-d.closed:
		return 0, ErrDeviceClosed
	default:
	}
	cp := append([]byte(nil), pkt...)
	select {
	case <-d.closed:
		return 0, ErrDeviceClosed
	case d.out <- cp:
		return len(pkt), nil
	default:
		d.mu.Lock()
		d.writeErr++
		d.mu.Unlock()
		return 0, ErrDeviceFull
	}
}

// MTU implements tun.Device.
func (d *Device) MTU() int { return d.mtu }

// Close ends the blocking read, as a host tearing down an interface does.
func (d *Device) Close() { d.closeOnce.Do(func() { close(d.closed) }) }

// Offer hands a packet to the device as though the host's IP stack had
// generated it. It reports false if the device is closed or its input queue
// is full. The packet is copied: WritePacket copies because the tun pump
// reuses its buffer, and a host stack copies into the tun queue the same way.
func (d *Device) Offer(pkt []byte) bool {
	select {
	case <-d.closed:
		return false
	default:
	}
	cp := append([]byte(nil), pkt...)
	select {
	case d.in <- cp:
		return true
	case <-d.closed:
		return false
	default:
		return false
	}
}

// Take waits for one packet to be written to the host, or reports false.
func (d *Device) Take(within time.Duration) ([]byte, bool) {
	select {
	case p := <-d.out:
		return p, true
	case <-time.After(within):
		return nil, false
	}
}

// Drained reports how many packets are waiting to be taken.
func (d *Device) Drained() int { return len(d.out) }

// WriteDrops reports how many WritePacket calls hit a full output queue.
// Without this, the only evidence of those drops is an error tun wraps as
// ErrDeviceWrite and driver counts as innerRejected — a test looking at the
// device itself could not see them.
func (d *Device) WriteDrops() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.writeErr
}

// --- inner packets -----------------------------------------------------------

// V4 builds an address from bytes rather than from a dotted string, the
// convention winn3/tun and winn3/driver both use so that nothing in this tree
// contains a literal address. The inner range used by the rigs here is RFC
// 1918 and is no node this project runs.
func V4(a, b, c, d byte) netip.Addr { return netip.AddrFrom4([4]byte{a, b, c, d}) }

// IPv4Packet builds a well-formed inner IPv4 packet with a correct header
// checksum. The tun layer verifies the checksum, so a builder that got it wrong
// would make every rig here measure its own builder.
//
// The DF bit is set, which is the case that matters: an oversize packet with DF
// clear produces no path-MTU signal at all by design (winn3/tun §2.5), so a rig
// that built packets without it could not tell a working signal from a
// suppressed one.
func IPv4Packet(src, dst netip.Addr, payload []byte) []byte {
	total := 20 + len(payload)
	b := make([]byte, total)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	binary.BigEndian.PutUint16(b[4:6], 0x1234)
	b[6] = 0x40 // DF
	b[8] = 64   // TTL
	b[9] = 17   // UDP; nothing in this tree parses above the IP header
	s := src.As4()
	dd := dst.As4()
	copy(b[12:16], s[:])
	copy(b[16:20], dd[:])
	binary.BigEndian.PutUint16(b[10:12], ipv4Checksum(b[:20]))
	copy(b[20:], payload)
	return b
}

func ipv4Checksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(h[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// PayloadOf returns the bytes after the IPv4 header. A digest comparison is
// about what the tunnel carried, not about the header the rig wrote.
func PayloadOf(pkt []byte) []byte {
	if len(pkt) < 20 {
		return nil
	}
	return pkt[20:]
}

// IsICMPv4FragNeeded reports whether pkt is the inward path-MTU signal
// winn3/tun synthesises, and what next-hop MTU it names.
//
// It reads the message rather than trusting a counter, because the counter says
// a signal was emitted and this says the host would act on it: a synthesised
// ICMP message with the wrong type, the wrong code or a bad checksum is
// discarded silently by every stack, which turns the path-MTU signal into an
// invisible black hole.
func IsICMPv4FragNeeded(pkt []byte) (mtu int, ok bool) {
	if len(pkt) < 20+8 {
		return 0, false
	}
	if pkt[0]>>4 != 4 {
		return 0, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return 0, false
	}
	if pkt[9] != 1 { // ICMP
		return 0, false
	}
	icmp := pkt[ihl:]
	if icmp[0] != 3 || icmp[1] != 4 { // Destination Unreachable / Fragmentation Needed
		return 0, false
	}
	// A real stack discards a Frag Needed whose IPv4 header checksum or ICMP
	// checksum is wrong. tun.Inbound validates the IPv4 header checksum but
	// not the ICMP checksum (parseIPv4 treats proto 1 as opaque payload), so
	// this oracle is the only check that the host would actually act on the
	// signal. Returning ok for a bad checksum is how a path-MTU black hole
	// becomes an invisible one.
	if internetChecksum(pkt[:ihl]) != 0 {
		return 0, false
	}
	if internetChecksum(icmp) != 0 {
		return 0, false
	}
	return int(binary.BigEndian.Uint16(icmp[6:8])), true
}

// internetChecksum is RFC 1071. Applied to a buffer that already carries its
// correct checksum it returns 0, which is how IPv4 headers and ICMP messages
// are verified. It matches winn3/tun's checksum so a packet tun would accept
// at the IP layer is the same packet this oracle accepts at the IP layer.
func internetChecksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
