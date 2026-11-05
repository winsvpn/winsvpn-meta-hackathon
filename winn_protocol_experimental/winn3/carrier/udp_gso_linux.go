//go:build linux || android

package carrier

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

const (
	solUDP             = 17  // SOL_UDP
	udpSegment         = 103 // UDP_SEGMENT
	gsoSegmentLimit    = 45  // 45 * 1402 = 63,090 bytes <= 65,535 max UDP payload
	gsoMinSegments     = 2
	maxUDPSuperPayload = 65535
)

// GSOBatchConn wraps a kernelBatchConn to coalesce equal-sized outbound UDP packets
// into kernel-offloaded GSO super-buffers via SOL_UDP / UDP_SEGMENT.
type GSOBatchConn struct {
	raw      kernelBatchConn
	rawConn  syscall.RawConn
	isConn   bool
	enabled  atomic.Bool

	mu       sync.Mutex
	superBuf []byte
	ctrlBuf  []byte

	TxGSOCalls    atomic.Uint64
	TxGSOSegments atomic.Uint64
	TxMMSGCalls   atomic.Uint64
	TxGSODisabled atomic.Bool
}

func wrapGSOBatchConn(raw kernelBatchConn, conn *net.UDPConn) kernelBatchConn {
	if raw == nil || conn == nil {
		return raw
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return raw
	}
	isConn := conn.RemoteAddr() != nil
	if !isConn {
		// GSO optimization targets connected carrier sockets.
		return raw
	}
	// TUNNEL-SPEED-2 Turn 9, arm X1. The phone's uplink is the only direction
	// that leaves through this UDP_SEGMENT path (the gateway's shared socket
	// is unconnected and never wrapped), and it is the only direction that
	// shows 33 to 44% receive-order inversions at the far end while the
	// downlink (plain sendmmsg) shows 1 to 4% and raw single datagrams
	// (test G) 0.006 to 0.11%. WINN3_UDP_GSO=0 keeps the plain sendmmsg path
	// so one phone build measures both arms; unset or any other value is the
	// previous behaviour exactly. The decision is logged once per socket so
	// the arm's logcat proves which path ran.
	if os.Getenv("WINN3_UDP_GSO") == "0" {
		fmt.Fprintf(os.Stderr, "winn-debug: [carrier.udp] udp gso off (WINN3_UDP_GSO=0): sendmmsg only\n")
		return raw
	}

	probed := false
	_ = rawConn.Control(func(fd uintptr) {
		if err := probeUDPSegment(int(fd)); err == nil {
			probed = true
		}
	})
	if !probed {
		return raw
	}

	gso := &GSOBatchConn{
		raw:      raw,
		rawConn:  rawConn,
		isConn:   isConn,
		superBuf: make([]byte, 0, maxUDPSuperPayload),
		ctrlBuf:  make([]byte, unix.CmsgSpace(2)),
	}
	gso.enabled.Store(true)
	fmt.Fprintf(os.Stderr, "winn-debug: [carrier.udp] udp gso on: up to %d segments per sendmsg\n", gsoSegmentLimit)
	return gso
}

// txStats reports the GSO path's counters for carrier.Stats.
func (g *GSOBatchConn) txStats() (calls, segments, batchCalls uint64, disabled bool) {
	return g.TxGSOCalls.Load(), g.TxGSOSegments.Load(), g.TxMMSGCalls.Load(), g.TxGSODisabled.Load()
}

// gsoTxStats fills the UDP carrier's transmit-path counters from the GSO
// wrapper when the socket got one. A socket that was never batch-written,
// an unconnected socket and a platform without the wrapper all report zero.
func (u *UDP) gsoTxStats(st *Stats) {
	g, ok := u.sendBatchState.get(u.conn).(*GSOBatchConn)
	if !ok || g == nil {
		return
	}
	st.TxGSOCalls, st.TxGSOSegments, st.TxBatchCalls, st.TxGSODisabled = g.txStats()
}

func probeUDPSegment(fd int) error {
	// Probe with segmentSize = 1402, then disable (0)
	if err := unix.SetsockoptInt(fd, solUDP, udpSegment, 1402); err != nil {
		return err
	}
	return unix.SetsockoptInt(fd, solUDP, udpSegment, 0)
}

func (g *GSOBatchConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	// Downlink freeze invariant: pass through directly to raw without touching.
	return g.raw.ReadBatch(ms, flags)
}

func isPermanentGSODisable(err error) bool {
	return errors.Is(err, unix.ENOPROTOOPT) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EPROTONOSUPPORT) ||
		errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, unix.EPERM) ||
		errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.EMSGSIZE) ||
		errors.Is(err, unix.EIO)
}

func (g *GSOBatchConn) WriteBatch(ms []ipv4.Message, flags int) (int, error) {
	nMsgs := len(ms)
	if nMsgs == 0 {
		return 0, nil
	}
	if !g.enabled.Load() {
		g.TxMMSGCalls.Add(1)
		return g.raw.WriteBatch(ms, flags)
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	sent := 0
	for sent < nMsgs {
		if len(ms[sent].Buffers) == 0 || len(ms[sent].Buffers[0]) == 0 {
			return sent, errors.New("empty buffer in WriteBatch")
		}
		segSize := len(ms[sent].Buffers[0])

		// Find contiguous run of equal-length packets
		run := 1
		for sent+run < nMsgs && run < gsoSegmentLimit {
			if len(ms[sent+run].Buffers) == 0 || len(ms[sent+run].Buffers[0]) != segSize {
				break
			}
			if (run+1)*segSize > maxUDPSuperPayload {
				break
			}
			run++
		}

		if run >= gsoMinSegments {
			nSent, err := g.sendGSOLocked(ms[sent:sent+run], segSize)
			if err == nil && nSent > 0 {
				sent += nSent
				continue
			}
			if err != nil && isPermanentGSODisable(err) {
				g.enabled.Store(false)
				g.TxGSODisabled.Store(true)
			}
			// On GSO failure, fall through to raw sendmmsg for remaining
		}

		// Send non-GSO prefix or remaining through raw batch writer
		end := sent + 1
		for end < nMsgs {
			if end-sent >= 32 {
				break
			}
			if g.enabled.Load() && end+1 < nMsgs && len(ms[end].Buffers) > 0 && len(ms[end+1].Buffers) > 0 &&
				len(ms[end].Buffers[0]) == len(ms[end+1].Buffers[0]) && len(ms[end].Buffers[0]) > 0 {
				break
			}
			end++
		}
		g.TxMMSGCalls.Add(1)
		n, err := g.raw.WriteBatch(ms[sent:end], flags)
		if n > 0 {
			sent += n
		}
		if err != nil {
			return sent, err
		}
		if n == 0 {
			return sent, io.ErrShortWrite
		}
	}
	return sent, nil
}

func (g *GSOBatchConn) sendGSOLocked(msgs []ipv4.Message, segSize int) (int, error) {
	g.superBuf = g.superBuf[:0]
	for i := range msgs {
		g.superBuf = append(g.superBuf, msgs[i].Buffers[0]...)
	}

	need := unix.CmsgSpace(2)
	if cap(g.ctrlBuf) < need {
		g.ctrlBuf = make([]byte, need)
	}
	g.ctrlBuf = g.ctrlBuf[:need]
	for i := range g.ctrlBuf {
		g.ctrlBuf[i] = 0
	}
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&g.ctrlBuf[0]))
	hdr.Level = solUDP
	hdr.Type = udpSegment
	hdr.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(g.ctrlBuf[unix.CmsgLen(0):], uint16(segSize))

	var (
		writtenBytes int
		sysErr       error
	)
	err := g.rawConn.Write(func(fd uintptr) bool {
		n, e := unix.SendmsgN(int(fd), g.superBuf, g.ctrlBuf, nil, 0)
		if e == syscall.EAGAIN || e == syscall.EWOULDBLOCK {
			return false
		}
		writtenBytes = n
		sysErr = e
		return true
	})
	if err != nil {
		return 0, err
	}
	if sysErr != nil {
		return 0, sysErr
	}
	if writtenBytes != len(g.superBuf) {
		return 0, io.ErrShortWrite
	}

	g.TxGSOCalls.Add(1)
	g.TxGSOSegments.Add(uint64(len(msgs)))
	return len(msgs), nil
}
