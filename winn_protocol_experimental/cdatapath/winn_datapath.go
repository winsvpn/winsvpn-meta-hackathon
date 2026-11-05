//go:build darwin

// Command cdatapath exposes the Winn Protocol v3 in-process datapath over a C
// ABI, built as a static archive.
//
//	CGO_ENABLED=1 go build -buildmode=c-archive -o libwinn_datapath.a ./cdatapath
//
// This is the iOS and macOS transport of the contract, and it deliberately
// mirrors how the reviewed AmneziaWG Go bridge already reaches Apple in this
// repository: Go compiles to libwg-go.a, an Objective-C wrapper links the
// archive and re-exports a small C surface, and Swift reaches it through the
// staged framework. Nothing here invents a fifth native strategy; it is a
// second consumer of the one Apple already uses. iOS forbids subprocesses, so
// the framed duplex protocol in ../datapath/duplex is not an option there.
//
// # Memory contract
//
// Every char* this archive returns is heap-allocated here and MUST be released
// by the caller with WinnTunnelFreeString. This matches ../cshared exactly, so
// a wrapper that already frees WinnFreeString results has nothing new to learn.
// NULL is never used to report success: functions that can fail write an
// allocated error string through an out parameter, and a NULL out value means
// no error.
//
// # Handle contract
//
// WinnTunnelCreate returns a positive int64 handle. Zero and negative values
// are never valid handles; a failure returns 0 and sets the error out
// parameter. Handles are never reused within the lifetime of the process, so a
// stale handle always fails cleanly instead of addressing a later tunnel.
//
// # Buffer contract
//
// WinnTunnelWriteInbound and WinnTunnelReadOutbound take caller-owned buffers
// and never retain them past the call. ReadOutbound returns the byte count, or
// a negative status code. The codes are stable and are the only negative values
// it can return:
//
//	-1 WINN_TUNNEL_ERR_HANDLE     no such handle
//	-2 WINN_TUNNEL_ERR_CLOSED     the tunnel is closed
//	-3 WINN_TUNNEL_ERR_TIMEOUT    timeout expired with no datagram
//	-4 WINN_TUNNEL_ERR_TOO_LARGE  buffer too small; the datagram was truncated
//	-5 WINN_TUNNEL_ERR_CARRIER    terminal carrier failure, see status JSON
//	-6 WINN_TUNNEL_ERR_ARGUMENT   a nil buffer or non-positive capacity
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"winsvpn.local/winnprotocol/datapath"
)

func main() {}

// Negative return codes for WinnTunnelWriteInbound and WinnTunnelReadOutbound.
const (
	errHandle   = -1
	errClosed   = -2
	errTimeout  = -3
	errTooLarge = -4
	errCarrier  = -5
	errArgument = -6
)

var (
	registryMu   sync.RWMutex
	registry     = map[int64]*datapath.Engine{}
	nextHandle   atomic.Int64
	deadlineZero = time.Duration(0)
)

//export WinnTunnelFreeString
func WinnTunnelFreeString(value *C.char) {
	if value != nil {
		C.free(unsafe.Pointer(value))
	}
}

// WinnTunnelContractVersion identifies the datapath contract this archive
// implements. A wrapper should compare it against the version it was written
// for before it creates a tunnel.
//
//export WinnTunnelContractVersion
func WinnTunnelContractVersion() *C.char {
	return C.CString(datapath.ContractVersion)
}

// WinnTunnelProtocolVersion is the Winn v3 connectivity contract version.
//
//export WinnTunnelProtocolVersion
func WinnTunnelProtocolVersion() *C.char {
	return C.CString(datapath.ProtocolVersion)
}

// WinnTunnelMaxDatagram is the largest datagram any configuration may permit.
// A wrapper should size its read buffer with this and never guess.
//
//export WinnTunnelMaxDatagram
func WinnTunnelMaxDatagram() C.int {
	return C.int(datapath.MaxDatagramCeiling)
}

// WinnTunnelCreate opens one datapath.
//
// configJson is the datapath configuration. udpFd is a UDP socket descriptor
// the host has already prepared; on Android it must have been through
// VpnService.protect first. Pass -1 to let the engine open its own socket,
// which it will do only if the configuration sets allow_own_socket.
//
// THE ENGINE TAKES OWNERSHIP of udpFd and closes it in WinnTunnelClose. The
// caller must not close it.
//
// Returns a positive handle, or 0 with an allocated error string in errorOut.
//
//export WinnTunnelCreate
func WinnTunnelCreate(
	configJSON *C.char,
	udpFD C.int,
	errorOut **C.char,
) C.longlong {
	if errorOut != nil {
		*errorOut = nil
	}
	if configJSON == nil {
		setError(errorOut, errors.New("winn datapath configuration is NULL"))
		return 0
	}
	engine, err := datapath.Open([]byte(C.GoString(configJSON)), int(udpFD))
	if err != nil {
		setError(errorOut, err)
		return 0
	}
	handle := nextHandle.Add(1)
	registryMu.Lock()
	registry[handle] = engine
	registryMu.Unlock()
	return C.longlong(handle)
}

// WinnTunnelWriteInbound hands one datagram from the host to the protocol.
// Returns the byte count written, or a negative code.
//
//export WinnTunnelWriteInbound
func WinnTunnelWriteInbound(
	handle C.longlong,
	buffer *C.char,
	length C.int,
) C.int {
	// winn/3 standalone tunnels live in their own registry and carry inner IP
	// rather than AmneziaWG outer datagrams. Handles are drawn from the one
	// counter, so a handle is in at most one registry and this dispatch is
	// unambiguous. See winn_datapath_winn3.go.
	if t := lookupWinn3(int64(handle)); t != nil {
		return winn3WriteInbound(t, buffer, length)
	}
	engine := lookup(int64(handle))
	if engine == nil {
		return errHandle
	}
	if buffer == nil || length <= 0 {
		return errArgument
	}
	packet := unsafe.Slice((*byte)(unsafe.Pointer(buffer)), int(length))
	written, err := engine.WriteInbound(packet)
	if err != nil {
		return writeFailureCode(err)
	}
	return C.int(written)
}

// WinnTunnelReadOutbound returns one datagram from the protocol to the host.
// timeoutMs <= 0 blocks until a datagram, a close, or a carrier failure.
//
//export WinnTunnelReadOutbound
func WinnTunnelReadOutbound(
	handle C.longlong,
	buffer *C.char,
	capacity C.int,
	timeoutMS C.int,
) C.int {
	if t := lookupWinn3(int64(handle)); t != nil {
		return winn3ReadOutbound(t, buffer, capacity, timeoutMS)
	}
	engine := lookup(int64(handle))
	if engine == nil {
		return errHandle
	}
	if buffer == nil || capacity <= 0 {
		return errArgument
	}
	packet := unsafe.Slice((*byte)(unsafe.Pointer(buffer)), int(capacity))
	timeout := deadlineZero
	if timeoutMS > 0 {
		timeout = time.Duration(timeoutMS) * time.Millisecond
	}
	count, err := engine.ReadOutboundTimeout(packet, timeout)
	if err != nil {
		return readFailureCode(err)
	}
	return C.int(count)
}

// WinnTunnelStatusJSON returns the tunnel status. The caller must free it. An
// unknown handle yields a JSON object saying so, never NULL, so a wrapper can
// always log something meaningful.
//
//export WinnTunnelStatusJSON
func WinnTunnelStatusJSON(handle C.longlong) *C.char {
	if t := lookupWinn3(int64(handle)); t != nil {
		return C.CString(t.statusJSON())
	}
	engine := lookup(int64(handle))
	if engine == nil {
		return C.CString(`{"contract":"` + datapath.ContractVersion +
			`","closed":true,"carrier_error":"unknown tunnel handle"}`)
	}
	return C.CString(engine.StatusJSON())
}

// WinnTunnelClose stops the tunnel, closes the UDP socket it owns, and retires
// the handle. It is idempotent: closing an unknown handle is not an error.
// Returns NULL on success or an allocated error string the caller must free.
//
//export WinnTunnelClose
func WinnTunnelClose(handle C.longlong) *C.char {
	winn3Mu.Lock()
	w, isWinn3 := winn3Registry[int64(handle)]
	delete(winn3Registry, int64(handle))
	winn3Mu.Unlock()
	if isWinn3 {
		if err := w.close(); err != nil {
			return C.CString(err.Error())
		}
		return nil
	}

	registryMu.Lock()
	engine, ok := registry[int64(handle)]
	delete(registry, int64(handle))
	registryMu.Unlock()
	if !ok {
		return nil
	}
	if err := engine.Close(); err != nil {
		return C.CString(err.Error())
	}
	return nil
}

func lookup(handle int64) *datapath.Engine {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return registry[handle]
}

func writeFailureCode(err error) C.int {
	switch {
	case errors.Is(err, datapath.ErrClosed):
		return errClosed
	case errors.Is(err, datapath.ErrDatagramTooLarge):
		return errTooLarge
	default:
		return errCarrier
	}
}

func readFailureCode(err error) C.int {
	switch {
	case errors.Is(err, datapath.ErrClosed):
		return errClosed
	case errors.Is(err, datapath.ErrDeadlineExceeded):
		return errTimeout
	case errors.Is(err, datapath.ErrDatagramTooLarge):
		return errTooLarge
	default:
		return errCarrier
	}
}

func setError(errorOut **C.char, err error) {
	if errorOut == nil || err == nil {
		return
	}
	*errorOut = C.CString(err.Error())
}
