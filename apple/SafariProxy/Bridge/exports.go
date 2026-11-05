package main

/*
#include <stdint.h>
*/
import "C"
import "unsafe"

func safariText(p *C.char) string {
	if p == nil {
		return ""
	}
	return C.GoString(p)
}
func safariBytes(p unsafe.Pointer, n C.int) ([]byte, bool) {
	if n < 0 || n > 65535 || p == nil && n != 0 {
		return nil, false
	}
	return unsafe.Slice((*byte)(p), int(n)), true
}

//export SafariStackCreate
func SafariStackCreate(v4, v6 *C.char, mtu C.int) C.longlong {
	return C.longlong(safariNewStack(safariText(v4), safariText(v6), int(mtu)))
}

//export SafariStackClose
func SafariStackClose(h C.longlong) { safariCloseStack(int64(h)) }

//export SafariStackEnqueuePacket
func SafariStackEnqueuePacket(h C.longlong, p unsafe.Pointer, n C.int) C.int {
	b, ok := safariBytes(p, n)
	if !ok {
		return safariArgument
	}
	return C.int(safariEnqueue(int64(h), b))
}

//export SafariStackDequeuePacket
func SafariStackDequeuePacket(h C.longlong, p unsafe.Pointer, n, ms C.int) C.int {
	b, ok := safariBytes(p, n)
	if !ok {
		return safariArgument
	}
	return C.int(safariDequeue(int64(h), b, int(ms)))
}

//export SafariStackDialTCP
func SafariStackDialTCP(h C.longlong, ip *C.char, port, ms C.int) C.longlong {
	return C.longlong(safariDial(int64(h), safariText(ip), int(port), int(ms), false))
}

//export SafariStackDialUDP
func SafariStackDialUDP(h C.longlong, ip *C.char, port, ms C.int) C.longlong {
	return C.longlong(safariDial(int64(h), safariText(ip), int(port), int(ms), true))
}

//export SafariFlowRead
func SafariFlowRead(h C.longlong, p unsafe.Pointer, n, ms C.int) C.int {
	b, ok := safariBytes(p, n)
	if !ok {
		return safariArgument
	}
	return C.int(safariRead(int64(h), b, int(ms)))
}

//export SafariFlowWrite
func SafariFlowWrite(h C.longlong, p unsafe.Pointer, n, ms C.int) C.int {
	b, ok := safariBytes(p, n)
	if !ok {
		return safariArgument
	}
	return C.int(safariWrite(int64(h), b, int(ms)))
}

//export SafariFlowCloseWrite
func SafariFlowCloseWrite(h C.longlong) C.int { return C.int(safariCloseWrite(int64(h))) }

//export SafariFlowClose
func SafariFlowClose(h C.longlong) { safariCloseFlow(int64(h)) }
