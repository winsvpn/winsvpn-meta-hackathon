// Package sysconv holds the narrowing conversions this project makes when it
// hands values to the operating system, each one checked rather than asserted.
//
// Go's integer conversions are silent: uint16(70000) is 4464 and int(fd) on a
// value that does not fit is whatever the low bits say. Every such conversion in
// the privileged networking paths was written where the author could see the
// value's provenance and knew it fit — which is exactly the kind of reasoning
// that stops being true when a caller changes and no compiler notices.
//
// These helpers make the check part of the conversion. A value that does not fit
// produces an error naming what it was and what it had to be, instead of a
// plausible wrong number silently reaching a socket option or a port range.
package sysconv

import (
	"fmt"
	"math"
)

// Descriptor converts a raw file descriptor from syscall.RawConn's Control
// callback into the int the unix socket-option calls take.
//
// The callback's parameter is a uintptr purely because that is the widest thing
// a descriptor can be on any platform Go supports; on Linux the kernel returns
// a small nonnegative int and Go's netFD stores it as an int, so the round trip
// is exact for every descriptor that can actually exist. The check is here for
// the case that reasoning stops holding — a descriptor arriving from somewhere
// other than a live netFD — where the alternative is a negative or truncated
// number passed to setsockopt, which either fails confusingly or, worse,
// addresses a different descriptor.
func Descriptor(fd uintptr) (int, error) {
	if fd > uintptr(math.MaxInt) {
		return 0, fmt.Errorf(
			"file descriptor %d does not fit in an int; refusing to apply a "+
				"socket option to a truncated descriptor number", fd,
		)
	}
	descriptor := int(fd)
	if descriptor < 0 {
		return 0, fmt.Errorf("file descriptor %d is negative", descriptor)
	}
	return descriptor, nil
}

// Port converts a configured port number to the uint16 the AWG interface
// configuration uses, requiring it to be a usable listening port.
//
// Zero is excluded deliberately as well as the out-of-range values: in this
// project a zero listen port means "let the kernel choose", and the callers
// here are configuring an explicit range whose whole purpose is to be
// predictable. A silently truncated 65536 becoming 0 would therefore not fail
// loudly — it would quietly turn a pinned port into an ephemeral one.
func Port(value int) (uint16, error) {
	if value < 1 || value > math.MaxUint16 {
		return 0, fmt.Errorf(
			"port %d is outside 1..%d", value, math.MaxUint16,
		)
	}
	return uint16(value), nil
}

// FirewallMark converts a mark read back from a socket option to the uint32 the
// configuration carries, so a comparison cannot be made against a
// sign-extended or truncated value.
func FirewallMark(value int) (uint32, error) {
	if value < 0 || int64(value) > int64(math.MaxUint32) {
		return 0, fmt.Errorf(
			"firewall mark %d is outside 0..%d", value, uint32(math.MaxUint32),
		)
	}
	return uint32(value), nil
}

// SocketOptionInt converts a uint32 configuration value to the int that
// unix.SetsockoptInt takes.
//
// This is NOT a no-op, and assuming it was is the mistake this function exists
// to prevent. It is easy to reason that "int is 64 bits, so a uint32 always
// fits" — but Go's int is the platform's word size, and linux/386 and linux/arm
// have a 32-bit int. Files under a plain `//go:build linux` constraint compile
// for those targets, so on them a mark above MaxInt32 becomes a NEGATIVE int and
// setsockopt receives a value the caller never asked for. amd64 CI never sees
// it, which is precisely why it would survive.
func SocketOptionInt(value uint32) (int, error) {
	if uint64(value) > uint64(math.MaxInt) {
		return 0, fmt.Errorf(
			"socket option value %d does not fit in this platform's int "+
				"(max %d); on a 32-bit target it would be applied as a "+
				"negative number", value, math.MaxInt,
		)
	}
	return int(value), nil
}
