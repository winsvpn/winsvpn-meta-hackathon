package sysconv

import (
	_ "embed"
	"math"
	"strconv"
	"strings"
	"testing"
)

//go:embed sysconv.go
var sysconvSource string

// TestPortRejectsEverythingOutsideOneToSixtyFiveThousand pins the boundary,
// including the case that motivated the check: 65536 narrows to 0, and 0 is not
// "invalid" further down — it means "let the kernel choose an ephemeral port".
// A silent truncation there turns a pinned range into an unpredictable one
// rather than producing an error.
func TestPortRejectsEverythingOutsideOneToSixtyFiveThousand(t *testing.T) {
	for _, value := range []int{1, 1024, 41200, 65535} {
		got, err := Port(value)
		if err != nil || int(got) != value {
			t.Fatalf("Port(%d) = %d, %v", value, got, err)
		}
	}
	for _, value := range []int{0, -1, 65536, 65537, 131072, math.MaxInt} {
		if got, err := Port(value); err == nil {
			t.Fatalf(
				"Port(%d) returned %d with no error; uint16(%d) would be %d",
				value, got, value, uint16(value), // #nosec G115 -- the point
			)
		}
	}
}

// TestFirewallMarkRejectsValuesThatCannotBeAMark covers the read-back path,
// where a negative or oversized int must not silently compare equal to some
// legitimate mark.
func TestFirewallMarkRejectsValuesThatCannotBeAMark(t *testing.T) {
	// Held in a runtime int64 rather than written as a constant: on a 32-bit
	// target int(math.MaxUint32) does not compile at all, constant-folded or
	// not. That is the same portability trap this package exists for,
	// appearing in its own test.
	var maxUint32 int64 = math.MaxUint32
	accepted := []int{0, 1, 0x997a}
	if strconv.IntSize == 64 {
		accepted = append(accepted, int(maxUint32))
	}
	for _, value := range accepted {
		got, err := FirewallMark(value)
		if err != nil || uint64(got) != uint64(value) {
			t.Fatalf("FirewallMark(%d) = %d, %v", value, got, err)
		}
	}
	rejected := []int{-1, math.MinInt}
	if strconv.IntSize == 64 {
		rejected = append(rejected, int(maxUint32+1), math.MaxInt)
	}
	for _, value := range rejected {
		if got, err := FirewallMark(value); err == nil {
			t.Fatalf("FirewallMark(%d) returned %d with no error", value, got)
		}
	}
}

// TestSocketOptionIntIsMeaningfulOnBothWordSizes is the reason this helper
// exists.
//
// On a 64-bit target every uint32 fits in an int and the conversion really is a
// no-op — which is exactly why writing it as one survived review, and why an
// amd64-only test proves nothing. On linux/386 and linux/arm int is 32 bits, so
// any mark above MaxInt32 becomes NEGATIVE. The assertions are therefore keyed
// to strconv.IntSize rather than being written for the platform that happens to
// run them.
func TestSocketOptionIntIsMeaningfulOnBothWordSizes(t *testing.T) {
	t.Logf("this platform's int is %d bits", strconv.IntSize)

	// Always representable, on every target.
	for _, value := range []uint32{0, 1, 0x997a, math.MaxInt32} {
		got, err := SocketOptionInt(value)
		if err != nil || uint32(got) != value { // #nosec G115 -- checked above
			t.Fatalf("SocketOptionInt(%d) = %d, %v", value, got, err)
		}
		if got < 0 {
			t.Fatalf("SocketOptionInt(%d) produced a negative int %d", value, got)
		}
	}

	// The boundary that differs by word size.
	aboveInt32 := []uint32{math.MaxInt32 + 1, math.MaxUint32}
	for _, value := range aboveInt32 {
		got, err := SocketOptionInt(value)
		if strconv.IntSize == 32 {
			if err == nil {
				t.Fatalf(
					"SocketOptionInt(%d) returned %d on a 32-bit int; a bare "+
						"conversion would have produced %d, a negative mark",
					value, got, int32(value), // #nosec G115 -- illustrative
				)
			}
			continue
		}
		if err != nil {
			t.Fatalf(
				"SocketOptionInt(%d) failed on a 64-bit int, where it fits: %v",
				value, err,
			)
		}
		if got < 0 || uint32(got) != value { // #nosec G115 -- checked above
			t.Fatalf("SocketOptionInt(%d) = %d", value, got)
		}
	}
}

// TestDescriptorRejectsAnImpossibleDescriptor covers the uintptr narrowing.
func TestDescriptorRejectsAnImpossibleDescriptor(t *testing.T) {
	for _, value := range []uintptr{0, 3, 1024} {
		got, err := Descriptor(value)
		if err != nil || uintptr(got) != value {
			t.Fatalf("Descriptor(%d) = %d, %v", value, got, err)
		}
	}
	// ^uintptr(0) is the maximum uintptr on every platform and can never be a
	// real descriptor; as a bare int(fd) it becomes -1, which setsockopt would
	// reject confusingly rather than obviously.
	if got, err := Descriptor(^uintptr(0)); err == nil {
		t.Fatalf("Descriptor(max uintptr) returned %d with no error", got)
	}
}

// TestSocketOptionIntSourceKeepsThe32BitOverflowCheck exists because a
// runtime test keyed on strconv.IntSize cannot catch a regression on a
// 64-bit host: every uint32 fits in a 64-bit int, so deleting the MaxInt
// comparison still returns success for MaxInt32+1 and MaxUint32. That
// comparison is the whole reason SocketOptionInt exists — on linux/386 and
// linux/arm those values become a negative setsockopt argument. This test
// reads the function body so 64-bit CI cannot serve that false green.
func TestSocketOptionIntSourceKeepsThe32BitOverflowCheck(t *testing.T) {
	// embed, not os.ReadFile: ReadFile looks at the working tree, so
	// `go test -overlay` substituting a truncated sysconv.go would still
	// read the original and serve a false green. embed records the file
	// the compiler actually built.
	src := sysconvSource
	const sig = "func SocketOptionInt(value uint32) (int, error)"
	start := strings.Index(src, sig)
	if start < 0 {
		t.Fatalf("did not find %q in embedded sysconv.go", sig)
	}
	rest := src[start:]
	end := strings.Index(rest[len(sig):], "\nfunc ")
	fn := rest
	if end >= 0 {
		fn = rest[:len(sig)+end]
	}
	const needle = "uint64(value) > uint64(math.MaxInt)"
	if !strings.Contains(fn, needle) {
		t.Fatalf(
			"SocketOptionInt is missing %q; a bare int(value) is negative on linux/386 and linux/arm.\nfunction:\n%s",
			needle, fn,
		)
	}
}
