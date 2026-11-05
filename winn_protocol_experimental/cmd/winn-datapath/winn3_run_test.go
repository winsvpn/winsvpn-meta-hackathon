package main

import (
	"strings"
	"testing"
)

// TestWinn3RefuseDeviceFlagMismatch is the missing red for the function a
// sibling lane found untested: deleting it used to not go red. These are the
// two pairs that used to start the process and then either fail late
// ("tun descriptor -1 is not usable") or ignore the flag with no message.
func TestWinn3RefuseDeviceFlagMismatch(t *testing.T) {
	tunfd := winn3Profile{Device: winn3DeviceSpec{Kind: winn3DeviceTunFD}}
	err := winn3RefuseDeviceFlagMismatch(tunfd, winn3Options{tunFD: -1})
	if err == nil {
		t.Fatal("device.kind tun-fd without -winn3-tun-fd must be refused")
	}
	if !strings.Contains(err.Error(), "-winn3-tun-fd") {
		t.Fatalf("refusal %q does not name the flag", err)
	}

	if err := winn3RefuseDeviceFlagMismatch(tunfd, winn3Options{tunFD: -1, printSizing: true}); err != nil {
		t.Fatalf("-winn3-print-sizing may omit the descriptor: %v", err)
	}
	if err := winn3RefuseDeviceFlagMismatch(tunfd, winn3Options{tunFD: 4}); err != nil {
		t.Fatalf("tun-fd with a descriptor must be accepted: %v", err)
	}

	loop := winn3Profile{Device: winn3DeviceSpec{Kind: winn3DeviceLoopbackUDP}}
	err = winn3RefuseDeviceFlagMismatch(loop, winn3Options{tunFD: 3})
	if err == nil {
		t.Fatal("-winn3-tun-fd alongside loopback-udp must be refused: it used to be stored and never read")
	}
	if !strings.Contains(err.Error(), "silently ignored") {
		t.Fatalf("refusal %q does not name the silent-ignore", err)
	}
	if err := winn3RefuseDeviceFlagMismatch(loop, winn3Options{tunFD: -1}); err != nil {
		t.Fatalf("loopback-udp without a tun-fd must be accepted: %v", err)
	}
}
