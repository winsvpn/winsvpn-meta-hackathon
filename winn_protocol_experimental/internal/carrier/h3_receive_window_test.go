package carrier

import (
	"testing"

	"github.com/quic-go/quic-go"
)

func TestClientReceiveWindowsBoundDefaultsAndSuppliedConfigs(t *testing.T) {
	for _, disablePadding := range []bool{false, true} {
		for _, supplied := range []*quic.Config{nil, {
			InitialStreamReceiveWindow:     8 * 1024 * 1024,
			MaxStreamReceiveWindow:         16 * 1024 * 1024,
			InitialConnectionReceiveWindow: 16 * 1024 * 1024,
			MaxConnectionReceiveWindow:     32 * 1024 * 1024,
			Allow0RTT:                      true,
		}} {
			dialer := &H3Dialer{QUICConfig: supplied, DisableLengthPadding: disablePadding}
			got := dialer.h3QUICConfig()
			if got.InitialStreamReceiveWindow != 128*1024 || got.MaxStreamReceiveWindow != 512*1024 ||
				got.InitialConnectionReceiveWindow != 256*1024 || got.MaxConnectionReceiveWindow != 2*1024*1024 {
				t.Fatalf("unbounded client receive windows: %+v", got)
			}
			if !got.EnableDatagrams || got.Allow0RTT || got.InitialPacketSize < H3InitialPacketSize(0) {
				t.Fatal("receive window limits changed client transport invariants")
			}
			if supplied != nil && (supplied == got || supplied.MaxConnectionReceiveWindow != 32*1024*1024 || !supplied.Allow0RTT) {
				t.Fatal("client limits mutated the caller's shared configuration")
			}
		}
	}
}
