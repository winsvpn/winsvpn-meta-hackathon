package carrier

import "testing"

func TestPathMTUExplainsDatagram(t *testing.T) {
	tests := []struct {
		name   string
		mtu    int
		msgLen int
		want   bool
	}{
		{name: "narrower path", mtu: 1280, msgLen: 1380, want: true},
		{name: "equal path", mtu: 1280, msgLen: 1280, want: false},
		{name: "wider path", mtu: 1450, msgLen: 1280, want: false},
		{name: "missing measurement", mtu: 0, msgLen: 1380, want: false},
		{name: "negative measurement", mtu: -1, msgLen: 1380, want: false},
		{name: "zero message", mtu: 1280, msgLen: 0, want: false},
		{name: "negative message", mtu: 1280, msgLen: -10, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := pathMTUExplainsDatagram(test.mtu, test.msgLen); got != test.want {
				t.Fatalf(
					"pathMTUExplainsDatagram(%d, %d) = %t, want %t",
					test.mtu,
					test.msgLen,
					got,
					test.want,
				)
			}
		})
	}
}
