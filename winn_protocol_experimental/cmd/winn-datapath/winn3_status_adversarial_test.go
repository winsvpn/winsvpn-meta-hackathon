package main

import (
	"strings"
	"testing"
)

// Table-driven adversarial cases for decodeWinn3Status, the Go host-side
// parser of the standalone v3 status document. The production desktop hosts
// parse the same document in C++ (ParseWinn3StatusLine); this table pins the
// same refusals so a hostile line cannot silently set promotion_ready.
//
// wantErr empty means the document must parse. A non-empty wantErr is a
// substring the refusal must contain, so deleting the guard that produces
// that substring turns the row red.
func TestDecodeWinn3StatusAdversarialTable(t *testing.T) {
	honest, err := winn3EncodeStatus(winn3Status{
		Event:          "carrying",
		Posture:        winn3PostureFull,
		PromotionReady: true,
		GateState:      "carrying",
		RxPackets:      7,
		InnerMTU:       1359,
		MessageSize:    1388,
		Plan:           []string{"udp", "tcp", "tls"},
	})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := winn3EncodeStatus(winn3Status{
		Event:          "posture",
		Posture:        winn3PostureBootstrap,
		PromotionReady: false,
		GateState:      "handshaking",
		InnerMTU:       1359,
		MessageSize:    1388,
	})
	if err != nil {
		t.Fatal(err)
	}

	type row struct {
		name     string
		input    string
		wantErr  string
		ready    bool
		wantGate string
		notGate  string
	}
	rows := []row{
		{name: "honest carrying document", input: string(honest), ready: true},
		{name: "honest bootstrap document", input: string(bootstrap)},
		{name: "trailing whitespace after one object", input: string(honest) + "  \n", ready: true},
		{name: "leading whitespace", input: "  \n" + string(bootstrap)},
		{name: "empty", input: "", wantErr: "empty document"},
		{name: "whitespace only", input: "   \n\t", wantErr: "empty document"},
		{name: "not json", input: "not json at all", wantErr: "JSON object"},
		{name: "JSON null", input: "null", wantErr: "JSON object"},
		{name: "JSON array", input: "[]", wantErr: "JSON object"},
		{name: "JSON true", input: "true", wantErr: "JSON object"},
		{name: "JSON string", input: `"posture"`, wantErr: "JSON object"},
		{name: "truncated object", input: `{"event":"posture"`, wantErr: "decode"},
		{name: "trailing comma", input: `{"event":"posture","promotion_ready":false,}`, wantErr: "decode"},
		{name: "no promotion_ready", input: `{"event":"posture"}`, wantErr: "promotion_ready is absent"},
		{name: "no event", input: `{"promotion_ready":false}`, wantErr: "event is absent"},
		{name: "event is JSON null", input: `{"event":null,"promotion_ready":false}`, wantErr: "event is empty"},
		{name: "event is empty string", input: `{"event":"","promotion_ready":false}`, wantErr: "event is empty"},
		{name: "event as number", input: `{"event":1,"promotion_ready":false}`, wantErr: "decode"},
		{name: "promotion_ready as string", input: `{"event":"posture","promotion_ready":"true"}`, wantErr: "decode"},
		{name: "promotion_ready as 1", input: `{"event":"posture","promotion_ready":1}`, wantErr: "decode"},
		{name: "promotion_ready as null", input: `{"event":"posture","promotion_ready":null}`, wantErr: "JSON boolean"},
		{name: "promotion_ready truex prefix", input: `{"event":"posture","promotion_ready":truex}`, wantErr: "decode"},
		{
			name:    "concatenated second object is an under-read and must be refused",
			input:   string(bootstrap) + `{"event":"carrying","promotion_ready":true}`,
			wantErr: "single JSON object",
		},
		{
			name:    "concatenated number after the object",
			input:   string(bootstrap) + " 1",
			wantErr: "single JSON object",
		},
		{
			name:    "duplicate promotion_ready true then false",
			input:   `{"event":"posture","promotion_ready":true,"gate_state":"carrying","rx_packets":3,"promotion_ready":false}`,
			wantErr: "duplicate JSON member",
		},
		{
			name:    "duplicate promotion_ready false then true",
			input:   `{"event":"posture","promotion_ready":false,"promotion_ready":true}`,
			wantErr: "duplicate JSON member",
		},
		{
			name:    "inner_mtu overflowing int64 is a decode error, not a wrap",
			input:   `{"event":"posture","promotion_ready":false,"inner_mtu":9223372036854775808}`,
			wantErr: "decode",
		},
		{
			name:    "inner_mtu 2^32+1500 would truncate to 1500 on a 32-bit int",
			input:   `{"event":"posture","promotion_ready":false,"inner_mtu":4294968796}`,
			wantErr: "inner_mtu",
		},
		{
			name:    "inner_mtu above the IPv4 datagram ceiling",
			input:   `{"event":"posture","promotion_ready":false,"inner_mtu":65536}`,
			wantErr: "inner_mtu",
		},
		{
			name:  "inner_mtu zero is a legal parse; the bootstrap builder refuses it",
			input: `{"event":"posture","promotion_ready":false,"inner_mtu":0}`,
		},
		{
			name:    "inner_mtu negative",
			input:   `{"event":"posture","promotion_ready":false,"inner_mtu":-1}`,
			wantErr: "inner_mtu",
		},
		{
			name:    "inner_mtu as a JSON string is a decode error",
			input:   `{"event":"posture","promotion_ready":false,"inner_mtu":"1359"}`,
			wantErr: "decode",
		},
		{
			name:    "inner_mtu as a JSON null",
			input:   `{"event":"posture","promotion_ready":false,"inner_mtu":null}`,
			wantErr: "inner_mtu is null",
		},
		{
			name:    "message_size above the IPv4 datagram ceiling",
			input:   `{"event":"posture","promotion_ready":false,"message_size":65536}`,
			wantErr: "message_size",
		},
		{
			name:    "rx_packets overflowing uint64",
			input:   `{"event":"posture","promotion_ready":false,"rx_packets":18446744073709551616}`,
			wantErr: "decode",
		},
		{
			name:  "rx_packets uint64 max is a number, not a wrap",
			input: `{"event":"posture","promotion_ready":false,"rx_packets":18446744073709551615}`,
		},
		{
			name:    "rx_packets scientific notation",
			input:   `{"event":"posture","promotion_ready":false,"rx_packets":1e2}`,
			wantErr: "decode",
		},
		{
			name:    "rx_packets fractional",
			input:   `{"event":"posture","promotion_ready":false,"rx_packets":1.5}`,
			wantErr: "decode",
		},
		{
			name:    "rx_packets negative",
			input:   `{"event":"posture","promotion_ready":false,"rx_packets":-1}`,
			wantErr: "decode",
		},
		{
			name:    "rx_packets JSON null",
			input:   `{"event":"posture","promotion_ready":false,"rx_packets":null}`,
			wantErr: "rx_packets is null",
		},
		{
			name:    "UTF-8 BOM",
			input:   "\xEF\xBB\xBF" + string(bootstrap),
			wantErr: "JSON object",
		},
		{
			name:    "document larger than maxWinn3StatusBytes",
			input:   strings.Repeat("x", maxWinn3StatusBytes+1),
			wantErr: "exceeds",
		},
		{
			name: "JSON nesting deeper than maxWinn3StatusJSONDepth",
			input: func() string {
				var b strings.Builder
				b.WriteByte('{')
				for i := 0; i < maxWinn3StatusJSONDepth; i++ {
					b.WriteString(`"x":{`)
				}
				b.WriteString(`"y":1`)
				for i := 0; i < maxWinn3StatusJSONDepth+1; i++ {
					b.WriteByte('}')
				}
				return b.String()
			}(),
			wantErr: "nesting depth",
		},
		{
			name: "JSON nesting exactly maxWinn3StatusJSONDepth still parses",
			input: func() string {
				var b strings.Builder
				b.WriteString(`{"event":"posture","promotion_ready":false,"n":`)
				for i := 0; i < maxWinn3StatusJSONDepth-1; i++ {
					b.WriteByte('{')
					if i+1 < maxWinn3StatusJSONDepth-1 {
						b.WriteString(`"n":`)
					} else {
						b.WriteString(`"y":1`)
					}
				}
				for i := 0; i < maxWinn3StatusJSONDepth-1; i++ {
					b.WriteByte('}')
				}
				b.WriteByte('}')
				return b.String()
			}(),
		},
		{
			name:    "plan longer than the known classes",
			input:   `{"event":"posture","promotion_ready":false,"plan":["udp","tcp","tls","udp"]}`,
			wantErr: "plan has 4 entries",
		},
		{
			name:    "plan as a string is a decode error",
			input:   `{"event":"posture","promotion_ready":false,"plan":"udp"}`,
			wantErr: "decode",
		},
		{
			name:    "plan as an object is a decode error",
			input:   `{"event":"posture","promotion_ready":false,"plan":{"udp":true}}`,
			wantErr: "decode",
		},
		{
			name:    "nested promotion_ready is not a top-level key",
			input:   `{"event":"posture","nested":{"promotion_ready":true,"gate_state":"carrying","rx_packets":1}}`,
			wantErr: "promotion_ready is absent",
		},
		{
			name:    "honest document wrapped in an extra object",
			input:   `{"wrapper":{"event":"posture","promotion_ready":true,"gate_state":"carrying","rx_packets":1}}`,
			wantErr: "event is absent",
		},
		{
			name:  "nested ready beside top-level false stays false",
			input: `{"event":"posture","promotion_ready":false,"nested":{"promotion_ready":true,"gate_state":"carrying","rx_packets":9}}`,
		},
		{
			name:  "unknown extra field is ignored",
			input: `{"event":"posture","promotion_ready":false,"diagnostic":"ok"}`,
		},
		{
			name:  "promotion_ready true with zero rx_packets still parses; hosts re-check",
			input: `{"event":"posture","promotion_ready":true,"gate_state":"carrying","rx_packets":0}`,
			ready: true,
		},
		{
			name:  "encoding-failure fallback the engine itself emits",
			input: `{"event":"refused","posture":"bootstrap","promotion_ready":false,"refusal":"status could not be encoded"}`,
		},
		{
			name:    "rx_packets leading zeros are not an integer",
			input:   `{"event":"posture","promotion_ready":false,"rx_packets":01}`,
			wantErr: "decode",
		},
		{
			name:  "rx_packets zero is a legal parse and is not ready",
			input: `{"event":"posture","promotion_ready":false,"gate_state":"carrying","rx_packets":0}`,
		},
		{
			name:    "gate_state as a number is not a state name",
			input:   `{"event":"posture","promotion_ready":true,"gate_state":1,"rx_packets":3}`,
			wantErr: "decode",
		},
		{
			name:    "gate_state as JSON null is not a state name",
			input:   `{"event":"posture","promotion_ready":true,"gate_state":null,"rx_packets":3}`,
			wantErr: "gate_state is not a JSON string",
		},
		{
			name:    "duplicate rx_offered is untrustworthy",
			input:   `{"event":"posture","promotion_ready":false,"rx_offered":0,"rx_offered":9}`,
			wantErr: "duplicate JSON member",
		},
		{
			name:    "rx_offered JSON null",
			input:   `{"event":"posture","promotion_ready":false,"rx_offered":null}`,
			wantErr: "rx_offered is null",
		},
		{
			name:    "rx_packets with a leading plus",
			input:   `{"event":"posture","promotion_ready":false,"rx_packets":+1}`,
			wantErr: "decode",
		},
		{
			name:    "duplicate event is untrustworthy",
			input:   `{"event":"posture","event":"carrying","promotion_ready":false}`,
			wantErr: "duplicate JSON member",
		},
		{
			name:    "rx_packets NaN is not an integer",
			input:   `{"event":"posture","promotion_ready":false,"rx_packets":NaN}`,
			wantErr: "decode",
		},
		{
			name:    "rx_packets Infinity is not an integer",
			input:   `{"event":"posture","promotion_ready":false,"rx_packets":Infinity}`,
			wantErr: "decode",
		},
		{
			name:    "unknown JSON escape in gate_state is not a state name",
			input:   `{"event":"posture","promotion_ready":true,"gate_state":"\carrying","rx_packets":7}`,
			wantErr: "decode",
		},
		{
			name:    "truncated JSON escape at end of string",
			input:   `{"event":"posture","promotion_ready":false,"gate_state":"carrying\"}`,
			wantErr: "decode",
		},
		{
			name:    "embedded NUL after the object is trailing garbage",
			input:   "{\"event\":\"posture\",\"promotion_ready\":false}\x00",
			wantErr: "single JSON object",
		},
		{
			name:    "JSON \\r in gate_state is a carriage return, not the letter r",
			input:   `{"event":"posture","promotion_ready":true,"gate_state":"ca\rrying","rx_packets":7}`,
			ready:   true,
			notGate: "carrying",
		},
		{
			name:     "JSON \\u0063 is c, so \\u0063arrying is the carrying gate",
			input:    `{"event":"posture","promotion_ready":true,"gate_state":"\u0063arrying","rx_packets":7}`,
			ready:    true,
			wantGate: "carrying",
		},
		{
			name:    "uppercase CARRYING is not the tun vocabulary token",
			input:   `{"event":"posture","promotion_ready":true,"gate_state":"CARRYING","rx_packets":7}`,
			ready:   true,
			notGate: "carrying",
		},
		{
			name:    "padded carrying is not the tun vocabulary token",
			input:   `{"event":"posture","promotion_ready":true,"gate_state":" carrying","rx_packets":7}`,
			ready:   true,
			notGate: "carrying",
		},
	}

	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("parser panicked: %v", rec)
				}
			}()
			got, err := decodeWinn3Status([]byte(r.input))
			if r.wantErr == "" {
				if err != nil {
					t.Fatalf("accepted row refused: %v", err)
				}
				if got.PromotionReady != r.ready {
					t.Fatalf("promotion_ready=%v, want %v", got.PromotionReady, r.ready)
				}
				if r.wantGate != "" && got.GateState != r.wantGate {
					t.Fatalf("gate_state=%q, want %q", got.GateState, r.wantGate)
				}
				if r.notGate != "" && got.GateState == r.notGate {
					t.Fatalf("gate_state=%q, must not equal %q", got.GateState, r.notGate)
				}
				return
			}
			if err == nil {
				t.Fatalf("hostile input was accepted: %+v", got)
			}
			if got.PromotionReady {
				t.Fatal("a refused document still reported promotion_ready")
			}
			if !strings.Contains(err.Error(), r.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), r.wantErr)
			}
		})
	}
}

// TestDecodeWinn3StatusRoundTripsTheEncoder pins that every document
// winn3EncodeStatus emits is one decodeWinn3Status accepts. A parser that
// refused the engine's own output would be an outage, not a fix.
func TestDecodeWinn3StatusRoundTripsTheEncoder(t *testing.T) {
	cases := []winn3Status{
		{Event: "sizing", Posture: winn3PostureBootstrap, InnerMTU: 1359, MessageSize: 1388},
		{Event: "posture", Posture: winn3PostureBootstrap, GateState: "handshaking", InnerMTU: 1359, MessageSize: 1388},
		{
			Event: "carrying", Posture: winn3PostureFull, PromotionReady: true,
			GateState: "carrying", RxPackets: 1, InnerMTU: 1359, MessageSize: 1388,
			Plan: []string{"udp", "tcp", "tls"}, InnerIPv6: true,
		},
		{Event: "stopped", Posture: winn3PostureBootstrap, GateState: "closed", InnerMTU: 1359, MessageSize: 1388},
		{Event: "refused", Posture: winn3PostureBootstrap, Refusal: "status could not be encoded"},
	}
	for _, want := range cases {
		encoded, err := winn3EncodeStatus(want)
		if err != nil {
			t.Fatalf("encode %s: %v", want.Event, err)
		}
		got, err := decodeWinn3Status(encoded)
		if err != nil {
			t.Fatalf("decode engine output for event %s: %v\n%s", want.Event, err, encoded)
		}
		if got.Event != want.Event || got.PromotionReady != want.PromotionReady ||
			got.Posture != want.Posture || got.RxPackets != want.RxPackets {
			t.Fatalf("round trip drifted: got %+v want %+v", got, want)
		}
	}
}
