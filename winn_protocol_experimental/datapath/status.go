package datapath

import (
	"encoding/json"
	"runtime"
	"time"
)

// Status is the machine-readable state of one engine. Every field is either an
// observed counter or a value the caller configured; nothing here is inferred
// or optimistic.
//
// # Read this before gating route promotion on any field here
//
// Up means ONE thing: the engine is open and the carrier socket has not failed.
// It is link liveness. It is NOT evidence that a tunnel exists, that the
// gateway answered, or that anything was decrypted. A host that promotes
// default routes onto the tunnel when Up goes true is promoting on the strength
// of "a socket exists".
//
// The transfer-proven signal is TransportObservedBothWays, backed by
// RxTransportPayloadDatagrams and TxTransportPayloadDatagrams. Those move only
// when a datagram carrying the AmneziaWG transport-data header type, larger
// than a bare keepalive, crossed the carrier in that direction — inbound only
// from the configured gateway endpoint. A peer cannot produce transport-data
// messages without having completed the handshake and derived transport keys,
// so seeing them in both directions is real evidence of a working tunnel.
//
// # What this layer cannot tell you, stated plainly
//
// There is no honest "handshake completed" boolean available here, and one is
// deliberately not provided. Winn carries AmneziaWG outer datagrams opaquely:
// it holds no keys and verifies no authentication tag. Every field below is a
// header-type comparison on bytes the engine cannot decrypt. An on-path
// observer replaying an old transport datagram from the gateway's address would
// move the same counters.
//
// The AUTHORITATIVE handshake signal is the host's own AWG engine — the same
// thing "awg show <if> latest-handshakes" reports, which
// internal/directawg/status_cli.go already consumes on Linux. A correct
// route-promotion gate is the conjunction:
//
//	winn.TransportObservedBothWays  AND  hostAWGEngine.latestHandshake is recent
//
// Winn's half proves the carrier is delivering; the AWG engine's half proves
// the cryptography succeeded. Neither alone is sufficient, and this layer
// cannot supply the second.
type Status struct {
	Contract        string `json:"contract"`
	ProtocolVersion string `json:"protocol_version"`
	SessionID       string `json:"session_id,omitempty"`
	Payload         string `json:"payload"`
	Carrier         string `json:"carrier"`
	GatewayEndpoint string `json:"gateway_endpoint"`
	LocalEndpoint   string `json:"local_endpoint"`
	MaxDatagram     int    `json:"max_datagram"`
	QueueDepth      int    `json:"queue_depth"`
	QueueLength     int    `json:"queue_length"`
	GOOS            string `json:"goos"`
	GOARCH          string `json:"goarch"`

	// Up is link liveness only: open, and no terminal carrier error. See the
	// type comment before using it as a gate.
	Up bool `json:"up"`

	// SocketOwnedByEngine is false when the engine adopted a descriptor from
	// the host. On Android it MUST be false; a true here means the outer
	// socket was never protected and the tunnel will loop.
	SocketOwnedByEngine bool `json:"socket_owned_by_engine"`

	// GatewaySenderFilter reports whether the engine drops datagrams that did
	// not come from the configured gateway endpoint.
	//
	// True on direct-awg, where the transport is a bare UDP socket and the
	// filter is the only thing between an off-path sender and the host's AWG
	// engine — RxForeign counts what it rejected.
	//
	// False on a carrier, where the transport is an authenticated Winn envelope
	// over TLS 1.3 / QUIC and the peer address a carrier PacketConn reports is
	// synthetic. There the filter would reject everything, and the
	// authentication it would be duplicating is already stronger. RxForeign
	// stays at zero and means nothing in that mode.
	GatewaySenderFilter bool `json:"gateway_sender_filter"`

	OpenedAt   string `json:"opened_at"`
	UptimeMS   int64  `json:"uptime_ms"`
	Closed     bool   `json:"closed"`
	CarrierErr string `json:"carrier_error,omitempty"`

	// FirstRxAt is when the gateway first answered. Empty means never.
	FirstRxAt string `json:"first_rx_at,omitempty"`

	TxDatagrams uint64 `json:"tx_datagrams"`
	TxBytes     uint64 `json:"tx_bytes"`
	TxRejected  uint64 `json:"tx_rejected"`

	RxDatagrams uint64 `json:"rx_datagrams"`
	RxBytes     uint64 `json:"rx_bytes"`
	RxDropped   uint64 `json:"rx_dropped"`
	RxOversize  uint64 `json:"rx_oversize"`
	RxForeign   uint64 `json:"rx_foreign_sender"`

	// AWGClassification names where the header-type table came from:
	// "configured-h1h4" when the caller supplied awg_header_types, or
	// "wireguard-default-1234" when it fell back. Under AmneziaWG obfuscation
	// the fallback classifies almost nothing, so a host that sees
	// wireguard-default-1234 together with zero transport counters is looking
	// at a configuration gap, not at a dead tunnel.
	AWGClassification string `json:"awg_classification"`

	// AWGPrefixPaddingS1 through AWGPrefixPaddingS4 report the prefix padding
	// classification is actually using: the byte offset at which it looks for
	// the handshake-initiation, handshake-response, cookie-reply and
	// transport-data header word. Zero means offset 0, the unpadded WireGuard
	// layout.
	//
	// All four are reported because the only symptom of getting one wrong is a
	// counter that never moves. A host whose deployment sets S1=16 and S2=80
	// but sees zeros here is not looking at a silent gateway; it is looking at
	// a configuration that omitted s1/s2 from awg_header_types, and the
	// handshake counters below cannot fire until it supplies them.
	//
	// S4 carries the same trap and a worse consequence, which is why it is
	// reported rather than left implicit. A deployment using a nonzero
	// transport padding whose config omits s4 classifies no payload-carrying
	// transport datagram at all, so TransportObservedBothWays - the one field a
	// route-promotion gate may use - stays false on a perfectly healthy tunnel.
	// Seeing zero here against a deployment that configured a nonzero s4 is the
	// diagnosis.
	AWGPrefixPaddingS1 uint16 `json:"awg_prefix_padding_s1"`
	AWGPrefixPaddingS2 uint16 `json:"awg_prefix_padding_s2"`
	AWGPrefixPaddingS3 uint16 `json:"awg_prefix_padding_s3"`
	AWGPrefixPaddingS4 uint16 `json:"awg_prefix_padding_s4"`

	TxHandshakeInitiations     uint64 `json:"tx_handshake_initiations"`
	TxTransportDatagrams       uint64 `json:"tx_transport_datagrams"`
	TxTransportPayloadDatagram uint64 `json:"tx_transport_payload_datagrams"`

	RxHandshakeResponses       uint64 `json:"rx_handshake_responses"`
	RxTransportDatagrams       uint64 `json:"rx_transport_datagrams"`
	RxTransportPayloadDatagram uint64 `json:"rx_transport_payload_datagrams"`

	// HandshakeResponseObserved is true once a datagram from the configured
	// gateway carried the AmneziaWG handshake-response header type. It is
	// evidence the gateway is answering, not that the response verified.
	//
	// # Read this if you are looking at a false here
	//
	// A false is meaningful ONLY when AWGPrefixPaddingS1 and AWGPrefixPaddingS2
	// match the deployment's actual S1 and S2. If they are zero and the
	// deployment pads, the configuration omitted s1/s2 from awg_header_types
	// and this field cannot fire no matter what the gateway does. Check those
	// two fields before concluding anything about the gateway.
	//
	// # The defect this used to carry, and what closed it
	//
	// AmneziaWG PREPENDS S1 random bytes to a handshake initiation and S2 to a
	// handshake response. classify() read only the leading word, so under the
	// shipping profile of S1=16 and S2=80 it read random padding, returned
	// ClassUnknown, and this field together with TxHandshakeInitiations and
	// RxHandshakeResponses could never fire. Transport data is unpadded UNDER
	// THE SHIPPING PROFILE, which sets S4=0 — that is why the transport
	// counters stayed correct on the same tunnel and why the defect went
	// unnoticed. A deployment that sets S4 pads its payload-carrying transport
	// messages but not its keepalives; see AWGHeaderTypes.classify.
	//
	// It was proven by A/B on device ZY22GTV6Z3, 2026-08-03, identical runs
	// differing only in padding, both completing a real AmneziaWG handshake:
	//
	//	S1=16 S2=80  handshake completes, counters 0 / 0 / false
	//	S1=0  S2=0   handshake completes, counters 1 / 1 / true
	//
	// AWGHeaderTypes now carries S1, S2 and S3 alongside H1..H4, and classify()
	// tests each message class at its own padded offset. The three handshake
	// fields fire under the shipping profile in unit tests
	// (TestEngineCountersFireUnderTheShippingObfuscationProfile drives padded
	// frames through a real socket and requires 1 / 1 / true).
	//
	// OUTSTANDING: the device A/B has NOT been re-run. The fix is unit-proven
	// only, and on-device re-confirmation with S1=16 / S2=80 against a real
	// gateway is still owed. Until that exists, treat a true here as evidence
	// the classifier and the counters agree, not as evidence the device path
	// was re-measured.
	//
	// Still true, and unchanged by the fix: this is a header-type comparison on
	// bytes the engine cannot decrypt, and the prefix padding is not covered by
	// AmneziaWG's AEAD. It is evidence the gateway is answering, never proof
	// that anything verified. A route-promotion gate belongs on
	// TransportObservedBothWays together with the host AWG engine's own
	// handshake timestamp — see the type comment — not on this field.
	HandshakeResponseObserved bool `json:"handshake_response_observed"`

	// TransportObservedBothWays is the transfer-proven signal: at least one
	// payload-carrying transport datagram has crossed in each direction. This
	// is the field a route-promotion gate should use, together with the host
	// AWG engine's own handshake timestamp. See the type comment.
	TransportObservedBothWays bool `json:"transport_observed_both_ways"`

	// Escalation is the carrier-escalation verdict, or nil when escalation is
	// off — which is the default and what every configuration written before
	// escalation.go existed resolves to.
	//
	// A POINTER with omitempty, rather than a value, and that is the whole
	// point of the field's shape: a nil pointer emits no key at all, so the
	// status document an existing host parses is byte-for-byte what it was.
	// A value type would add "carrier_escalation":{...} with zero fields to
	// every status document in the fleet.
	Escalation *Assessment `json:"carrier_escalation,omitempty"`
}

// Status returns a snapshot. It never blocks on the datapath.
func (engine *Engine) Status() Status {
	if engine == nil {
		return Status{Contract: ContractVersion, Closed: true, Up: false}
	}
	closed := false
	select {
	case <-engine.closed:
		closed = true
	default:
	}
	local := ""
	if address := engine.conn.LocalAddr(); address != nil {
		local = address.String()
	}
	carrierErr := ""
	if held := engine.pumpErr.Load(); held != nil {
		carrierErr = (*held).Error()
	}
	classification := "wireguard-default-1234"
	if engine.headersConfigured {
		classification = "configured-h1h4"
	}
	firstRx := ""
	if nanos := engine.counters.firstRxUnixNano.Load(); nanos != 0 {
		firstRx = time.Unix(0, nanos).UTC().Format(time.RFC3339Nano)
	}
	txPayload := engine.counters.txTransportPayload.Load()
	rxPayload := engine.counters.rxTransportPayload.Load()
	var escalation *Assessment
	if assessment, assessed := engine.AssessEscalation(); assessed {
		escalation = &assessment
	}
	return Status{
		Contract:                   ContractVersion,
		ProtocolVersion:            ProtocolVersion,
		SessionID:                  engine.config.SessionID,
		Payload:                    engine.config.Payload,
		Carrier:                    engine.config.Carrier,
		GatewayEndpoint:            engine.config.GatewayEndpoint,
		LocalEndpoint:              local,
		MaxDatagram:                engine.config.MaxDatagram,
		QueueDepth:                 engine.config.QueueDepth,
		QueueLength:                len(engine.queue),
		GOOS:                       runtime.GOOS,
		GOARCH:                     runtime.GOARCH,
		Up:                         !closed && carrierErr == "",
		SocketOwnedByEngine:        engine.ownsSocket,
		GatewaySenderFilter:        engine.filterGatewaySender,
		OpenedAt:                   engine.openedAt.Format(time.RFC3339Nano),
		UptimeMS:                   time.Since(engine.openedAt).Milliseconds(),
		Closed:                     closed,
		CarrierErr:                 carrierErr,
		FirstRxAt:                  firstRx,
		TxDatagrams:                engine.counters.inboundDatagrams.Load(),
		TxBytes:                    engine.counters.inboundBytes.Load(),
		TxRejected:                 engine.counters.inboundRejected.Load(),
		RxDatagrams:                engine.counters.outboundDatagrams.Load(),
		RxBytes:                    engine.counters.outboundBytes.Load(),
		RxDropped:                  engine.counters.outboundDropped.Load(),
		RxOversize:                 engine.counters.outboundOversize.Load(),
		RxForeign:                  engine.counters.foreignSender.Load(),
		AWGClassification:          classification,
		AWGPrefixPaddingS1:         engine.headerTypes.S1,
		AWGPrefixPaddingS2:         engine.headerTypes.S2,
		AWGPrefixPaddingS3:         engine.headerTypes.S3,
		AWGPrefixPaddingS4:         engine.headerTypes.S4,
		TxHandshakeInitiations:     engine.counters.txHandshakeInitiations.Load(),
		TxTransportDatagrams:       engine.counters.txTransport.Load(),
		TxTransportPayloadDatagram: txPayload,
		RxHandshakeResponses:       engine.counters.rxHandshakeResponses.Load(),
		RxTransportDatagrams:       engine.counters.rxTransport.Load(),
		RxTransportPayloadDatagram: rxPayload,
		HandshakeResponseObserved:  engine.counters.rxHandshakeResponses.Load() > 0,
		TransportObservedBothWays:  txPayload > 0 && rxPayload > 0,
		Escalation:                 escalation,
	}
}

// StatusJSON is Status encoded. It never returns an empty string: an encoding
// failure yields a JSON object naming the failure, because a host that gets ""
// cannot tell "closed" from "broken".
func (engine *Engine) StatusJSON() string {
	encoded, err := json.Marshal(engine.Status())
	if err != nil {
		return `{"contract":"` + ContractVersion +
			`","up":false,"error":"status encoding failed"}`
	}
	return string(encoded)
}
