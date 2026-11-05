package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// The v3 status document, and the ONE place the promotion gate is decided.
//
// # Why the predicate lives here and not in either host
//
// Two desktop hosts have to answer the same question — may the tunnel be
// widened from the bootstrap posture to the full one — and the answer is a
// conjunction over two counters that live in different layers. Computed twice,
// in two languages, it will be computed differently: the obvious mistake is
// RxOffered for RxPackets, which is the difference between "a payload arrived"
// and "an inner packet was validated and reached the host device", and it is
// exactly the class of error a sibling lane caught in this protocol today.
//
// So it is computed once, in Go, next to the counters, and both hosts read a
// boolean. A host cannot get it wrong because a host is not asked.
//
// # Why the document is fail-closed by construction
//
// PromotionReady is only ever set by winn3PromotionReady. Every other field is
// descriptive. A host that cannot parse the document, or that reads a document
// with the field absent, gets Go's zero value for a bool, which is false, which
// is the bootstrap posture. There is no encoding of this document that widens a
// tunnel by accident.

// winn3PromotionReady is the ONE place in this binary that answers "may the
// host promote routes?".
//
// Both conditions must hold before this function returns true. Neither is
// enough on its own, and neither is ever substituted for by a proxy like "the
// carrier handshake succeeded", "the tun device was created", or "link is up in
// terms of "the socket connected":
//
//  1. Gate.State() == StateCarrying — the session driver says DATA may flow;
//     and
//  2. Stats().RxPackets > 0 — an inner packet was validated and reached the
//     host device, which is the first moment anything has proven the whole
//     chain: carrier, crypto, framing, address assignment, host device.
//
// RxPackets is the right counter and RxOffered is not. The first counts
// deliveries, the second counts arrivals.
func winn3PromotionReady(gate tun.State, rxPackets uint64) bool {
	return gate == tun.StateCarrying && rxPackets > 0
}

// winn3Posture names the posture the host must be holding right now.
//
// It is derived from the same predicate rather than tracked separately,
// because a posture field that could disagree with the boolean is a posture
// field that eventually will.
func winn3Posture(ready bool) string {
	if ready {
		return winn3PostureFull
	}
	return winn3PostureBootstrap
}

const (
	// winn3PostureBootstrap is one /32, no default route, no IPv6, no DNS, and
	// the outer-socket exclusion already installed.
	winn3PostureBootstrap = "bootstrap"

	// winn3PostureFull is the promoted posture: default route, IPv6, DNS and
	// the full route set, in one call.
	winn3PostureFull = "promoted"

	// winn3PostureHold is published only by the supervised frame mode, while
	// lifecycle is recovering or blocked: keep exactly the capture already
	// installed, neither narrowing a promoted posture to bootstrap nor
	// widening a bootstrap one. promotion_ready stays false with it.
	winn3PostureHold = "hold"

	// maxWinn3StatusBytes bounds one status document. A legitimate line is a
	// few hundred bytes of scalars. Same ceiling as maxWinn3ProfileBytes and
	// as kMaxStatusLineBytes in winn3_posture.h.
	maxWinn3StatusBytes = 64 << 10

	// maxWinn3StatusJSONDepth is well above a legitimate document (root
	// object plus the plan array) and well below the nesting that
	// encoding/json will recurse through while skipping an unknown value.
	maxWinn3StatusJSONDepth = 8
)

// winn3Status is what the engine publishes on stdout, one JSON object per line.
//
// Line-delimited JSON rather than the duplex framing, because this is not the
// datapath contract: it is a different protocol with a different engine, and
// dressing it in the winn/1 frame header would invite a host to send it winn/1
// opcodes. Both desktop hosts already read a child process's pipe.
//
// Every field is a counter, an enum or a boolean this process computed itself.
// There is no endpoint, no address, no session identifier and no path in it, so
// unlike the winn/1 status document this one is safe to log in full — which
// matters, because the field a support ticket needs is the one that says why a
// tunnel refused to widen.
type winn3Status struct {
	// Event is "sizing", "posture", "carrying", "refused" or "stopped".
	Event string `json:"event"`

	// SessionID is the frame mode's opaque correlator, echoed from the Create
	// document so a host can match a status line to the tunnel it asked for. It
	// is omitted entirely when unset, so the desktop mode's document is
	// unchanged byte for byte. It is never put on the wire.
	SessionID string `json:"session_id,omitempty"`

	// Posture is the posture the host must be holding, derived from Promotion.
	Posture string `json:"posture"`

	// PromotionReady is the gate. It is the zero value on purpose. Before first
	// promotion, and always in the desktop mode, false means bootstrap. In the
	// supervised frame mode, once the tunnel has proven delivery, false means
	// hold (see Lifecycle and winn3PostureHold), never a return to bootstrap.
	PromotionReady bool `json:"promotion_ready"`

	// GateState is the tun gate's own name for its state, for diagnosis only.
	// A host must not re-derive PromotionReady from it.
	GateState string `json:"gate_state"`

	// The two counters the predicate is built from, published so that a host
	// can show a user why nothing has happened yet, and so that an operator can
	// tell "the session never established" from "it established and nothing
	// came back".
	RxPackets uint64 `json:"rx_packets"`
	RxOffered uint64 `json:"rx_offered"`

	// The fail-closed evidence counters. Nonzero TxDroppedClosed with a
	// carrying gate is the tunnel refusing to leak, which is the behaviour, not
	// a fault.
	TxPackets       uint64 `json:"tx_packets"`
	TxDroppedClosed uint64 `json:"tx_dropped_closed"`
	RxDroppedClosed uint64 `json:"rx_dropped_closed"`

	// TxDroppedInvalid is a DIFFERENT claim from TxDroppedClosed and the two
	// must not be read as one number. TxDroppedClosed is the gate refusing
	// while shut. TxDroppedInvalid is the gate OPEN and the packet refused
	// anyway, because the tun layer's outbound validator would not carry it —
	// most importantly a source address this session was never assigned, which
	// is precisely the packet that would have identified the host to anything
	// watching past the gateway.
	//
	// It is published because it is the only in-process evidence that the
	// refusal fired. Without it the claim "a packet with an unassigned source
	// address never left this host" can only be supported by packet capture,
	// which is not available on a user's phone in the field — and this is a
	TxDroppedInvalid uint64 `json:"tx_dropped_invalid"`
	TxDroppedSink    uint64 `json:"tx_dropped_sink"`
	TxDroppedOversize uint64 `json:"tx_dropped_oversize"`
	DroppedToEngine  uint64 `json:"dropped_to_engine,omitempty"`

	// The frame-mode queue census, published only by the frame server and
	// omitted when zero, so the desktop document is unchanged. Every field is
	// a count or a depth; none names anything. host_* is the downlink side
	// (toHost and the frame pump's writes to the host), engine_* the uplink
	// ring, ring_* its drain gate. recv_batches and send_batches turn
	// messages_received and messages_sent into real socket batch occupancy;
	// data_frames_dropped and rekeys say whether a rekey's data pause, not
	// the network, took packets.
	HostQueueDepth       uint64 `json:"host_queue_depth,omitempty"`
	HostQueueHighWater   uint64 `json:"host_queue_high_water,omitempty"`
	DroppedToHost        uint64 `json:"dropped_to_host,omitempty"`
	HostWriteBatches     uint64 `json:"host_write_batches,omitempty"`
	HostWritePackets     uint64 `json:"host_write_packets,omitempty"`
	HostWriteNanos       uint64 `json:"host_write_ns,omitempty"`
	HostWriteMaxNanos    uint64 `json:"host_write_max_ns,omitempty"`
	EngineQueueDepth     uint64 `json:"engine_queue_depth,omitempty"`
	EngineQueueHighWater uint64 `json:"engine_queue_high_water,omitempty"`
	RingPopCalls         uint64 `json:"ring_pop_calls,omitempty"`
	RingPopPackets       uint64 `json:"ring_pop_packets,omitempty"`
	RingWakePark         uint64 `json:"ring_wake_park,omitempty"`
	RecvBatches          uint64 `json:"recv_batches,omitempty"`
	SendBatches          uint64 `json:"send_batches,omitempty"`
	DataFramesDropped    uint64 `json:"data_frames_dropped,omitempty"`
	Rekeys               uint64 `json:"rekeys,omitempty"`
	SendQueueHighWater   uint64 `json:"send_queue_high_water,omitempty"`
	SendQueueDepth       uint64 `json:"send_queue_depth,omitempty"`
	// OuterReordered is authenticated downlink messages that arrived after a
	// later one, and OuterLost downlink messages that never arrived (or were
	// dropped before they were opened). Both omitted when zero.
	OuterReordered uint64 `json:"outer_reordered,omitempty"`
	OuterLost      uint64 `json:"outer_lost,omitempty"`
	// OuterReorderDepth splits outer_reordered by displacement
	// (core.ReorderDepth: [1], [2,3], [4,7], ..., [256,511], [512,inf)).
	// Omitted when nothing arrived late.
	OuterReorderDepth []uint64 `json:"outer_reorder_depth,omitempty"`
	// The outer socket's transmit path (carrier.Stats): sendmsg calls that
	// carried a UDP_SEGMENT super-datagram, the datagrams they carried, the
	// plain sendmmsg calls beside them, and whether the kernel refused
	// UDP_SEGMENT for good. Omitted when zero. Under WINN3_UDP_GSO=0 the
	// wrapper that counts them is bypassed (carrier/udp_gso_linux.go
	// wrapGSOBatchConn returns the raw conn), so all four are absent while
	// send_batches and messages_sent move: that absence is the G0 proof, and
	// tx_batch_calls does not move on that arm.
	TxGSOCalls    uint64 `json:"tx_gso_calls,omitempty"`
	TxGSOSegments uint64 `json:"tx_gso_segments,omitempty"`
	TxBatchCalls  uint64 `json:"tx_batch_calls,omitempty"`
	TxGSODisabled bool   `json:"tx_gso_disabled,omitempty"`

	// Loop-level seam counters.
	MessagesSent     uint64 `json:"messages_sent"`
	MessagesReceived uint64 `json:"messages_received"`
	SendFailed       uint64 `json:"send_failed"`
	RecvFailed       uint64 `json:"recv_failed"`
	Migrations       uint64 `json:"migrations"`

	// Unopenable is messages the session could not open: noise, a scan, a
	// replay, or the far side of a burst loss beyond the token window.
	// MessagesReceived counts those too — readLoop increments it for every
	// carrier message Deliver did not abort on — so a spray makes
	// messages_received climb. This field is the diagnosis; without it the
	// document says the tunnel is receiving.
	Unopenable uint64 `json:"unopenable"`

	// PathNarrowedFor is how many times this session concluded the path
	// carries small messages and not full-size ones. PromotionReady can stay
	// true on the small packets; this is the counter that names the stall.
	PathNarrowedFor uint64 `json:"path_narrowed_for"`

	// RekeyInitResends counts REKEY_INIT frames this end re-sent while, as
	// the rekey initiator, it waited for the peer's ACK. Nonzero means the
	// network lost an INIT (or the ACK was slower than the first resend) and
	// the resend, not the rekey timeout, decided the rekey. Omitted when zero.
	RekeyInitResends uint64 `json:"rekey_init_resends,omitempty"`

	// InnerMTU is the exact MTU the host must have set on the interface, and
	// MessageSize is the plan floor it came from. Published in the first
	// document so that a host which started this process before configuring the
	// interface still gets the number from the authority rather than computing
	// its own.
	InnerMTU    int `json:"inner_mtu"`
	MessageSize int `json:"message_size"`

	// InnerIPv6 reports whether the plan floor can carry inner IPv6 at all.
	// False is common and is not a defect. A host must not install IPv6 at
	// promotion when this is false.
	InnerIPv6 bool `json:"inner_ipv6"`

	// Plan is the migration plan the floor was computed over, echoed so that a
	// host's own idea of the plan can be diffed against the engine's.
	Plan []string `json:"plan"`

	// OuterSocketExclusion echoes the host's declaration, so that the claim
	// sits next to the counters it is supposed to explain.
	OuterSocketExclusion string `json:"outer_socket_exclusion"`

	// Refusal is set on the "refused" event and is the whole reason. It is a
	// refusal and never a downgrade: there is no field here that a host can
	// read as "carry on with a wider posture". In frame mode it also carries
	// the final cause once lifecycle is blocked.
	Refusal string `json:"refusal,omitempty"`

	// Lifecycle is the supervised frame mode's recovery state, one of the
	// driver.Lifecycle* values: "connecting", "connected", "recovering",
	// "blocked" or "stopped". LifecycleCause is set only with "blocked" and is
	// one of "never_established", "budget_spent" or "terminal"; the text of
	// the final error is in Refusal. Both are omitted before Create and in the
	// desktop mode, whose document is unchanged byte for byte.
	//
	// "recovering" means no retired round's counters are published and
	// promotion is not ready; posture is "hold". "blocked" persists, is
	// observable here without another packet, and authorises no fallback to
	// another protocol and no release of capture. Neither ever asks a
	// promoted host to narrow to bootstrap.
	Lifecycle      string `json:"lifecycle,omitempty"`
	LifecycleCause string `json:"lifecycle_cause,omitempty"`
}

// winn3HoldCaptureWhileRecovering replaces the bootstrap posture that a
// document with no proven round would otherwise carry. Bootstrap is the right
// answer before a tunnel has ever proven delivery and the wrong instruction to
// a host that may have promoted since: recovery and blocking keep capture as
// it is, and so does a proven tunnel whose gate a rekey is holding for a
// moment. everProven is the tunnel's own record that some round delivered.
func winn3HoldCaptureWhileRecovering(status *winn3Status, everProven bool) {
	switch {
	case status.Lifecycle == driver.LifecycleRecovering,
		status.Lifecycle == driver.LifecycleBlocked,
		everProven && !status.PromotionReady:
		status.PromotionReady = false
		status.Posture = winn3PostureHold
	}
}

// winn3StatusFrom builds a status document from the live loop.
//
// It takes the tunnel rather than reaching for a global so that the function is
// testable, and it is the only constructor: a status document assembled
// anywhere else could set PromotionReady by hand.
func winn3StatusFrom(
	event string,
	loop *driver.Loop,
	sizing driver.Sizing,
	exclusion string,
) winn3Status {
	status := winn3Status{
		Event:                event,
		InnerMTU:             sizing.InnerMTU,
		MessageSize:          sizing.MessageSize,
		InnerIPv6:            sizing.InnerIPv6,
		OuterSocketExclusion: exclusion,
	}
	for _, class := range sizing.Classes {
		status.Plan = append(status.Plan, class.String())
	}
	if loop == nil {
		status.GateState = tun.StateClosed.String()
		status.Posture = winn3Posture(false)
		return status
	}
	loopStats := loop.Stats()
	status.MessagesSent = loopStats.MessagesSent
	status.MessagesReceived = loopStats.MessagesReceived
	status.SendFailed = loopStats.SendFailed
	status.RecvFailed = loopStats.RecvFailed
	status.Migrations = loopStats.Migrations
	status.Unopenable = loopStats.Unopenable
	status.PathNarrowedFor = loopStats.PathNarrowedFor
	if sess := loop.Session(); sess != nil {
		status.RekeyInitResends = sess.Stats().RekeyInitResends
	}

	tunnel := loop.Tunnel()
	if tunnel == nil {
		// A loop with no tun is a control-plane probe or a gateway-side
		// session. It has no host device, so it can never prove delivery to
		// one, so it can never be promotion-ready. Saying so explicitly beats
		// leaving it to the zero value.
		status.GateState = tun.StateClosed.String()
		status.Posture = winn3Posture(false)
		return status
	}
	gate := tunnel.Gate().State()
	tunStats := tunnel.Stats()
	status.GateState = gate.String()
	status.RxPackets = tunStats.RxPackets
	status.RxOffered = tunStats.RxOffered
	status.TxPackets = tunStats.TxPackets
	status.TxDroppedClosed = tunStats.TxDroppedClosed
	status.TxDroppedInvalid = tunStats.TxDroppedInvalid
	status.TxDroppedSink = tunStats.TxDroppedSink
	status.TxDroppedOversize = tunStats.TxDroppedOversize
	status.RxDroppedClosed = tunStats.RxDroppedClosed
	status.PromotionReady = winn3PromotionReady(gate, tunStats.RxPackets)
	status.Posture = winn3Posture(status.PromotionReady)
	return status
}

// winn3EncodeStatus renders one document.
//
// The frame mode needs the bytes rather than a write, because its status
// travels inside a StatusResponse frame rather than as a line on stdout. Both
// modes therefore encode through this one function, which is what keeps the two
// documents field-for-field identical.
func winn3EncodeStatus(status winn3Status) ([]byte, error) {
	encoded, err := json.Marshal(status)
	if err != nil {
		return nil, fmt.Errorf("encode winn3 status: %w", err)
	}
	return encoded, nil
}

// winn3WriteStatus emits one document followed by a newline.
func winn3WriteStatus(w io.Writer, status winn3Status) error {
	encoded, err := winn3EncodeStatus(status)
	if err != nil {
		return err
	}
	if _, err := w.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("write winn3 status: %w", err)
	}
	return nil
}

// decodeWinn3Status is the host-side parser for one status document.
//
// cmd/winn-datapath publishes these lines; the desktop hosts parse them in
// C++ (ParseWinn3StatusLine). This function is the same contract in Go, so a
// hostile or malformed line can be refused here without a C++ toolchain, and
// so the encoder's output can be round-tripped against the rules the hosts
// enforce.
//
// A parse error is fail-closed: the caller holds the bootstrap posture. There
// is no decode outcome that sets PromotionReady on a document the engine
// would not have written.
func decodeWinn3Status(raw []byte) (winn3Status, error) {
	if len(raw) > maxWinn3StatusBytes {
		return winn3Status{}, fmt.Errorf("winn3 status: document exceeds %d bytes",
			maxWinn3StatusBytes)
	}
	trimmed := winn3TrimStatusLine(raw)
	if len(trimmed) == 0 {
		return winn3Status{}, fmt.Errorf("winn3 status: empty document")
	}
	if trimmed[0] != '{' {
		return winn3Status{}, fmt.Errorf("winn3 status: document must be a JSON object")
	}
	if depth := winn3JSONNestingDepth(trimmed); depth > maxWinn3StatusJSONDepth {
		return winn3Status{}, fmt.Errorf(
			"winn3 status: JSON nesting depth %d exceeds %d",
			depth, maxWinn3StatusJSONDepth)
	}
	if err := winn3RejectDuplicateTopLevelKeys(trimmed); err != nil {
		return winn3Status{}, fmt.Errorf("winn3 status: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	var status winn3Status
	if err := decoder.Decode(&status); err != nil {
		return winn3Status{}, fmt.Errorf("winn3 status: decode: %w", err)
	}
	if decoder.More() {
		return winn3Status{}, fmt.Errorf("winn3 status: document must be a single JSON object")
	}

	var members map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &members); err != nil {
		return winn3Status{}, fmt.Errorf("winn3 status: decode: %w", err)
	}
	if _, ok := members["event"]; !ok {
		return winn3Status{}, fmt.Errorf("winn3 status: event is absent")
	}
	if status.Event == "" {
		// encoding/json leaves a string unchanged on JSON null, so event:null
		// would otherwise parse as a present empty event. C++ ReadJsonString
		// refuses null. An empty event is not a document the engine writes.
		return winn3Status{}, fmt.Errorf("winn3 status: event is empty")
	}
	if _, ok := members["promotion_ready"]; !ok {
		return winn3Status{}, fmt.Errorf("winn3 status: promotion_ready is absent")
	}
	readyRaw := bytes.TrimSpace(members["promotion_ready"])
	if !bytes.Equal(readyRaw, []byte("true")) && !bytes.Equal(readyRaw, []byte("false")) {
		// encoding/json leaves a bool unchanged on JSON null, so
		// promotion_ready:null would otherwise parse as false. C++
		// ReadJsonBool refuses anything that is not the tokens true/false.
		return winn3Status{}, fmt.Errorf("winn3 status: promotion_ready is not a JSON boolean")
	}
	if raw, ok := members["gate_state"]; ok {
		t := bytes.TrimSpace(raw)
		if len(t) < 2 || t[0] != '"' {
			return winn3Status{}, fmt.Errorf("winn3 status: gate_state is not a JSON string")
		}
	}
	for _, key := range []string{"inner_mtu", "message_size", "rx_packets", "rx_offered"} {
		raw, ok := members[key]
		if !ok {
			continue
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return winn3Status{}, fmt.Errorf("winn3 status: %s is null", key)
		}
	}
	if status.InnerMTU < 0 || status.InnerMTU > 65535 {
		return winn3Status{}, fmt.Errorf("winn3 status: inner_mtu %d is not an MTU",
			status.InnerMTU)
	}
	if status.MessageSize < 0 || status.MessageSize > 65535 {
		return winn3Status{}, fmt.Errorf(
			"winn3 status: message_size %d is not a message size", status.MessageSize)
	}
	if len(status.Plan) > maxWinn3PlanEntries {
		return winn3Status{}, fmt.Errorf("winn3 status: plan has %d entries, max %d",
			len(status.Plan), maxWinn3PlanEntries)
	}
	return status, nil
}

func winn3TrimStatusLine(raw []byte) []byte {
	start, end := 0, len(raw)
	for start < end {
		c := raw[start]
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			break
		}
		start++
	}
	for end > start {
		c := raw[end-1]
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			break
		}
		end--
	}
	return raw[start:end]
}

func winn3RejectDuplicateTopLevelKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return fmt.Errorf("document must be a JSON object")
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("decode: %w", err)
		}
		key, ok := keyToken.(string)
		if !ok {
			return fmt.Errorf("JSON object key is not a string")
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate JSON member %q", key)
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("decode: %w", err)
		}
	}
	end, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if endDelim, ok := end.(json.Delim); !ok || endDelim != '}' {
		return fmt.Errorf("document must be a JSON object")
	}
	if decoder.More() {
		return fmt.Errorf("document must be a single JSON object")
	}
	return nil
}
