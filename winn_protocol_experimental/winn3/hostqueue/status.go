// SPDX-License-Identifier: MIT
// Derived from cmd/winn-datapath for the isolated direct-host study candidate.
// See docs/evidence/stages345_astra/windows.md for the shared and candidate paths.
package hostqueue

import (
	"encoding/json"
	"fmt"
	"io"

	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// PromotionReady shares the desktop predicate. rxPackets must come from the
// tun layer, which requires both successful writes and a proven device read.
func PromotionReady(gate tun.State, rxPackets uint64) bool {
	return gate == tun.StateCarrying && rxPackets > 0
}

func winn3Posture(ready bool) string {
	if ready {
		return winn3PostureFull
	}
	return winn3PostureBootstrap
}

const (
	winn3PostureBootstrap = "bootstrap"

	winn3PostureFull = "promoted"

	maxWinn3StatusBytes = 64 << 10

	maxWinn3StatusJSONDepth = 8
)

type winn3Status struct {
	Event string `json:"event"`

	SessionID string `json:"session_id,omitempty"`

	Posture string `json:"posture"`

	PromotionReady bool `json:"promotion_ready"`

	GateState string `json:"gate_state"`

	RxPackets uint64 `json:"rx_packets"`
	RxOffered uint64 `json:"rx_offered"`

	TxPackets       uint64 `json:"tx_packets"`
	TxDroppedClosed uint64 `json:"tx_dropped_closed"`
	RxDroppedClosed uint64 `json:"rx_dropped_closed"`

	TxDroppedInvalid uint64 `json:"tx_dropped_invalid"`

	MessagesSent     uint64 `json:"messages_sent"`
	MessagesReceived uint64 `json:"messages_received"`
	SendFailed       uint64 `json:"send_failed"`
	RecvFailed       uint64 `json:"recv_failed"`
	Migrations       uint64 `json:"migrations"`

	Unopenable uint64 `json:"unopenable"`

	PathNarrowedFor uint64 `json:"path_narrowed_for"`

	InnerMTU    int `json:"inner_mtu"`
	MessageSize int `json:"message_size"`

	InnerIPv6 bool `json:"inner_ipv6"`

	Plan []string `json:"plan"`

	OuterSocketExclusion string `json:"outer_socket_exclusion"`

	Refusal string `json:"refusal,omitempty"`
}

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

	tunnel := loop.Tunnel()
	if tunnel == nil {
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
	status.RxDroppedClosed = tunStats.RxDroppedClosed
	status.PromotionReady = PromotionReady(gate, tunStats.RxPackets)
	status.Posture = winn3Posture(status.PromotionReady)
	return status
}

func winn3EncodeStatus(status winn3Status) ([]byte, error) {
	encoded, err := json.Marshal(status)
	if err != nil {
		return nil, fmt.Errorf("encode winn3 status: %w", err)
	}
	return encoded, nil
}

func winn3WriteStatus(w io.Writer, status winn3Status) error {
	encoded, err := winn3EncodeStatus(status)
	if err != nil {
		return err
	}
	line := append(encoded, '\n')
	n, err := w.Write(line)
	if err != nil {
		return fmt.Errorf("write winn3 status: %w", err)
	}
	if n != len(line) {
		return io.ErrShortWrite
	}
	return nil
}
