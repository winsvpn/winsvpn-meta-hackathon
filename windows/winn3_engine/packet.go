package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The inner-packet rules, kept in a file with NO build tag on purpose.
//
// Everything in here is pure arithmetic and byte inspection, so it compiles and
// its tests run on the maintainer's machine -- which for this project is a Mac.
// The Wintun half of this binary can only be compiled for Windows and can only
// be exercised on Windows; if the rules that decide whether a packet is allowed
// to move lived in that half, they would be unreviewable and untestable
// everywhere the work is actually done. They are the part most worth testing,
// so they live where they can be.

// # THE MTU ARITHMETIC
//
// Worked here rather than cited, because this number being wrong is invisible:
// the tunnel reports up, small packets work, and every full-size flow black
// holes. All of these were confirmed by EXECUTING the winn3 packages rather
// than by reading the table in the handoff document.
//
//	tun.Overhead() = core.TransportOverhead() + tun.FrameOverhead
//	               = (DemuxToken 8 + innerLength 2 + AEADTag 16) + 3
//	               = 26 + 3
//	               = 29
//
// The carrier's message size is NOT the one the session dialled. It is the
// FLOOR over every class the session may escalate to, because a migration must
// never need a smaller packet than the one already in flight:
//
//	carrier.Floor(1280, udp, tcp, tls) = 1168      <- what the session is pinned to
//	carrier.MaxMessageSizeFor(udp, ipv4, 1280) = 1252  <- what UDP alone would allow
//	                                      gap =   84
//
// So the two candidate inner MTUs are:
//
//	FLOOR:            1168 - 29 = 1139   <- correct; what the adapter must carry
//	DIALLED UDP/IPv4: 1252 - 29 = 1223   <- the trap
//
// An adapter set to 1223 hands the session packets up to 1223 bytes. The
// session is pinned at a 1168-byte message, which carries 1139 bytes of inner
// packet. Everything between 1140 and 1223 is therefore accepted by Windows,
// accepted by this relay, and then dropped inside the tunnel as oversize -- 84
// bytes of silent loss that only appears on full-size flows, only after the
// first migration, and in a country where nobody can attach a debugger.
//
// This relay does not compute the floor; cmd/winn-datapath does, publishes it
// as `inner_mtu` in its status document, and refuses a create document that
// disagrees. The operator passes it here with -mtu, and the obligation on the
// privileged service is to pass the SAME number it read from `inner_mtu` and to
// refuse to promote if the two ever disagree.
const (
	// winn3ShippingFloorInnerMTU is carrier.Floor(1280, udp, tcp, tls) minus
	// tun.Overhead(). It is not hard-wired as the only legal value -- a wider
	// measured path legitimately yields a larger one -- it is the value this
	// lane expects at the shipping floor and is reported at startup so that a
	// mismatch is visible in a log rather than only in a throughput graph.
	winn3ShippingFloorInnerMTU = 1139

	// winn3DialledUDPv4InnerMTU is the trap value above. Passing it is refused
	// outright: there is no plan under which the adapter should be sized from
	// the dialled carrier rather than the floor, so this is always a bug and
	// never a deliberate choice.
	winn3DialledUDPv4InnerMTU = 1223

	// winn3MinInnerMTU mirrors tun.MinInnerMTUv4. Below this the tun layer
	// refuses to build at all, so accepting it here would only move the refusal
	// somewhere less legible.
	winn3MinInnerMTU = 576

	// winn3MaxInnerMTU mirrors tun.MaxIPPacket.
	winn3MaxInnerMTU = 65535

	// winn3IPv6MinLinkMTU is RFC 8200's minimum link MTU. An inner MTU below it
	// cannot carry inner IPv6, which is why the shipping floor of 1139 implies
	// an IPv4-only inner posture and why the bootstrap posture has no IPv6 in
	// it. Reported, not enforced: what the inner assignment is belongs to the
	// engine's create document, not to a relay.
	winn3IPv6MinLinkMTU = 1280
)

var errInnerMTU = errors.New("winn3 relay: inner MTU")

// Validate the published MTU's bounds. Plan correctness is established by
// the engine; VerifyAppliedMtuStillAgrees checks the adapter against it.
func validateInnerMTU(mtu int) error {
	switch {
	case mtu <= 0:
		return fmt.Errorf("%w %d is not usable; pass the engine's inner_mtu",
			errInnerMTU, mtu)
	case mtu < winn3MinInnerMTU:
		return fmt.Errorf("%w %d is below the %d-byte IPv4 minimum",
			errInnerMTU, mtu, winn3MinInnerMTU)
	case mtu > winn3MaxInnerMTU:
		return fmt.Errorf("%w %d is above the %d-byte maximum",
			errInnerMTU, mtu, winn3MaxInnerMTU)
	}
	return nil
}

// startCommand is the one control line this relay accepts, on stdin, from the
// privileged service that started it. It lives here rather than beside the
// Wintun code so that its refusals are testable on a machine that has no
// Wintun -- which is every machine this project is developed on.
type startCommand struct {
	mtu        int
	enginePort int
}

// parseStartCommand reads `start mtu=<n> engine-port=<n>`.
//
// Unknown tokens are a REFUSAL rather than something to ignore, for the same
// reason loadWinn3Profile sets DisallowUnknownFields: a service that misspells
// a key and is told nothing believes a setting took effect that did not, and on
// this line the setting that could silently not take effect is the MTU.
func parseStartCommand(line string) (startCommand, error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 0 || fields[0] != "start" {
		return startCommand{}, fmt.Errorf(
			"expected a line beginning `start`, got %q", line)
	}
	var cmd startCommand
	seen := map[string]bool{}
	for _, field := range fields[1:] {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			return startCommand{}, fmt.Errorf("field %q is not key=value", field)
		}
		if seen[key] {
			return startCommand{}, fmt.Errorf("field %q appears twice", key)
		}
		seen[key] = true
		number, err := strconv.Atoi(value)
		if err != nil {
			return startCommand{}, fmt.Errorf("field %q is not a number", field)
		}
		switch key {
		case "mtu":
			cmd.mtu = number
		case "engine-port":
			cmd.enginePort = number
		default:
			return startCommand{}, fmt.Errorf("unknown field %q", key)
		}
	}
	if !seen["mtu"] || !seen["engine-port"] {
		return startCommand{}, errors.New("both mtu and engine-port are required")
	}
	if err := validateInnerMTU(cmd.mtu); err != nil {
		return startCommand{}, err
	}
	if cmd.enginePort <= 0 || cmd.enginePort > 65535 {
		return startCommand{}, fmt.Errorf(
			"engine-port %d is not usable", cmd.enginePort)
	}
	return cmd, nil
}

// Packet refusal reasons. Each is a distinct sentinel so the relay can count
// them separately: "the host sent something absurd" and "the tunnel is dropping
// traffic" are different problems and a single counter conflates them.
var (
	errPacketEmpty    = errors.New("zero-length")
	errPacketOversize = errors.New("larger than the inner MTU")
	errPacketNotIP    = errors.New("does not start at an IP version nibble")
	errPacketShort    = errors.New("shorter than its own IP header")
	errPacketDeclared = errors.New("declares a length that does not fit")
)

// classifyInnerPacket decides whether one buffer may cross the relay.
//
// What crosses this relay is a RAW INNER IP PACKET starting at its version
// nibble -- no Darwin address-family prefix, no Linux packet-information
// header, no length prefix. Wintun's ring already hands over exactly that, and
// the loopback seam carries exactly one such packet per datagram.
//
// This is deliberately NOT a full IP validator. winn3/tun is the validator and
// it re-checks everything here on both sides; duplicating it would produce two
// validators that eventually disagree, and the more permissive one would be the
// one that mattered. What this rejects is the narrow set that must never be
// forwarded even once: nothing, something too big for the tunnel to carry, and
// something that is not an IP packet at all. The last of those is the one that
// matters most -- a buffer that is not an IP packet reaching the seam means the
// relay has been wired to the wrong side of something.
func classifyInnerPacket(pkt []byte, mtu int) error {
	if len(pkt) == 0 {
		return errPacketEmpty
	}
	if len(pkt) > mtu {
		return errPacketOversize
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return errPacketShort
		}
		// The declared total length is checked against what actually arrived.
		// A packet claiming to be longer than its buffer is the shape a
		// truncated read takes, and forwarding one produces undetectable
		// corruption at the next layer rather than a visible error.
		if total := int(binary.BigEndian.Uint16(pkt[2:4])); total > len(pkt) {
			return errPacketDeclared
		}
		return nil
	case 6:
		if len(pkt) < 40 {
			return errPacketShort
		}
		if payload := int(binary.BigEndian.Uint16(pkt[4:6])); payload+40 > len(pkt) {
			return errPacketDeclared
		}
		return nil
	default:
		return errPacketNotIP
	}
}
