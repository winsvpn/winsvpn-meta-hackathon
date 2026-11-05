// Package wcf3 defines the Winn Carrier Frame v3 wire envelope. WCF3 binds
// every frame to one verified connection attempt and candidate while keeping a
// compact 64-byte header suitable for 1,024-byte privacy cells.
package wcf3

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
)

const (
	Magic              = "WCF3"
	HeaderSize         = 64
	MaxFrameSize       = 1500
	MaxPayloadSize     = MaxFrameSize - HeaderSize
	PrivacyCellSize    = 1024
	PrivacyPayloadSize = PrivacyCellSize - HeaderSize
	ProbePayloadSize   = 32

	KindData     byte = 1
	KindProbe    byte = 2
	KindProbeAck byte = 3
	KindCover    byte = 4

	FlagPadded byte = 1 << 0

	allowedFlags  = FlagPadded
	bindingDomain = "winn-wcf3-binding/v1\x00"
)

type Context struct {
	SessionID     [16]byte
	BindingID     [16]byte
	PSKGeneration uint64
	SequenceEpoch uint64
}

type Frame struct {
	Kind          byte
	Flags         byte
	SessionID     [16]byte
	BindingID     [16]byte
	PSKGeneration uint64
	SequenceEpoch uint64
	Sequence      uint64
	Payload       []byte
}

func ContextFromBinding(
	binding connectivity.Binding,
	now time.Time,
) (Context, error) {
	if err := binding.Validate(now); err != nil {
		return Context{}, err
	}
	session, err := hex.DecodeString(binding.SessionID)
	if err != nil || len(session) != 16 {
		return Context{}, errors.New("binding session ID is not 16 bytes")
	}
	bindingID, err := DeriveBindingID(binding, now)
	if err != nil {
		clear(session)
		return Context{}, err
	}
	var context Context
	copy(context.SessionID[:], session)
	clear(session)
	context.BindingID = bindingID
	context.PSKGeneration = binding.PSKGeneration
	context.SequenceEpoch = binding.SequenceEpoch
	return context, nil
}

func DeriveBindingID(
	binding connectivity.Binding,
	now time.Time,
) ([16]byte, error) {
	if err := binding.Validate(now); err != nil {
		return [16]byte{}, err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(bindingDomain))
	writeString(hash, binding.AttemptID)
	writeString(hash, binding.Profile)
	writeString(hash, string(binding.Mode))
	writeString(hash, binding.ManifestDigest)
	writeString(hash, binding.CandidateID)
	writeString(hash, binding.NodeID)
	writeString(hash, binding.SessionID)
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], binding.PSKGeneration)
	_, _ = hash.Write(number[:])
	binary.BigEndian.PutUint64(number[:], binding.SequenceEpoch)
	_, _ = hash.Write(number[:])
	writeString(hash, binding.Nonce)
	writeString(hash, binding.ExpiresAt.UTC().Format(time.RFC3339Nano))
	sum := hash.Sum(nil)
	var result [16]byte
	copy(result[:], sum)
	clear(sum)
	clear(number[:])
	return result, nil
}

// Encode returns one WCF3 frame. totalSize zero selects the minimum frame size;
// otherwise cryptographically random padding expands the frame to totalSize.
func Encode(frame Frame, totalSize int) ([]byte, error) {
	if err := validateFrame(frame); err != nil {
		return nil, err
	}
	minimum := HeaderSize + len(frame.Payload)
	if totalSize == 0 {
		totalSize = minimum
	}
	if totalSize < minimum || totalSize > MaxFrameSize {
		return nil, errors.New("WCF3 total size is outside frame limits")
	}
	flags := frame.Flags &^ FlagPadded
	if totalSize > minimum {
		flags |= FlagPadded
	}
	encoded := make([]byte, totalSize)
	copy(encoded[0:4], Magic)
	encoded[4] = frame.Kind
	encoded[5] = flags
	// #nosec G115 -- validateFrame above rejects payloads over MaxPayloadSize
	// (1,436 bytes), far under uint16's range.
	binary.BigEndian.PutUint16(encoded[6:8], uint16(len(frame.Payload)))
	copy(encoded[8:24], frame.SessionID[:])
	copy(encoded[24:40], frame.BindingID[:])
	binary.BigEndian.PutUint64(encoded[40:48], frame.PSKGeneration)
	binary.BigEndian.PutUint64(encoded[48:56], frame.SequenceEpoch)
	binary.BigEndian.PutUint64(encoded[56:64], frame.Sequence)
	copy(encoded[HeaderSize:minimum], frame.Payload)
	if totalSize > minimum {
		if _, err := io.ReadFull(rand.Reader, encoded[minimum:]); err != nil {
			clear(encoded)
			return nil, fmt.Errorf("generate WCF3 padding: %w", err)
		}
	}
	return encoded, nil
}

// EncodePrivacyCell is the only encoder for Maximum Privacy traffic. It
// enforces the frozen 1,024-byte cell and 960-byte payload ceiling.
func EncodePrivacyCell(frame Frame) ([]byte, error) {
	if len(frame.Payload) > PrivacyPayloadSize {
		return nil, errors.New("WCF3 privacy payload exceeds 960 bytes")
	}
	return Encode(frame, PrivacyCellSize)
}

// Decode is the structural/test-only decoder. Production receive paths must use
// DecodeWithReplay or DecodePrivacyCell so a structurally valid duplicate can
// never bypass the direction-separated replay window. The returned payload is
// an independent allocation.
func Decode(
	encoded []byte,
	maxPayload int,
	expected *Context,
) (Frame, error) {
	if len(encoded) < HeaderSize || len(encoded) > MaxFrameSize {
		return Frame{}, errors.New("WCF3 frame size is invalid")
	}
	if string(encoded[:4]) != Magic {
		return Frame{}, errors.New("WCF3 magic mismatch")
	}
	kind := encoded[4]
	flags := encoded[5]
	if flags&^allowedFlags != 0 {
		return Frame{}, errors.New("WCF3 frame contains unknown flags")
	}
	payloadLength := int(binary.BigEndian.Uint16(encoded[6:8]))
	if maxPayload <= 0 || maxPayload > MaxPayloadSize {
		return Frame{}, errors.New("WCF3 maximum payload limit is invalid")
	}
	if payloadLength > maxPayload ||
		HeaderSize+payloadLength > len(encoded) {
		return Frame{}, errors.New("WCF3 payload length is invalid")
	}
	padded := len(encoded) > HeaderSize+payloadLength
	if padded != (flags&FlagPadded != 0) {
		return Frame{}, errors.New("WCF3 padding flag and frame size disagree")
	}
	frame := Frame{
		Kind:          kind,
		Flags:         flags,
		PSKGeneration: binary.BigEndian.Uint64(encoded[40:48]),
		SequenceEpoch: binary.BigEndian.Uint64(encoded[48:56]),
		Sequence:      binary.BigEndian.Uint64(encoded[56:64]),
		Payload:       append([]byte(nil), encoded[HeaderSize:HeaderSize+payloadLength]...),
	}
	copy(frame.SessionID[:], encoded[8:24])
	copy(frame.BindingID[:], encoded[24:40])
	if err := validateFrame(frame); err != nil {
		clear(frame.Payload)
		return Frame{}, err
	}
	if expected != nil &&
		(frame.SessionID != expected.SessionID ||
			frame.BindingID != expected.BindingID ||
			frame.PSKGeneration != expected.PSKGeneration ||
			frame.SequenceEpoch != expected.SequenceEpoch) {
		clear(frame.Payload)
		return Frame{}, errors.New("WCF3 connection binding mismatch")
	}
	return frame, nil
}

// DecodeWithReplay validates one generic WCF3 frame against its immutable
// connection context and atomically consumes its sequence in the selected
// receive direction.
func DecodeWithReplay(
	encoded []byte,
	maxPayload int,
	expected *Context,
	replay *ReplayWindow,
	direction Direction,
) (Frame, error) {
	if expected == nil || replay == nil {
		return Frame{}, errors.New(
			"WCF3 receive decode requires context and replay window",
		)
	}
	frame, err := Decode(encoded, maxPayload, expected)
	if err != nil {
		return Frame{}, err
	}
	if err := replay.Accept(direction, frame); err != nil {
		clear(frame.Payload)
		return Frame{}, err
	}
	return frame, nil
}

// DecodePrivacyCell structurally validates one fixed cell, enforces the
// expected connection context, and consumes its sequence in a direction-
// separated replay window.
func DecodePrivacyCell(
	encoded []byte,
	expected *Context,
	replay *ReplayWindow,
	direction Direction,
) (Frame, error) {
	if len(encoded) != PrivacyCellSize {
		return Frame{}, errors.New("WCF3 privacy cell must be 1024 bytes")
	}
	if expected == nil || replay == nil {
		return Frame{}, errors.New(
			"WCF3 privacy decode requires context and replay window",
		)
	}
	return DecodeWithReplay(
		encoded, PrivacyPayloadSize, expected, replay, direction,
	)
}

func validateFrame(frame Frame) error {
	if !validKind(frame.Kind) {
		return errors.New("WCF3 frame kind is invalid")
	}
	if frame.Flags&^allowedFlags != 0 {
		return errors.New("WCF3 frame flags are invalid")
	}
	if zero16(frame.SessionID) || zero16(frame.BindingID) {
		return errors.New("WCF3 session and binding IDs are required")
	}
	if frame.PSKGeneration == 0 ||
		frame.SequenceEpoch == 0 ||
		frame.Sequence == 0 {
		return errors.New("WCF3 generation, epoch, and sequence are required")
	}
	if len(frame.Payload) > MaxPayloadSize {
		return errors.New("WCF3 payload exceeds maximum")
	}
	switch frame.Kind {
	case KindData:
		if len(frame.Payload) == 0 {
			return errors.New("WCF3 data payload is empty")
		}
	case KindProbe, KindProbeAck:
		if len(frame.Payload) != ProbePayloadSize {
			return errors.New("WCF3 probe payload must be 32 bytes")
		}
	case KindCover:
		if len(frame.Payload) != 0 {
			return errors.New("WCF3 cover frame contains data")
		}
	}
	return nil
}

func validKind(kind byte) bool {
	switch kind {
	case KindData, KindProbe, KindProbeAck, KindCover:
		return true
	default:
		return false
	}
}

func zero16(value [16]byte) bool {
	var combined byte
	for _, current := range value {
		combined |= current
	}
	return combined == 0
}

type stringWriter interface {
	Write([]byte) (int, error)
}

func writeString(writer stringWriter, value string) {
	var length [4]byte
	// #nosec G115 -- writeString's only caller, DeriveBindingID, first calls
	// binding.Validate, which bounds every field passed here to <=128 bytes
	// (identifierPattern/sessionPattern) or a fixed enum/timestamp format,
	// all far under uint32.
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write([]byte(value))
}
