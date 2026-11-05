package carrier

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

// The first raw TCP record is carried as an opaque TLS 1.2 session ticket.
// This is a single ClientHello record, not a TLS handshake. The gateway does
// not answer it until the embedded Winn initiation authenticates.
func encodeTCPFirstFlight(record []byte) ([]byte, error) {
	if len(record) > 0xffff-128 {
		return nil, errors.New("TCP first flight exceeds TLS record limit")
	}
	var random [64]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return nil, err
	}
	body := make([]byte, 0, len(record)+128)
	body = append(body, 0x03, 0x03)
	body = append(body, random[:32]...)
	body = append(body, 32)
	body = append(body, random[32:]...)
	body = append(body, 0, 4, 0xc0, 0x2f, 0xc0, 0x30)
	body = append(body, 1, 0)
	extensions := make([]byte, 0, len(record)+14)
	extensions = append(extensions, 0, 13, 0, 6, 0, 4, 4, 3, 5, 3)
	extensions = append(extensions, 0, 35, byte(len(record)>>8), byte(len(record)))
	extensions = append(extensions, record...)
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)
	handshake := make([]byte, 0, len(body)+4)
	handshake = append(handshake, 1, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)
	wire := []byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}
	return append(wire, handshake...), nil
}

func readTCPFirstFlight(r io.Reader, maxTicket int) ([]byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	if header[0] != 0x16 || header[1] != 0x03 || header[2] > 0x03 {
		return nil, errors.New("not a TLS ClientHello record")
	}
	n := int(binary.BigEndian.Uint16(header[3:]))
	if n < 4 || n > maxTicket+256 {
		return nil, errors.New("TCP first flight record length out of bounds")
	}
	handshake := make([]byte, n)
	if _, err := io.ReadFull(r, handshake); err != nil {
		return nil, err
	}
	if handshake[0] != 1 || int(handshake[1])<<16|int(handshake[2])<<8|int(handshake[3]) != n-4 {
		return nil, errors.New("not a complete TLS ClientHello")
	}
	body := handshake[4:]
	if len(body) < 35 || body[0] != 0x03 || body[1] != 0x03 {
		return nil, errors.New("invalid ClientHello body")
	}
	pos := 34
	sidLen := int(body[pos])
	pos++
	if sidLen > 32 || pos+sidLen+2 > len(body) {
		return nil, errors.New("invalid ClientHello session id")
	}
	pos += sidLen
	ciphersLen := int(binary.BigEndian.Uint16(body[pos:]))
	pos += 2
	if ciphersLen < 2 || ciphersLen%2 != 0 || pos+ciphersLen+1 > len(body) {
		return nil, errors.New("invalid ClientHello ciphers")
	}
	pos += ciphersLen
	compressionLen := int(body[pos])
	pos++
	if compressionLen < 1 || pos+compressionLen+2 > len(body) {
		return nil, errors.New("invalid ClientHello compression")
	}
	pos += compressionLen
	extensionsLen := int(binary.BigEndian.Uint16(body[pos:]))
	pos += 2
	if pos+extensionsLen != len(body) {
		return nil, errors.New("invalid ClientHello extensions length")
	}
	for pos < len(body) {
		if pos+4 > len(body) {
			return nil, errors.New("short ClientHello extension")
		}
		kind := binary.BigEndian.Uint16(body[pos:])
		length := int(binary.BigEndian.Uint16(body[pos+2:]))
		pos += 4
		if pos+length > len(body) {
			return nil, errors.New("invalid ClientHello extension length")
		}
		if kind == 35 && length >= SaltSize+LengthRecordOverhead && length <= maxTicket {
			return body[pos : pos+length], nil
		}
		pos += length
	}
	return nil, errors.New("ClientHello has no Winn first flight")
}
