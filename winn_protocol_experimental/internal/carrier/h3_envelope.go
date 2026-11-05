package carrier

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"

	"winsvpn.local/winnprotocol/internal/carrierauth"
)

type synchronizedDatagramStream struct {
	mu     sync.Mutex
	stream *http3.Stream
}

func (stream *synchronizedDatagramStream) Send(encoded []byte) error {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	datagram := make([]byte, 1, len(encoded)+1)
	datagram[0] = 0 // RFC 9298 context ID zero.
	datagram = append(datagram, encoded...)
	err := stream.stream.SendDatagram(datagram)
	clear(datagram)
	return err
}

func proxyH3Envelopes(writer http.ResponseWriter, backend *net.UDPConn, claims carrierauth.RequestClaims, maxInner, maxOuter int, deduplicator *SessionDeduplicator) error {
	streamer, ok := writer.(http3.HTTPStreamer)
	if !ok {
		return errors.New("HTTP/3 response does not expose its request stream")
	}
	stream := streamer.HTTPStream()
	sender := &synchronizedDatagramStream{stream: stream}
	writer.Header().Set(http3.CapsuleProtocolHeader, "?1")
	writer.WriteHeader(http.StatusOK)

	results := make(chan error, 3)
	go func() {
		results <- annotateRelayError(
			"client-to-backend relay",
			h3EnvelopesToUDP(
				stream, sender, backend,
				claims.SessionID+"|"+claims.SequenceEpoch,
				maxInner, maxOuter, deduplicator,
			),
		)
	}()
	go func() {
		var sequence atomic.Uint64
		results <- annotateRelayError(
			"backend-to-client relay",
			udpToH3Envelopes(
				sender, backend, maxInner, maxOuter, &sequence,
				claims.Privacy == carrierauth.PrivacyHighRisk,
			),
		)
	}()
	go func() {
		_, err := io.Copy(io.Discard, stream)
		results <- annotateRelayError("request capsule relay", err)
	}()
	first := <-results
	stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	_ = stream.Close()
	_ = backend.Close()
	return first
}

func annotateRelayError(direction string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", direction, err)
}

func h3EnvelopesToUDP(stream *http3.Stream, sender *synchronizedDatagramStream, backend *net.UDPConn, sessionID string, maxInner, maxOuter int, deduplicator *SessionDeduplicator) error {
	for {
		datagram, err := stream.ReceiveDatagram(context.Background())
		if err != nil {
			return err
		}
		contextID, consumed, err := quicvarint.Parse(datagram)
		if err != nil {
			return err
		}
		if contextID != 0 {
			continue
		}
		if len(datagram)-consumed > maxOuter {
			return ErrDatagramTooLarge
		}
		outerSize := len(datagram) - consumed
		frame, err := decodeEnvelope(datagram[consumed:], maxInner)
		clear(datagram)
		if err != nil {
			return err
		}
		switch frame.kind {
		case envelopeData:
			if deduplicator != nil &&
				!deduplicator.Accept(sessionID, frame.sequence, time.Now().UTC()) {
				continue
			}
			if _, err := backend.Write(frame.payload); err != nil {
				return err
			}
		case envelopeProbe:
			ack, err := encodeEnvelope(
				envelopeProbeAck, frame.sequence, nil,
				outerSize,
			)
			if err != nil {
				return err
			}
			err = sender.Send(ack)
			clear(ack)
			if err != nil {
				return err
			}
		case envelopeCover:
			continue
		default:
			return errors.New("client sent an invalid HTTP/3 carrier envelope")
		}
	}
}

func udpToH3Envelopes(sender *synchronizedDatagramStream, backend *net.UDPConn, maxInner, maxOuter int, sequence *atomic.Uint64, privacyPadding bool) error {
	buffer := make([]byte, maxInner+1)
	for {
		count, err := backend.Read(buffer)
		if err != nil {
			return err
		}
		if count > maxInner {
			clear(buffer[:count])
			return ErrDatagramTooLarge
		}
		outerSize := envelopeHeaderSize + count
		if privacyPadding {
			outerSize = privacyBucket(outerSize, maxOuter)
		}
		encoded, err := encodeEnvelope(envelopeData, sequence.Add(1), buffer[:count], outerSize)
		clear(buffer[:count])
		if err != nil {
			return err
		}
		err = sender.Send(encoded)
		clear(encoded)
		if err != nil {
			return err
		}
	}
}
