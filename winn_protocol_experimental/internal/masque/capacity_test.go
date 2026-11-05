package masque

import (
	"context"
	"io"
	"sync"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
)

// TestDatagramCapacityReadsTheEstablishedLimitWithoutSending pins the property
// that lets a carrier stop probing the path with datagrams.
//
// DatagramCapacity must report what the already-established QUIC connection
// will carry, minus the framing this package and http3 add, and must do it
// without any datagram reaching the peer. A caller uses it to fail closed on a
// path that cannot carry its traffic; if it ever started emitting a datagram,
// the censor-triggerable behaviour it was written to remove would be back.
func TestDatagramCapacityReadsTheEstablishedLimitWithoutSending(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		streamID quic.StreamID
		limit    int64
		want     int
	}{
		{
			// The first request stream on a fresh connection: quarter stream
			// ID 0, a one-byte varint, plus the one-byte context ID.
			name:     "first request stream",
			streamID: 0,
			limit:    1393,
			want:     1391,
		},
		{
			// A later stream whose quarter ID needs a two-byte varint.
			name:     "later request stream",
			streamID: 4 * 64,
			limit:    1393,
			want:     1390,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			stream := &capacityStub{
				streamID: testCase.streamID,
				limit:    testCase.limit,
			}
			conn := newProxiedConn(
				stream,
				masqueAddr{"local"},
				masqueAddr{"remote"},
				nil,
			)
			defer conn.Close()

			capacity, err := conn.DatagramCapacity()
			if err != nil {
				t.Fatal(err)
			}
			if capacity != testCase.want {
				t.Fatalf("capacity = %d, want %d", capacity, testCase.want)
			}
			if delivered := stream.delivered(); delivered != 0 {
				t.Fatalf(
					"capacity read delivered %d datagrams to the peer; it must "+
						"deliver none",
					delivered,
				)
			}
			// The query itself must be impossible to accept, or a future
			// quic-go with a larger packet size would turn this read into a
			// datagram on the wire.
			if asked := stream.askedSize(); asked <= int(testCase.limit) {
				t.Fatalf(
					"capacity query asked for %d bytes against a %d-byte "+
						"limit; the query size must be impossible to accept",
					asked, testCase.limit,
				)
			}
		})
	}
}

// TestDatagramCapacitySurfacesAnAcceptedQuery covers the failure this design
// must never hide: if the query size ever becomes sendable, the caller has to
// hear about it rather than receive a plausible number.
func TestDatagramCapacitySurfacesAnAcceptedQuery(t *testing.T) {
	stream := &capacityStub{limit: -1}
	conn := newProxiedConn(
		stream, masqueAddr{"local"}, masqueAddr{"remote"}, nil,
	)
	defer conn.Close()
	if _, err := conn.DatagramCapacity(); err == nil {
		t.Fatal("an accepted capacity query was reported as a capacity")
	}
}

// capacityStub models quic-go's SendDatagram size check: a payload above limit
// is refused before anything is queued, so nothing reaches the peer. A negative
// limit accepts everything, which is the state this must never silently
// tolerate.
type capacityStub struct {
	streamID quic.StreamID
	limit    int64

	mu       sync.Mutex
	asked    int
	accepted int
}

func (s *capacityStub) SendDatagram(b []byte) error {
	// http3 prepends the quarter stream ID before the QUIC layer sees it.
	framed := len(quicvarint.Append(nil, uint64(s.streamID/4))) + len(b)
	s.mu.Lock()
	s.asked = framed
	accepted := s.limit < 0 || int64(framed) <= s.limit
	if accepted {
		s.accepted++
	}
	s.mu.Unlock()
	if !accepted {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: s.limit}
	}
	return nil
}

func (s *capacityStub) askedSize() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.asked
}

func (s *capacityStub) delivered() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted
}

func (s *capacityStub) StreamID() quic.StreamID { return s.streamID }

func (*capacityStub) Read([]byte) (int, error) { return 0, io.EOF }

func (*capacityStub) Write(b []byte) (int, error) { return len(b), nil }

func (*capacityStub) Close() error { return nil }

func (*capacityStub) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, io.EOF
}

func (*capacityStub) CancelRead(quic.StreamErrorCode) {}

func (*capacityStub) CancelWrite(quic.StreamErrorCode) {}

var _ http3Stream = &capacityStub{}
