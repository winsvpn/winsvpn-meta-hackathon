package masque

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
)

func TestWriteToReportsZeroBytesOnSendError(t *testing.T) {
	want := errors.New("send failed")
	stream := &writeResultStream{sendErr: want}
	conn := newProxiedConn(stream, masqueAddr{"local"}, masqueAddr{"remote"}, nil)
	defer conn.Close()

	payload := []byte("hello")
	n, err := conn.WriteTo(payload, nil)
	if n != 0 {
		t.Fatalf("WriteTo n = %d, want 0 when SendDatagram fails", n)
	}
	if !errors.Is(err, want) {
		t.Fatalf("WriteTo err = %v, want %v", err, want)
	}
}

func TestWriteToReturnsPayloadLengthOnSuccess(t *testing.T) {
	stream := &writeResultStream{}
	conn := newProxiedConn(stream, masqueAddr{"local"}, masqueAddr{"remote"}, nil)
	defer conn.Close()

	payload := []byte("hello")
	n, err := conn.WriteTo(payload, nil)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("WriteTo n = %d, want %d", n, len(payload))
	}
	if got := stream.lastSent; len(got) < 1 || got[0] != 0 {
		t.Fatalf("WriteTo framed payload = %v, want context ID 0 prefix", got)
	}
}

func TestWriteToAfterCloseReturnsErrClosed(t *testing.T) {
	stream := &writeResultStream{}
	conn := newProxiedConn(stream, masqueAddr{"local"}, masqueAddr{"remote"}, nil)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	n, err := conn.WriteTo([]byte("x"), nil)
	if n != 0 {
		t.Fatalf("WriteTo after Close n = %d, want 0", n)
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("WriteTo after Close err = %v, want net.ErrClosed", err)
	}
	if stream.sendCalls != 0 {
		t.Fatalf("WriteTo after Close still called SendDatagram %d times", stream.sendCalls)
	}
}

func TestReadFromAfterCloseReturnsErrClosed(t *testing.T) {
	stream := &writeResultStream{}
	conn := newProxiedConn(stream, masqueAddr{"local"}, masqueAddr{"remote"}, nil)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	n, addr, err := conn.ReadFrom(make([]byte, 8))
	if n != 0 || addr != nil {
		t.Fatalf("ReadFrom after Close n=%d addr=%v, want 0, nil", n, addr)
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReadFrom after Close err = %v, want net.ErrClosed", err)
	}
}

func TestReadFromDropsNonZeroContextIDAndDeliversNext(t *testing.T) {
	drop := append(quicvarint.Append(nil, 1), []byte("dropme")...)
	keep := append(quicvarint.Append(nil, 0), []byte("keep")...)
	stream := &writeResultStream{datagrams: [][]byte{drop, keep}}
	conn := newProxiedConn(stream, masqueAddr{"local"}, masqueAddr{"remote"}, nil)
	defer conn.Close()

	buf := make([]byte, 16)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != "keep" {
		t.Fatalf("ReadFrom data = %q, want %q", buf[:n], "keep")
	}
}

type writeResultStream struct {
	sendErr   error
	sendCalls int
	lastSent  []byte
	datagrams [][]byte
	readAt    int
}

func (s *writeResultStream) SendDatagram(b []byte) error {
	s.sendCalls++
	s.lastSent = append([]byte(nil), b...)
	return s.sendErr
}

func (s *writeResultStream) ReceiveDatagram(context.Context) ([]byte, error) {
	if s.readAt >= len(s.datagrams) {
		return nil, io.EOF
	}
	d := s.datagrams[s.readAt]
	s.readAt++
	return d, nil
}

func (*writeResultStream) Read([]byte) (int, error) { return 0, io.EOF }

func (*writeResultStream) Write(b []byte) (int, error) { return len(b), nil }

func (*writeResultStream) Close() error { return nil }

func (*writeResultStream) StreamID() quic.StreamID { return 0 }

func (*writeResultStream) CancelRead(quic.StreamErrorCode) {}

func (*writeResultStream) CancelWrite(quic.StreamErrorCode) {}

var _ http3Stream = &writeResultStream{}
