package carrier

import (
	"bytes"
	"context"
	"net"
	"reflect"
	"testing"
	"time"
)

// This test uses only interfaces present in the pristine tree. The optional
// configuration field is set by reflection so the pristine run reaches a wire
// assertion rather than failing to compile.
func TestTCPFirstFlightUsesClientHelloRecord(t *testing.T) {
	sink := &collectConn{}
	secret := testSecret(t)
	cfg := StreamConfig{
		Conn: sink, Secret: secret, Role: RoleClient,
		Class: ClassTCP, Rand: &countingRand{},
	}
	firstFlight := reflect.ValueOf(&cfg).Elem().FieldByName("TCPFirstFlight")
	if firstFlight.IsValid() {
		firstFlight.SetBool(true)
	}
	stream, err := NewStream(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	want := message(128, 7)
	if err := stream.Send(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	wire := sink.buf
	if len(wire) < 9 || !bytes.Equal(wire[:3], []byte{0x16, 0x03, 0x01}) {
		t.Fatalf("first TCP wire bytes = %x, want a TLS ClientHello record", wire[:min(len(wire), 3)])
	}
	if int(wire[3])<<8|int(wire[4]) != len(wire)-5 || wire[5] != 1 {
		t.Fatal("first TCP wire record is not a complete ClientHello")
	}
	client, gateway := net.Pipe()
	defer client.Close()
	defer gateway.Close()
	serverCfg := StreamConfig{Conn: gateway, Secret: secret, Role: RoleGateway, Class: ClassTCP}
	serverFirstFlight := reflect.ValueOf(&serverCfg).Elem().FieldByName("TCPFirstFlight")
	if serverFirstFlight.IsValid() {
		serverFirstFlight.SetBool(true)
	}
	server, err := NewStream(serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() { _, _ = client.Write(wire) }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got, err := server.Recv(ctx)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("gateway decoded first flight: message=%x err=%v", got, err)
	}
}
