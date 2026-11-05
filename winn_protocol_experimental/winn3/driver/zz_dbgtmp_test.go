package driver

import (
	"context"
	"net"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/session"
)

func TestZZDebugRig(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	sz := planSizing(t)
	kr := newKeyring(t)
	loopback := net.IPv4(127, 0, 0, 1)
	cliPort := reserveLoopbackPort(t, loopback)

	gwConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback, Port: 0})
	if err != nil {
		t.Skip(err)
	}
	defer gwConn.Close()
	gwAddr := gwConn.LocalAddr().(*net.UDPAddr)

	gwCar, err := carrier.NewUDP(carrier.UDPConfig{
		Conn: gwConn, Peer: &net.UDPAddr{IP: loopback, Port: cliPort},
		MaxMessageSize: sz.MessageSize, PathMTU: sz.PathMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	gw := newGatewayEndpoint(t, kr, endpointOpts{
		sizing: sz, carrier: gwCar,
		local: gatewayAddr(), router: clientAddr(),
	})
	defer gw.stop()
	gw.start(ctx)

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback, Port: cliPort})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	carEr, err := carrier.NewUDP(carrier.UDPConfig{
		Conn: conn, Peer: gwAddr,
		MaxMessageSize: sz.MessageSize, PathMTU: sz.PathMTU, OwnsConn: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	l, err := newNoTunClientLoop(kr, sz, carEr)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = l.Run(ctx) }()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(200 * time.Millisecond):
				t.Logf("client state=%v err=%v", l.Session().State(), l.Session().Err())
				if l.Session().State() == session.StateEstablished {
					return
				}
			}
		}
	}()
	time.Sleep(5 * time.Second)
}
