package directawg

import (
	"context"
	"errors"
	"net"
	"strconv"
	"time"
)

// UDPDialer opens a connected socket to an IP-literal endpoint. Requiring a
// signed literal prevents the direct path from leaking a hostname lookup before
// the protected DNS predicate is available.
type UDPDialer struct{}

func (UDPDialer) Dial(
	ctx context.Context,
	endpoint string,
) (net.PacketConn, error) {
	if ctx == nil {
		return nil, errors.New("UDP dial context is required")
	}
	if err := validateIPLiteralEndpoint(endpoint, false); err != nil {
		return nil, err
	}
	host, portText, _ := net.SplitHostPort(endpoint)
	port, _ := strconv.Atoi(portText)
	ip := net.ParseIP(host)
	network := "udp6"
	if ip.To4() != nil {
		network = "udp4"
	}
	var dialer net.Dialer
	raw, err := dialer.DialContext(ctx, network, endpoint)
	if err != nil {
		return nil, err
	}
	udp, ok := raw.(*net.UDPConn)
	if !ok {
		_ = raw.Close()
		return nil, errors.New("UDP dial did not return a UDP socket")
	}
	return &connectedPacketConn{
		UDPConn: udp,
		remote:  &net.UDPAddr{IP: ip, Port: port},
	}, nil
}

type connectedPacketConn struct {
	*net.UDPConn
	remote *net.UDPAddr
}

func (connection *connectedPacketConn) ReadFrom(
	packet []byte,
) (int, net.Addr, error) {
	count, err := connection.Read(packet)
	return count, cloneAddr(connection.remote), err
}

func (connection *connectedPacketConn) WriteTo(
	packet []byte,
	_ net.Addr,
) (int, error) {
	return connection.Write(packet)
}

func (connection *connectedPacketConn) SetDeadline(deadline time.Time) error {
	return connection.UDPConn.SetDeadline(deadline)
}

func cloneAddr(address *net.UDPAddr) *net.UDPAddr {
	if address == nil {
		return nil
	}
	result := *address
	result.IP = append(net.IP(nil), address.IP...)
	return &result
}
