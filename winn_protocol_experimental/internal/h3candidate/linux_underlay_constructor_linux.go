//go:build linux

package h3candidate

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	"github.com/quic-go/quic-go"
)

// NewLinuxProtectedUnderlayFactory constructs a QUIC underlay factory that
// binds and marks every initial and migration socket before use.
func NewLinuxProtectedUnderlayFactory(
	config LinuxProtectedUnderlayConfig,
) (ProtectedUnderlayFactory, error) {
	return newLinuxProtectedUnderlayFactory(
		config,
		linuxRealProtectedPacketOpener{},
		netLinuxInterfaceInspector{},
		dialLinuxQUICPath,
		nil,
	)
}

type netLinuxInterfaceInspector struct{}

func (netLinuxInterfaceInspector) Check(name string) error {
	networkInterface, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	if networkInterface.Flags&net.FlagUp == 0 {
		return errors.New("interface is down")
	}
	return nil
}

func dialLinuxQUICPath(
	ctx context.Context,
	socket net.PacketConn,
	remote *net.UDPAddr,
	tlsConfig *tls.Config,
	quicConfig *quic.Config,
) (*quic.Conn, *quic.Transport, error) {
	transport := &quic.Transport{
		Conn:               socket,
		ConnectionIDLength: 8,
	}
	connection, err := transport.Dial(
		ctx, remote, tlsConfig, quicConfig,
	)
	if err != nil {
		_ = transport.Close()
		return nil, nil, err
	}
	return connection, transport, nil
}
