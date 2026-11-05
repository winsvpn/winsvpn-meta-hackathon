//go:build !linux

package main

import (
	"context"
	"errors"
	"net"
)

func connectProtectedTCP(context.Context, int, *net.UDPAddr) (net.Conn, error) {
	return nil, errors.New("protected TCP descriptor connect is available on Linux and Android")
}
