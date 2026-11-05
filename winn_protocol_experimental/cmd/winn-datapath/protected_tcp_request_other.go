//go:build !unix

package main

import (
	"context"
	"errors"
)

func (s *winn3FrameServer) requestTCPDescriptor(context.Context) (int, error) {
	return -1, errors.New("protected TCP request channel needs a Unix socket")
}
