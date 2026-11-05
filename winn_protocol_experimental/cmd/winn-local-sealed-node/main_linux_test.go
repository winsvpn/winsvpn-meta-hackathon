//go:build linux && winn_incomplete_e8

package main

import (
	"bytes"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadExactContractAtIgnoresSCMRightsSharedOffset(t *testing.T) {
	const seals = unix.F_SEAL_WRITE | unix.F_SEAL_SHRINK |
		unix.F_SEAL_GROW | unix.F_SEAL_SEAL
	payload := []byte(`{"schema":"winn-test-contract/v1","value":"exact"}`)
	fd, err := unix.MemfdCreate(
		"winn-e8-offset-test",
		unix.MFD_ALLOW_SEALING|unix.MFD_CLOEXEC,
	)
	if err != nil {
		t.Fatal(err)
	}
	source := os.NewFile(uintptr(fd), "winn-e8-offset-test-source")
	if source == nil {
		_ = unix.Close(fd)
		t.Fatal("wrap source memfd")
	}
	defer source.Close()
	if count, err := source.Write(payload); err != nil ||
		count != len(payload) {
		t.Fatalf("write contract: count=%d err=%v", count, err)
	}
	if err := source.Sync(); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(source.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		t.Fatal(err)
	}
	if offset, err := source.Seek(0, io.SeekCurrent); err != nil ||
		offset != int64(len(payload)) {
		t.Fatalf("source offset is not adversarial EOF: %d %v", offset, err)
	}

	sockets, err := unix.Socketpair(
		unix.AF_UNIX,
		unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sockets[0])
	defer unix.Close(sockets[1])
	if err := unix.Sendmsg(
		sockets[0],
		[]byte("contract-ready"),
		unix.UnixRights(int(source.Fd())),
		nil,
		0,
	); err != nil {
		t.Fatal(err)
	}
	message := make([]byte, len("contract-ready"))
	control := make([]byte, unix.CmsgSpace(4))
	count, controlCount, flags, _, err := unix.Recvmsg(
		sockets[1], message, control, unix.MSG_CMSG_CLOEXEC,
	)
	if err != nil || count != len(message) ||
		!bytes.Equal(message, []byte("contract-ready")) ||
		flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 {
		t.Fatalf(
			"receive descriptor: count=%d flags=%d err=%v",
			count, flags, err,
		)
	}
	messages, err := unix.ParseSocketControlMessage(control[:controlCount])
	if err != nil || len(messages) != 1 {
		t.Fatalf("parse descriptor control: %v", err)
	}
	receivedFDs, err := unix.ParseUnixRights(&messages[0])
	if err != nil || len(receivedFDs) != 1 {
		t.Fatalf("parse descriptor rights: %v", err)
	}
	received := os.NewFile(
		uintptr(receivedFDs[0]), "winn-e8-offset-test-received",
	)
	if received == nil {
		_ = unix.Close(receivedFDs[0])
		t.Fatal("wrap received memfd")
	}
	defer received.Close()

	sourceInfo, sourceErr := source.Stat()
	receivedInfo, receivedErr := received.Stat()
	receivedSeals, sealsErr := unix.FcntlInt(
		received.Fd(), unix.F_GET_SEALS, 0,
	)
	receivedAccess, accessErr := unix.FcntlInt(
		received.Fd(), unix.F_GETFL, 0,
	)
	if sourceErr != nil || receivedErr != nil ||
		!os.SameFile(sourceInfo, receivedInfo) ||
		sealsErr != nil || receivedSeals != seals ||
		accessErr != nil || receivedAccess&unix.O_ACCMODE != unix.O_RDWR {
		t.Fatal("received contract identity, seals, or access differ")
	}
	before, err := received.Seek(0, io.SeekCurrent)
	if err != nil || before != int64(len(payload)) {
		t.Fatalf("SCM_RIGHTS did not preserve adversarial offset: %d %v", before, err)
	}
	replayed, err := readExactContractAt(
		received, receivedInfo.Size(), maxLocalRehearsalBytes,
	)
	if err != nil || !bytes.Equal(replayed, payload) {
		t.Fatalf("pread replay differs: %q %v", replayed, err)
	}
	after, err := received.Seek(0, io.SeekCurrent)
	if err != nil || after != before {
		t.Fatalf("pread changed shared offset: before=%d after=%d err=%v", before, after, err)
	}
}
