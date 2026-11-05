// Command winn-leak-canary-v2 is the controlled UDP echo endpoint used by the
// acceptance gateway. It records fsync'd, run-bound evidence and intentionally
// implements no other protocol.
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type event struct {
	Version  string `json:"version"`
	At       string `json:"at"`
	RunID    string `json:"run_id"`
	PeerIP   string `json:"peer_ip"`
	PeerPort uint16 `json:"peer_port"`
	Bytes    int    `json:"bytes"`
}

func main() {
	listen := flag.String("listen", "", "IP-literal UDP address:port")
	runID := flag.String("run-id", "", "lowercase 32-hex run identifier")
	evidencePath := flag.String("evidence-log", "", "exclusive absolute JSONL evidence")
	readyPath := flag.String("ready-file", "", "exclusive absolute readiness JSON")
	flag.Parse()
	if flag.NArg() != 0 || !lowerHex(*runID, 16) {
		fatal(errors.New("run-id must be lowercase 32-hex"))
	}
	address, err := netip.ParseAddrPort(*listen)
	if err != nil || address.Port() == 0 || address.Addr().IsUnspecified() {
		fatal(errors.New("listen must be a usable IP-literal address:port"))
	}
	evidence, err := exclusivePrivateFile(*evidencePath)
	if err != nil {
		fatal(err)
	}
	defer evidence.Close()
	connection, err := net.ListenUDP(
		func() string {
			if address.Addr().Is4() {
				return "udp4"
			}
			return "udp6"
		}(),
		net.UDPAddrFromAddrPort(address),
	)
	if err != nil {
		fatal(err)
	}
	defer connection.Close()
	if err := writeReady(*readyPath, map[string]any{
		"version": "winn-leak-canary-ready/v2",
		"run_id":  *runID,
		"pid":     os.Getpid(),
		"listen":  address.String(),
	}); err != nil {
		fatal(err)
	}
	encoder := json.NewEncoder(evidence)
	buffer := make([]byte, 2048)
	for {
		count, peer, err := connection.ReadFromUDPAddrPort(buffer)
		if err != nil {
			fatal(err)
		}
		if count == 0 {
			continue
		}
		if _, err := connection.WriteToUDPAddrPort(buffer[:count], peer); err != nil {
			fatal(err)
		}
		if err := encoder.Encode(event{
			Version: "winn-leak-canary-event/v2",
			At:      time.Now().UTC().Format(time.RFC3339Nano),
			RunID:   *runID, PeerIP: peer.Addr().Unmap().String(),
			PeerPort: peer.Port(), Bytes: count,
		}); err != nil {
			fatal(err)
		}
		if err := evidence.Sync(); err != nil {
			fatal(err)
		}
	}
}

func exclusivePrivateFile(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("output path must be absolute and clean")
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
		info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("output parent must be a private real directory")
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, err
	}
	file, openErr := root.OpenFile(
		filepath.Base(path),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0o600,
	)
	closeErr := root.Close()
	if openErr != nil {
		return nil, openErr
	}
	if closeErr != nil {
		_ = file.Close()
		return nil, closeErr
	}
	return file, nil
}

func writeReady(path string, value any) error {
	file, err := exclusivePrivateFile(path)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return errors.Join(encoder.Encode(value), file.Sync(), file.Close())
}

func lowerHex(value string, bytes int) bool {
	if len(value) != bytes*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == bytes
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
