package directawg

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const maxCLIOutput = 1 << 20

var interfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.=-]{1,64}$`)

// CLIStatusSource reads one peer through secret-free `awg/wg show IFACE
// latest-handshakes`, `transfer`, and `endpoints` queries. It deliberately does
// not use `show ... dump`, whose output contains the interface private key and
// peer preshared keys. The binary is executed directly without a shell.
type CLIStatusSource struct {
	binary        string
	interfaceName string
	peerPublicKey string
	run           func(context.Context, string, ...string) ([]byte, error)
}

func NewCLIStatusSource(
	binary string,
	interfaceName string,
	peerPublicKey string,
) (*CLIStatusSource, error) {
	if !filepath.IsAbs(binary) {
		return nil, errors.New("AWG status binary path must be absolute")
	}
	info, err := os.Stat(binary)
	if err != nil {
		return nil, fmt.Errorf("inspect AWG status binary: %w", err)
	}
	if !info.Mode().IsRegular() ||
		(runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0) {
		return nil, errors.New("AWG status binary must be executable")
	}
	if !interfaceNamePattern.MatchString(interfaceName) {
		return nil, errors.New("AWG status interface name is invalid")
	}
	if err := validatePublicKey(peerPublicKey); err != nil {
		return nil, err
	}
	return &CLIStatusSource{
		binary:        binary,
		interfaceName: interfaceName,
		peerPublicKey: peerPublicKey,
		run:           runBoundedStatusCommand,
	}, nil
}

func (source *CLIStatusSource) Status(ctx context.Context) (Status, error) {
	if ctx == nil {
		return Status{}, errors.New("AWG status context is required")
	}
	handshakeOutput, err := source.query(ctx, "latest-handshakes")
	if err != nil {
		return Status{}, err
	}
	handshake, err := parseLatestHandshake(
		handshakeOutput, source.peerPublicKey,
	)
	if err != nil {
		return Status{}, err
	}
	transferOutput, err := source.query(ctx, "transfer")
	if err != nil {
		return Status{}, err
	}
	rxBytes, txBytes, err := parseTransfer(
		transferOutput, source.peerPublicKey,
	)
	if err != nil {
		return Status{}, err
	}
	endpointOutput, err := source.query(ctx, "endpoints")
	if err != nil {
		return Status{}, err
	}
	endpoint, err := parseEndpoint(endpointOutput, source.peerPublicKey)
	if err != nil {
		return Status{}, err
	}
	return Status{
		PeerPublicKey:   source.peerPublicKey,
		PeerEndpoint:    endpoint,
		LatestHandshake: handshake,
		RxBytes:         rxBytes,
		TxBytes:         txBytes,
	}, nil
}

func (source *CLIStatusSource) query(
	ctx context.Context,
	field string,
) ([]byte, error) {
	switch field {
	case "latest-handshakes", "transfer", "endpoints":
	default:
		return nil, errors.New("unsupported AWG status query")
	}
	run := source.run
	if run == nil {
		run = runBoundedStatusCommand
	}
	output, err := run(
		ctx,
		source.binary,
		"show",
		source.interfaceName,
		field,
	)
	if err != nil {
		return nil, fmt.Errorf("AWG status %s query failed: %w", field, err)
	}
	return output, nil
}

func runBoundedStatusCommand(
	ctx context.Context,
	binary string,
	args ...string,
) ([]byte, error) {
	// #nosec G204 -- no shell is involved; binary is the controller's
	// validated, absolute AWG CLI path, and args are always exactly
	// ["show", interfaceName, field] with field restricted to a fixed
	// allow-list checked in query above.
	command := exec.CommandContext(
		ctx,
		binary,
		args...,
	)
	var stdout boundedBuffer
	var stderr boundedBuffer
	stdout.limit = maxCLIOutput
	stderr.limit = 64 << 10
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf(
			"command failed: %w: %s",
			err,
			strings.TrimSpace(stderr.String()),
		)
	}
	if stdout.exceeded {
		return nil, errors.New("command output exceeds limit")
	}
	return append([]byte(nil), stdout.Bytes()...), nil
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (buffer *boundedBuffer) Write(data []byte) (int, error) {
	total := len(data)
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining <= 0 {
		buffer.exceeded = true
		return total, nil
	}
	if len(data) > remaining {
		buffer.exceeded = true
		data = data[:remaining]
	}
	_, _ = buffer.buffer.Write(data)
	return total, nil
}

func (buffer *boundedBuffer) Bytes() []byte {
	return buffer.buffer.Bytes()
}

func (buffer *boundedBuffer) String() string {
	return buffer.buffer.String()
}

func parseLatestHandshake(
	data []byte,
	expectedPublicKey string,
) (time.Time, error) {
	fields, err := selectPeerFields(
		data, expectedPublicKey, 2, "latest-handshakes",
	)
	if err != nil {
		return time.Time{}, err
	}
	seconds, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || seconds < 0 {
		return time.Time{}, errors.New("AWG handshake timestamp is invalid")
	}
	if seconds == 0 {
		return time.Time{}, nil
	}
	return time.Unix(seconds, 0).UTC(), nil
}

func parseTransfer(
	data []byte,
	expectedPublicKey string,
) (uint64, uint64, error) {
	fields, err := selectPeerFields(
		data, expectedPublicKey, 3, "transfer",
	)
	if err != nil {
		return 0, 0, err
	}
	rxBytes, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, 0, errors.New("AWG receive counter is invalid")
	}
	txBytes, err := strconv.ParseUint(fields[2], 10, 64)
	if err != nil {
		return 0, 0, errors.New("AWG transmit counter is invalid")
	}
	return rxBytes, txBytes, nil
}

func parseEndpoint(data []byte, expectedPublicKey string) (string, error) {
	fields, err := selectPeerFields(
		data, expectedPublicKey, 2, "endpoints",
	)
	if err != nil {
		return "", err
	}
	if fields[1] == "" {
		return "", errors.New("AWG peer endpoint is empty")
	}
	return fields[1], nil
}

func selectPeerFields(
	data []byte,
	expectedPublicKey string,
	fieldCount int,
	query string,
) ([]string, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("AWG status %s output is empty", query)
	}
	text := strings.TrimRight(string(data), "\r\n")
	if text == "" {
		return nil, fmt.Errorf("AWG status %s output is empty", query)
	}
	lines := strings.Split(text, "\n")
	if len(lines) > 4096 {
		return nil, fmt.Errorf("AWG status %s line count is invalid", query)
	}
	seen := make(map[string]struct{}, len(lines))
	var selected []string
	for _, rawLine := range lines {
		line := strings.TrimSuffix(rawLine, "\r")
		if line == "" {
			return nil, fmt.Errorf(
				"AWG status %s contains an empty line", query,
			)
		}
		fields := strings.Split(line, "\t")
		if len(fields) != fieldCount {
			return nil, fmt.Errorf(
				"AWG status %s field count is invalid", query,
			)
		}
		if err := validatePublicKey(fields[0]); err != nil {
			return nil, fmt.Errorf(
				"AWG status %s peer key is invalid: %w", query, err,
			)
		}
		if _, duplicate := seen[fields[0]]; duplicate {
			return nil, fmt.Errorf(
				"AWG status %s repeats peer", query,
			)
		}
		seen[fields[0]] = struct{}{}
		if fields[0] == expectedPublicKey {
			selected = append([]string(nil), fields...)
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("AWG status %s peer is missing", query)
	}
	return selected, nil
}
