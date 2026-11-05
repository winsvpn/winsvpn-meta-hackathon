package awg

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"

	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/securefile"
)

type Applier interface {
	Apply(context.Context, string, []byte) error
	Description() string
}

// CurrentPSKSource returns a uniquely owned copy of the PSK that is currently
// applied to peerPublicKey. Callers own and must clear the returned bytes.
// Implementations must not return a requested-but-not-yet-applied key.
type CurrentPSKSource interface {
	ReadCurrentPSK(context.Context, string) ([]byte, error)
}

type FileApplier struct {
	Path string
}

func (a FileApplier) Apply(_ context.Context, peerPublicKey string, psk []byte) error {
	if err := protocol.ValidatePeerPublicKey(peerPublicKey); err != nil {
		return err
	}
	if err := validatePSK(psk); err != nil {
		return err
	}
	data := []byte(base64.StdEncoding.EncodeToString(psk) + "\n")
	defer clear(data)
	return securefile.AtomicWrite(a.Path, data, 0o600)
}

func (a FileApplier) Description() string {
	return "private-file:" + a.Path
}

func (a FileApplier) ReadCurrentPSK(
	ctx context.Context,
	peerPublicKey string,
) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if cause := context.Cause(ctx); cause != nil {
		return nil, cause
	}
	if err := protocol.ValidatePeerPublicKey(peerPublicKey); err != nil {
		return nil, err
	}
	data, err := securefile.ReadPrivateLimited(a.Path, 128)
	if errors.Is(err, os.ErrNotExist) {
		initial := make([]byte, 32)
		if _, randomErr := rand.Read(initial); randomErr != nil {
			return nil, fmt.Errorf("initialize applied PSK: %w", randomErr)
		}
		if err := validatePSK(initial); err != nil {
			clear(initial)
			return nil, fmt.Errorf("initialize applied PSK: %w", err)
		}
		encoded := []byte(base64.StdEncoding.EncodeToString(initial) + "\n")
		writeErr := securefile.AtomicWrite(a.Path, encoded, 0o600)
		clear(encoded)
		if writeErr != nil {
			clear(initial)
			return nil, fmt.Errorf("initialize applied PSK: %w", writeErr)
		}
		return initial, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read applied PSK: %w", err)
	}
	defer clear(data)
	psk, err := decodeAppliedPSK(bytes.TrimSpace(data))
	if err != nil {
		return nil, err
	}
	if cause := context.Cause(ctx); cause != nil {
		clear(psk)
		return nil, cause
	}
	return psk, nil
}

type CommandApplier struct {
	Binary    string
	Interface string
	TempDir   string
}

var interfacePattern = regexp.MustCompile(`^[A-Za-z0-9_.=-]{1,64}$`)

func (a CommandApplier) Apply(ctx context.Context, peerPublicKey string, psk []byte) error {
	if err := protocol.ValidatePeerPublicKey(peerPublicKey); err != nil {
		return err
	}
	if err := validatePSK(psk); err != nil {
		return err
	}
	if err := a.validate(); err != nil {
		return err
	}

	baseDir := a.TempDir
	if baseDir == "" {
		baseDir = os.TempDir()
	}
	privateDir, err := os.MkdirTemp(baseDir, "winn-psk-*")
	if err != nil {
		return fmt.Errorf("create private PSK directory: %w", err)
	}
	// #nosec G302 -- this is a directory; 0700 is the intended private mode.
	if err := os.Chmod(privateDir, 0o700); err != nil {
		_ = os.Remove(privateDir)
		return fmt.Errorf("secure private PSK directory: %w", err)
	}
	pskPath := filepath.Join(privateDir, "preshared-key")
	encoded := []byte(base64.StdEncoding.EncodeToString(psk) + "\n")
	if err := securefile.AtomicWrite(pskPath, encoded, 0o600); err != nil {
		clear(encoded)
		_ = os.Remove(privateDir)
		return err
	}
	clear(encoded)
	defer func() {
		_ = os.Remove(pskPath)
		_ = os.Remove(privateDir)
	}()

	// #nosec G204 -- no shell is involved; the binary is an absolute regular
	// executable, the interface is allowlisted, and the peer key is canonical.
	command := exec.CommandContext(
		ctx,
		a.Binary,
		"set",
		a.Interface,
		"peer",
		peerPublicKey,
		"preshared-key",
		pskPath,
	)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return fmt.Errorf("AWG command failed: %w", err)
	}
	return nil
}

func (a CommandApplier) Description() string {
	return "command:" + a.Binary + ":" + a.Interface
}

func (a CommandApplier) ReadCurrentPSK(
	ctx context.Context,
	peerPublicKey string,
) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if cause := context.Cause(ctx); cause != nil {
		return nil, cause
	}
	if err := protocol.ValidatePeerPublicKey(peerPublicKey); err != nil {
		return nil, err
	}
	if err := a.validate(); err != nil {
		return nil, err
	}
	// #nosec G204 -- no shell is involved; validate requires an absolute
	// executable and an allowlisted interface name.
	command := exec.CommandContext(
		ctx, a.Binary, "show", a.Interface, "preshared-keys",
	)
	command.Stderr = io.Discard
	output, err := command.Output()
	if err != nil {
		clear(output)
		return nil, fmt.Errorf("read applied AWG PSK: %w", err)
	}
	defer clear(output)
	var encoded []byte
	for _, line := range bytes.Split(output, []byte{'\n'}) {
		fields := bytes.Fields(line)
		if len(fields) != 2 ||
			!bytes.Equal(fields[0], []byte(peerPublicKey)) {
			continue
		}
		if encoded != nil {
			return nil, errors.New(
				"AWG reported duplicate peer PSKs",
			)
		}
		encoded = fields[1]
	}
	if encoded == nil {
		return nil, errors.New("AWG did not report the requested peer PSK")
	}
	psk, err := decodeAppliedPSK(encoded)
	if err != nil {
		return nil, err
	}
	if cause := context.Cause(ctx); cause != nil {
		clear(psk)
		return nil, cause
	}
	return psk, nil
}

func (a CommandApplier) validate() error {
	if a.Binary == "" {
		return errors.New("AWG command path is required")
	}
	if !filepath.IsAbs(a.Binary) {
		return errors.New("AWG command path must be absolute")
	}
	binaryInfo, err := os.Stat(a.Binary)
	if err != nil {
		return fmt.Errorf("inspect AWG command: %w", err)
	}
	if !binaryInfo.Mode().IsRegular() ||
		(runtime.GOOS != "windows" &&
			binaryInfo.Mode().Perm()&0o111 == 0) {
		return errors.New(
			"AWG command must be a regular executable file",
		)
	}
	if !interfacePattern.MatchString(a.Interface) {
		return errors.New("invalid AWG interface name")
	}
	return nil
}

func validatePSK(psk []byte) error {
	if len(psk) != 32 {
		return errors.New("PSK must be exactly 32 bytes")
	}
	if allZero(psk) {
		return errors.New("PSK must not be all zero")
	}
	return nil
}

func decodeAppliedPSK(encoded []byte) ([]byte, error) {
	decoded := make(
		[]byte,
		base64.StdEncoding.DecodedLen(len(encoded)),
	)
	length, err := base64.StdEncoding.Strict().Decode(decoded, encoded)
	if err != nil {
		clear(decoded)
		return nil, errors.New("applied PSK encoding is invalid")
	}
	decoded = decoded[:length]
	if len(decoded) != 32 || allZero(decoded) {
		clear(decoded)
		return nil, errors.New("applied PSK is invalid")
	}
	return decoded, nil
}

func allZero(value []byte) bool {
	var combined byte
	for _, current := range value {
		combined |= current
	}
	return combined == 0
}

var (
	_ CurrentPSKSource = FileApplier{}
	_ CurrentPSKSource = CommandApplier{}
)
