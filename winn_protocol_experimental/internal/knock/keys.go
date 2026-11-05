package knock

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"winsvpn.local/winnprotocol/internal/securefile"
)

// maxKeyFileBytes bounds the key file: a rotation overlap holds a
// handful of hex keys, so 16 KiB is generous while still refusing an
// unbounded read of an operator-supplied path.
const maxKeyFileBytes = 16 << 10

// LoadKeysFromFile reads one hex-encoded SPA key per non-empty,
// non-comment ('#'-prefixed) line from path.
//
// A server passes every returned key to NewGate, most current first, for
// rotation overlap (see Verify's doc). A client needs only its own single
// current key - keys[0] - and should treat a second line in its own key
// file as a configuration mistake worth surfacing, not something to
// silently pick one of; this function does not enforce that, since it does
// not know which role its caller is playing.
//
// The file's raw bytes are cleared after decoding. The decoded keys
// themselves are returned to the caller and are not this function's to
// clear - a Gate built from them needs to retain them for its own
// lifetime. Nothing here logs a key or any byte derived from one.
func LoadKeysFromFile(path string) ([][]byte, error) {
	data, err := securefile.ReadPrivateLimited(path, maxKeyFileBytes)
	if err != nil {
		return nil, fmt.Errorf("knock: reading key file: %w", err)
	}
	defer clear(data)
	var keys [][]byte
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, decodeErr := hex.DecodeString(line)
		if decodeErr != nil {
			return nil, errors.New("knock: a key file line is not valid hex")
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, errors.New("knock: key file contains no keys")
	}
	return keys, nil
}
