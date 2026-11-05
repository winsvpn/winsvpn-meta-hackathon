package echconfig

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"winsvpn.local/winnprotocol/internal/securefile"
)

// Per-node ECH rotation (Round GK OI-GK-3 step 1, 2026-09-26).
//
// Every data plane shipped with the same ECH key file. Replacing it outright
// would break any peer that cached the shared config, so a rotation is an
// OVERLAP: the new per-node key goes first with SendAsRetry set, and the old
// key stays second with SendAsRetry cleared. crypto/tls trial-decrypts against
// every installed key, so a holder of either config is accepted, and a peer
// whose config is rejected is handed only the new one as a retry config.
// Dropping the old entry is a later, separate step.

// EntryInfo is the PUBLIC description of one key-file entry. It carries no
// private key material and is safe to print, log or send to the hub.
type EntryInfo struct {
	ConfigID        byte
	PublicName      string
	PublicKeySHA256 string
	ConfigSHA256    string
	SendAsRetry     bool
}

// LoadKeyFile reads and fully validates an ECH key file, keeping the file form
// so a rotation can extend it. Unknown fields and trailing JSON are refused.
func LoadKeyFile(path string) (KeyFile, error) {
	data, err := securefile.ReadPrivateLimited(path, MaxConfigSize)
	if err != nil {
		return KeyFile{}, err
	}
	defer clear(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var file KeyFile
	if err := decoder.Decode(&file); err != nil {
		return KeyFile{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return KeyFile{}, errors.New("ECH key file contains extra JSON")
	}
	if _, err := TLSKeys(file); err != nil {
		return KeyFile{}, err
	}
	return file, nil
}

// Describe returns the public description of every entry, in file order.
func Describe(file KeyFile) ([]EntryInfo, error) {
	if _, err := TLSKeys(file); err != nil {
		return nil, err
	}
	result := make([]EntryInfo, 0, len(file.Keys))
	for _, entry := range file.Keys {
		config, err := base64.StdEncoding.Strict().DecodeString(entry.Config)
		if err != nil {
			return nil, errors.New("invalid ECH config encoding")
		}
		configID, publicName, publicKey, err := parseConfigPublic(config)
		if err != nil {
			return nil, err
		}
		keyDigest := sha256.Sum256(publicKey)
		configDigest := sha256.Sum256(config)
		result = append(result, EntryInfo{
			ConfigID:        configID,
			PublicName:      publicName,
			PublicKeySHA256: hex.EncodeToString(keyDigest[:]),
			ConfigSHA256:    hex.EncodeToString(configDigest[:]),
			SendAsRetry:     entry.SendAsRetry,
		})
	}
	return result, nil
}

// RetryConfigList is the ECHConfigList formed by the SendAsRetry entries: what
// the server hands a peer whose ECH it could not decrypt. For a file written
// by Generate or Rotate it equals the ech-config-list.bin written beside it.
func RetryConfigList(file KeyFile) ([]byte, error) {
	if _, err := TLSKeys(file); err != nil {
		return nil, err
	}
	var configs bytes.Buffer
	for _, entry := range file.Keys {
		if !entry.SendAsRetry {
			continue
		}
		config, err := base64.StdEncoding.Strict().DecodeString(entry.Config)
		if err != nil {
			return nil, errors.New("invalid ECH config encoding")
		}
		configs.Write(config)
	}
	if configs.Len() == 0 {
		return nil, errors.New("ECH key file has no send_as_retry entry")
	}
	if configs.Len() > int(^uint16(0)) {
		return nil, errors.New("ECH config list is too large")
	}
	list := make([]byte, 2, 2+configs.Len())
	// #nosec G115 -- the preceding bound rejects lengths above uint16.
	binary.BigEndian.PutUint16(list, uint16(configs.Len()))
	return append(list, configs.Bytes()...), nil
}

// Rotate returns a two-entry key file: a freshly generated key first, with
// SendAsRetry, then the existing key with SendAsRetry cleared. The returned
// list is the new key's ECHConfigList only.
//
// existing must hold exactly one entry. Two or more means an overlap is
// already in progress; rotating again would push the oldest key further back
// instead of retiring it, so that is refused. An empty publicName keeps the
// existing entry's public name, which is what keeps outer SNI, the cover
// certificate and the ECH public name one coherent origin. configID 0 draws a
// random ID different from the existing one.
func Rotate(existing KeyFile, publicName string, configID byte) ([]byte, KeyFile, error) {
	current, err := Describe(existing)
	if err != nil {
		return nil, KeyFile{}, err
	}
	if len(current) != 1 {
		return nil, KeyFile{}, fmt.Errorf(
			"ECH key file holds %d entries; an overlap is already in progress. "+
				"Drop the old entry before rotating again", len(current))
	}
	if publicName == "" {
		publicName = current[0].PublicName
	}
	if configID == current[0].ConfigID && configID != 0 {
		return nil, KeyFile{}, fmt.Errorf(
			"config ID %d is the existing key's; the new key needs its own", configID)
	}
	for configID == 0 || configID == current[0].ConfigID {
		var randomID [1]byte
		if _, err := rand.Read(randomID[:]); err != nil {
			return nil, KeyFile{}, err
		}
		configID = randomID[0]
	}
	list, generated, err := Generate(publicName, configID)
	if err != nil {
		return nil, KeyFile{}, err
	}
	fresh, err := Describe(generated)
	if err != nil {
		clear(list)
		return nil, KeyFile{}, err
	}
	if fresh[0].PublicKeySHA256 == current[0].PublicKeySHA256 {
		clear(list)
		return nil, KeyFile{}, errors.New("generated ECH key equals the existing key")
	}
	old := existing.Keys[0]
	old.SendAsRetry = false
	rotated := KeyFile{
		Format: KeyFileFormat,
		Keys:   []KeyEntry{generated.Keys[0], old},
	}
	if _, err := TLSKeys(rotated); err != nil {
		clear(list)
		return nil, KeyFile{}, err
	}
	return list, rotated, nil
}

// parseConfigPublic extracts the public fields of one validated ECHConfig.
func parseConfigPublic(config []byte) (byte, string, []byte, error) {
	if err := validateConfig(config); err != nil {
		return 0, "", nil, err
	}
	contents := config[4:]
	configID := contents[0]
	publicKey, rest, err := readOpaque16(contents[3:])
	if err != nil {
		return 0, "", nil, err
	}
	_, rest, err = readOpaque16(rest)
	if err != nil || len(rest) < 2 {
		return 0, "", nil, errors.New("truncated ECH public name")
	}
	nameLength := int(rest[1])
	if nameLength > len(rest)-2 {
		return 0, "", nil, errors.New("invalid ECH public name length")
	}
	return configID, string(rest[2 : 2+nameLength]), append([]byte(nil), publicKey...), nil
}
