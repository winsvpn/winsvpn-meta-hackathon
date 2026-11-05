// Package echconfig manages RFC 9849 Encrypted Client Hello material without
// weakening Winn's independent hybrid TLS key-exchange requirement.
package echconfig

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"winsvpn.local/winnprotocol/internal/securefile"
)

const (
	KeyFileFormat = "winn-ech-key-set/v1"
	MaxConfigSize = 64 << 10

	echVersion       = 0xfe0d
	kemX25519HKDF256 = 0x0020
	kdfHKDFSHA256    = 0x0001
	aeadAES128GCM    = 0x0001
	aeadChaCha20     = 0x0003
)

type KeyEntry struct {
	Config      string `json:"config"`
	PrivateKey  string `json:"private_key"`
	SendAsRetry bool   `json:"send_as_retry"`
}

type KeyFile struct {
	Format string     `json:"format"`
	Keys   []KeyEntry `json:"keys"`
}

// Generate creates one X25519 HPKE ECH configuration and its server key. ECH
// protects handshake metadata; Winn's TLS named group remains hybrid
// ECDHE+ML-KEM and is not replaced by this X25519 HPKE key.
func Generate(publicName string, configID byte) ([]byte, KeyFile, error) {
	if !validPublicName(publicName) {
		return nil, KeyFile{}, errors.New("ECH public name must be a valid DNS name")
	}
	if configID == 0 {
		var randomID [1]byte
		if _, err := rand.Read(randomID[:]); err != nil {
			return nil, KeyFile{}, err
		}
		configID = randomID[0]
		if configID == 0 {
			configID = 1
		}
	}
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, KeyFile{}, err
	}
	config, err := marshalConfig(configID, publicName, privateKey.PublicKey().Bytes())
	if err != nil {
		return nil, KeyFile{}, err
	}
	if len(config) > int(^uint16(0)) {
		return nil, KeyFile{}, errors.New("ECH config is too large")
	}
	list := make([]byte, 2, 2+len(config))
	// #nosec G115 -- the preceding bound rejects lengths above uint16.
	binary.BigEndian.PutUint16(list, uint16(len(config)))
	list = append(list, config...)
	keyFile := KeyFile{
		Format: KeyFileFormat,
		Keys: []KeyEntry{{
			Config:      base64.StdEncoding.EncodeToString(config),
			PrivateKey:  base64.StdEncoding.EncodeToString(privateKey.Bytes()),
			SendAsRetry: true,
		}},
	}
	return list, keyFile, nil
}

func EncodeKeyFile(keys KeyFile) ([]byte, error) {
	if _, err := TLSKeys(keys); err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func LoadClientConfigList(path string) ([]byte, error) {
	data, err := securefile.ReadPublicIntegrity(path, MaxConfigSize)
	if err != nil {
		return nil, err
	}
	if err := validateConfigList(data); err != nil {
		clear(data)
		return nil, err
	}
	return data, nil
}

// ValidateConfigList parses the RFC 9849 ECHConfigList structure accepted by
// Winn's production TLS configuration.
func ValidateConfigList(data []byte) error {
	return validateConfigList(data)
}

func LoadServerKeys(path string) ([]tls.EncryptedClientHelloKey, error) {
	file, err := LoadKeyFile(path)
	if err != nil {
		return nil, err
	}
	return TLSKeys(file)
}

func TLSKeys(file KeyFile) ([]tls.EncryptedClientHelloKey, error) {
	if file.Format != KeyFileFormat || len(file.Keys) == 0 || len(file.Keys) > 8 {
		return nil, errors.New("unsupported or empty ECH key file")
	}
	result := make([]tls.EncryptedClientHelloKey, 0, len(file.Keys))
	for _, encoded := range file.Keys {
		config, err := base64.StdEncoding.Strict().DecodeString(encoded.Config)
		if err != nil {
			return nil, errors.New("invalid ECH config encoding")
		}
		if err := validateConfig(config); err != nil {
			clear(config)
			return nil, err
		}
		privateKey, err := base64.StdEncoding.Strict().DecodeString(encoded.PrivateKey)
		if err != nil || len(privateKey) != 32 {
			clear(config)
			clear(privateKey)
			return nil, errors.New("invalid ECH private key")
		}
		configPublicKey, err := publicKeyFromConfig(config)
		if err != nil {
			clear(config)
			clear(privateKey)
			return nil, err
		}
		parsedPrivateKey, err := ecdh.X25519().NewPrivateKey(privateKey)
		if err != nil || !bytes.Equal(
			parsedPrivateKey.PublicKey().Bytes(), configPublicKey,
		) {
			clear(config)
			clear(privateKey)
			clear(configPublicKey)
			return nil, errors.New(
				"ECH private key does not match config public key",
			)
		}
		clear(configPublicKey)
		result = append(result, tls.EncryptedClientHelloKey{
			Config: config, PrivateKey: privateKey, SendAsRetry: encoded.SendAsRetry,
		})
	}
	return result, nil
}

func ConfigureClient(config *tls.Config, configList []byte, required bool) error {
	if config == nil {
		return errors.New("tls client configuration is required")
	}
	if !required {
		if len(configList) != 0 {
			return errors.New("ech configuration supplied while ECH is disabled")
		}
		return nil
	}
	if err := validateConfigList(configList); err != nil {
		return err
	}
	config.EncryptedClientHelloConfigList = append([]byte(nil), configList...)
	previous := config.VerifyConnection
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if previous != nil {
			if err := previous(state); err != nil {
				return err
			}
		}
		if !state.ECHAccepted {
			return errors.New("winn requires accepted Encrypted Client Hello")
		}
		return nil
	}
	return nil
}

func ConfigureServer(config *tls.Config, keys []tls.EncryptedClientHelloKey, required bool) error {
	if config == nil {
		return errors.New("tls server configuration is required")
	}
	if !required {
		if len(keys) != 0 {
			return errors.New("ech keys supplied while ECH is disabled")
		}
		return nil
	}
	if len(keys) == 0 {
		return errors.New("winn requires at least one ECH server key")
	}
	config.EncryptedClientHelloKeys = append([]tls.EncryptedClientHelloKey(nil), keys...)
	previous := config.VerifyConnection
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if previous != nil {
			if err := previous(state); err != nil {
				return err
			}
		}
		if !state.ECHAccepted {
			return errors.New("winn requires accepted Encrypted Client Hello")
		}
		return nil
	}
	return nil
}

// ConfigureServerCover installs the same ECH keys on a cover listener without
// making ECH acceptance a precondition for the handshake.
//
// ConfigureServer is right for the Winn profile, where a peer that did not use
// ECH has no business being. It is wrong for the listener a censor reaches:
// there, refusing a non-ECH client is itself the tell. A real ECH deployment
// serves the public-name site to clients that did not use ECH, so the cover
// profile must complete those handshakes normally and let the application
// layer decide what the peer is entitled to.
//
// The keys must still be installed here because Go decrypts ECH from the
// listener's own configuration, before GetConfigForClient can select the Winn
// profile.
func ConfigureServerCover(config *tls.Config, keys []tls.EncryptedClientHelloKey) error {
	if config == nil {
		return errors.New("tls server configuration is required")
	}
	if len(keys) == 0 {
		return errors.New("winn requires at least one ECH server key")
	}
	config.EncryptedClientHelloKeys = append([]tls.EncryptedClientHelloKey(nil), keys...)
	return nil
}

func marshalConfig(configID byte, publicName string, publicKey []byte) ([]byte, error) {
	if len(publicKey) != 32 || len(publicName) > 255 {
		return nil, errors.New("invalid ECH public key or public name")
	}
	var contents bytes.Buffer
	contents.WriteByte(configID)
	writeUint16(&contents, kemX25519HKDF256)
	if err := writeOpaque16(&contents, publicKey); err != nil {
		return nil, err
	}
	var suites bytes.Buffer
	writeUint16(&suites, kdfHKDFSHA256)
	writeUint16(&suites, aeadAES128GCM)
	writeUint16(&suites, kdfHKDFSHA256)
	writeUint16(&suites, aeadChaCha20)
	if err := writeOpaque16(&contents, suites.Bytes()); err != nil {
		return nil, err
	}
	// Pad hidden server names up to the maximum DNS presentation length.
	contents.WriteByte(253)
	// #nosec G115 -- publicName was bounded to 255 bytes above.
	contents.WriteByte(byte(len(publicName)))
	contents.WriteString(publicName)
	writeUint16(&contents, 0)
	if contents.Len() > 65535 {
		return nil, errors.New("ECH config is too large")
	}
	var config bytes.Buffer
	writeUint16(&config, echVersion)
	if err := writeOpaque16(&config, contents.Bytes()); err != nil {
		return nil, err
	}
	return config.Bytes(), nil
}

func validateConfigList(data []byte) error {
	if len(data) < 6 || len(data) > MaxConfigSize ||
		int(binary.BigEndian.Uint16(data[:2])) != len(data)-2 {
		return errors.New("invalid ECHConfigList framing")
	}
	remaining := data[2:]
	var count int
	for len(remaining) > 0 {
		if len(remaining) < 4 {
			return errors.New("truncated ECH config")
		}
		length := int(binary.BigEndian.Uint16(remaining[2:4])) + 4
		if length > len(remaining) {
			return errors.New("truncated ECH config")
		}
		if err := validateConfig(remaining[:length]); err != nil {
			return err
		}
		count++
		remaining = remaining[length:]
	}
	if count == 0 {
		return errors.New("ECHConfigList is empty")
	}
	return nil
}

func validateConfig(config []byte) error {
	if len(config) < 4 || binary.BigEndian.Uint16(config[:2]) != echVersion ||
		int(binary.BigEndian.Uint16(config[2:4])) != len(config)-4 {
		return errors.New("invalid RFC 9849 ECH config framing")
	}
	contents := config[4:]
	if len(contents) < 1+2+2+2+1+1+2 {
		return errors.New("truncated RFC 9849 ECH config contents")
	}
	contents = contents[1:] // config_id
	if binary.BigEndian.Uint16(contents[:2]) != kemX25519HKDF256 {
		return errors.New("unsupported ECH HPKE KEM")
	}
	contents = contents[2:]
	publicKey, rest, err := readOpaque16(contents)
	if err != nil || len(publicKey) != 32 {
		return errors.New("invalid ECH public key")
	}
	var nonzero byte
	for _, current := range publicKey {
		nonzero |= current
	}
	if nonzero == 0 {
		return errors.New("ECH public key is all zero")
	}
	suites, rest, err := readOpaque16(rest)
	if err != nil || len(suites) == 0 || len(suites)%4 != 0 {
		return errors.New("invalid ECH cipher suites")
	}
	for len(suites) > 0 {
		kdf := binary.BigEndian.Uint16(suites[:2])
		aead := binary.BigEndian.Uint16(suites[2:4])
		if kdf != kdfHKDFSHA256 ||
			(aead != aeadAES128GCM && aead != aeadChaCha20) {
			return errors.New("unsupported ECH cipher suite")
		}
		suites = suites[4:]
	}
	if len(rest) < 2 {
		return errors.New("truncated ECH public name")
	}
	maximumNameLength := rest[0]
	publicNameLength := int(rest[1])
	rest = rest[2:]
	if publicNameLength == 0 || publicNameLength > len(rest) {
		return errors.New("invalid ECH public name length")
	}
	publicName := string(rest[:publicNameLength])
	rest = rest[publicNameLength:]
	if !validPublicName(publicName) ||
		int(maximumNameLength) < len(publicName) {
		return errors.New("invalid ECH public name")
	}
	extensions, rest, err := readOpaque16(rest)
	if err != nil || len(rest) != 0 {
		return errors.New("invalid ECH extension vector")
	}
	for len(extensions) > 0 {
		if len(extensions) < 4 {
			return errors.New("truncated ECH extension")
		}
		length := int(binary.BigEndian.Uint16(extensions[2:4]))
		if length > len(extensions)-4 {
			return errors.New("truncated ECH extension")
		}
		extensions = extensions[4+length:]
	}
	return nil
}

func publicKeyFromConfig(config []byte) ([]byte, error) {
	if len(config) < 4 ||
		binary.BigEndian.Uint16(config[:2]) != echVersion ||
		int(binary.BigEndian.Uint16(config[2:4])) != len(config)-4 {
		return nil, errors.New("invalid RFC 9849 ECH config framing")
	}
	contents := config[4:]
	if len(contents) < 3 {
		return nil, errors.New("truncated RFC 9849 ECH config contents")
	}
	contents = contents[1:]
	if binary.BigEndian.Uint16(contents[:2]) != kemX25519HKDF256 {
		return nil, errors.New("unsupported ECH HPKE KEM")
	}
	publicKey, _, err := readOpaque16(contents[2:])
	if err != nil || len(publicKey) != 32 {
		return nil, errors.New("invalid ECH public key")
	}
	return append([]byte(nil), publicKey...), nil
}

func readOpaque16(data []byte) ([]byte, []byte, error) {
	if len(data) < 2 {
		return nil, nil, io.ErrUnexpectedEOF
	}
	length := int(binary.BigEndian.Uint16(data[:2]))
	if length > len(data)-2 {
		return nil, nil, io.ErrUnexpectedEOF
	}
	return data[2 : 2+length], data[2+length:], nil
}

func writeUint16(buffer *bytes.Buffer, value uint16) {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	buffer.Write(encoded[:])
}

func writeOpaque16(buffer *bytes.Buffer, value []byte) error {
	if len(value) > int(^uint16(0)) {
		return errors.New("ECH opaque value is too large")
	}
	// #nosec G115 -- the preceding bound rejects lengths above uint16.
	writeUint16(buffer, uint16(len(value)))
	buffer.Write(value)
	return nil
}

func validPublicName(value string) bool {
	if len(value) == 0 || len(value) > 253 || strings.HasPrefix(value, ".") ||
		strings.HasSuffix(value, ".") || strings.Contains(value, "..") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func PublicConfigListBase64(configList []byte) (string, error) {
	if err := validateConfigList(configList); err != nil {
		return "", fmt.Errorf("encode ECHConfigList: %w", err)
	}
	return base64.StdEncoding.EncodeToString(configList), nil
}
