package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/privacytoken"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/securefile"
)

type Paths struct {
	CACert               string
	CAKey                string
	ServerCert           string
	ServerKey            string
	DeviceCert           string
	DeviceKey            string
	StateKey             string
	AuditKey             string
	ControllerPQ65Seed   string
	ControllerPQ65Public string
	ControllerPQ87Seed   string
	ControllerPQ87Public string
	ControllerPQPins     string
	DevicePQ65Seed       string
	DevicePQ65Public     string
	DevicePQ87Seed       string
	DevicePQ87Public     string
	DeviceRegistry       string
	ECHConfigList        string
	ECHServerKeys        string
	PrivacyTokenPrivate  string
	PrivacyTokenPublic   string
	DeviceID             string
	ServerName           string
	OutputDir            string
}

func GenerateLab(outputDir, serverName, deviceID string, now time.Time) (Paths, error) {
	if !protocol.ValidDeviceID(deviceID) {
		return Paths{}, errors.New("invalid device ID")
	}
	if serverName == "" {
		return Paths{}, errors.New("server name is required")
	}
	if entries, err := os.ReadDir(outputDir); err == nil && len(entries) != 0 {
		return Paths{}, fmt.Errorf("output directory %s is not empty", outputDir)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Paths{}, err
	}
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return Paths{}, err
	}
	// #nosec G302 -- this is a directory; 0700 is the intended private mode.
	if err := os.Chmod(outputDir, 0o700); err != nil {
		return Paths{}, err
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return Paths{}, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "Winn Protocol Experimental Lab CA"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return Paths{}, err
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return Paths{}, err
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: "Winn Protocol Experimental Controller"},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if address := net.ParseIP(serverName); address != nil {
		serverTemplate.IPAddresses = []net.IP{address}
	} else {
		serverTemplate.DNSNames = []string{serverName}
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		return Paths{}, err
	}

	deviceKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return Paths{}, err
	}
	deviceURI, err := url.Parse("spiffe://winn.local/device/" + deviceID)
	if err != nil {
		return Paths{}, err
	}
	deviceTemplate := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: "Winn Device " + deviceID},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{deviceURI},
	}
	deviceDER, err := x509.CreateCertificate(rand.Reader, deviceTemplate, caTemplate, &deviceKey.PublicKey, caKey)
	if err != nil {
		return Paths{}, err
	}

	paths := Paths{
		CACert:               filepath.Join(outputDir, "ca.pem"),
		CAKey:                filepath.Join(outputDir, "ca-key.pem"),
		ServerCert:           filepath.Join(outputDir, "server.pem"),
		ServerKey:            filepath.Join(outputDir, "server-key.pem"),
		DeviceCert:           filepath.Join(outputDir, "device.pem"),
		DeviceKey:            filepath.Join(outputDir, "device-key.pem"),
		StateKey:             filepath.Join(outputDir, "state.key"),
		AuditKey:             filepath.Join(outputDir, "audit.key"),
		ControllerPQ65Seed:   filepath.Join(outputDir, "controller-mldsa65.seed"),
		ControllerPQ65Public: filepath.Join(outputDir, "controller-mldsa65.pub"),
		ControllerPQ87Seed:   filepath.Join(outputDir, "controller-mldsa87.seed"),
		ControllerPQ87Public: filepath.Join(outputDir, "controller-mldsa87.pub"),
		ControllerPQPins:     filepath.Join(outputDir, "controller-pq-pins.json"),
		DevicePQ65Seed:       filepath.Join(outputDir, "device-mldsa65.seed"),
		DevicePQ65Public:     filepath.Join(outputDir, "device-mldsa65.pub"),
		DevicePQ87Seed:       filepath.Join(outputDir, "device-mldsa87.seed"),
		DevicePQ87Public:     filepath.Join(outputDir, "device-mldsa87.pub"),
		DeviceRegistry:       filepath.Join(outputDir, "device-pq-registry.json"),
		ECHConfigList:        filepath.Join(outputDir, "ech-config-list.bin"),
		ECHServerKeys:        filepath.Join(outputDir, "ech-server-keys.json"),
		PrivacyTokenPrivate:  filepath.Join(outputDir, "privacy-token-issuer-key.pem"),
		PrivacyTokenPublic:   filepath.Join(outputDir, "privacy-token-issuer-public.pem"),
		DeviceID:             deviceID,
		ServerName:           serverName,
		OutputDir:            outputDir,
	}
	if err := writeCert(paths.CACert, caDER); err != nil {
		return Paths{}, err
	}
	if err := writePrivateKey(paths.CAKey, caKey); err != nil {
		return Paths{}, err
	}
	if err := writeCert(paths.ServerCert, serverDER); err != nil {
		return Paths{}, err
	}
	if err := writePrivateKey(paths.ServerKey, serverKey); err != nil {
		return Paths{}, err
	}
	if err := writeCert(paths.DeviceCert, deviceDER); err != nil {
		return Paths{}, err
	}
	if err := writePrivateKey(paths.DeviceKey, deviceKey); err != nil {
		return Paths{}, err
	}
	stateKey := make([]byte, 32)
	if _, err := rand.Read(stateKey); err != nil {
		return Paths{}, err
	}
	if err := securefile.AtomicWrite(paths.StateKey, stateKey, 0o600); err != nil {
		clear(stateKey)
		return Paths{}, err
	}
	clear(stateKey)
	auditKey := make([]byte, 32)
	if _, err := rand.Read(auditKey); err != nil {
		return Paths{}, err
	}
	if err := securefile.AtomicWrite(paths.AuditKey, auditKey, 0o600); err != nil {
		clear(auditKey)
		return Paths{}, err
	}
	clear(auditKey)
	controller65, err := generatePQPair(pqauth.MLDSA65, paths.ControllerPQ65Seed, paths.ControllerPQ65Public)
	if err != nil {
		return Paths{}, err
	}
	controller87, err := generatePQPair(pqauth.MLDSA87, paths.ControllerPQ87Seed, paths.ControllerPQ87Public)
	if err != nil {
		return Paths{}, err
	}
	device65, err := generatePQPair(pqauth.MLDSA65, paths.DevicePQ65Seed, paths.DevicePQ65Public)
	if err != nil {
		return Paths{}, err
	}
	device87, err := generatePQPair(pqauth.MLDSA87, paths.DevicePQ87Seed, paths.DevicePQ87Public)
	if err != nil {
		return Paths{}, err
	}
	registry, err := pqauth.RegistryDocument(deviceID, device65, device87)
	if err != nil {
		return Paths{}, err
	}
	registryData, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return Paths{}, err
	}
	registryData = append(registryData, '\n')
	if err := securefile.AtomicWrite(paths.DeviceRegistry, registryData, 0o644); err != nil {
		return Paths{}, err
	}
	controllerPins, err := pqauth.VerifierSetDocument(controller65, controller87)
	if err != nil {
		return Paths{}, err
	}
	controllerPinData, err := json.MarshalIndent(controllerPins, "", "  ")
	if err != nil {
		return Paths{}, err
	}
	controllerPinData = append(controllerPinData, '\n')
	if err := securefile.AtomicWrite(paths.ControllerPQPins, controllerPinData, 0o644); err != nil {
		return Paths{}, err
	}
	echList, echKeys, err := echconfig.Generate("public.winn.invalid", 0)
	if err != nil {
		return Paths{}, err
	}
	echKeyData, err := echconfig.EncodeKeyFile(echKeys)
	if err != nil {
		clear(echList)
		return Paths{}, err
	}
	if err := securefile.AtomicWrite(paths.ECHConfigList, echList, 0o644); err != nil {
		clear(echList)
		clear(echKeyData)
		return Paths{}, err
	}
	clear(echList)
	if err := securefile.AtomicWrite(paths.ECHServerKeys, echKeyData, 0o600); err != nil {
		clear(echKeyData)
		return Paths{}, err
	}
	clear(echKeyData)
	tokenKey, err := privacytoken.GenerateIssuerKey(3072)
	if err != nil {
		return Paths{}, err
	}
	tokenPrivate, tokenPublic, err := privacytoken.MarshalIssuerKeys(tokenKey)
	if err != nil {
		return Paths{}, err
	}
	if err := securefile.AtomicWrite(paths.PrivacyTokenPrivate, tokenPrivate, 0o600); err != nil {
		clear(tokenPrivate)
		clear(tokenPublic)
		return Paths{}, err
	}
	clear(tokenPrivate)
	if err := securefile.AtomicWrite(paths.PrivacyTokenPublic, tokenPublic, 0o644); err != nil {
		clear(tokenPublic)
		return Paths{}, err
	}
	clear(tokenPublic)
	return paths, nil
}

func generatePQPair(algorithm, seedPath, publicPath string) (*pqauth.Signer, error) {
	seed, err := pqauth.GenerateSeed()
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	signer, err := pqauth.NewSigner(algorithm, seed)
	if err != nil {
		return nil, err
	}
	if err := securefile.AtomicWrite(seedPath, seed, 0o600); err != nil {
		return nil, err
	}
	publicKey := signer.PublicBytes()
	defer clear(publicKey)
	if err := securefile.AtomicWrite(publicPath, publicKey, 0o644); err != nil {
		return nil, err
	}
	return signer, nil
}

func writeCert(path string, der []byte) error {
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return securefile.AtomicWrite(path, data, 0o644)
}

func writePrivateKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	defer clear(der)
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer clear(data)
	return securefile.AtomicWrite(path, data, 0o600)
}

func randomSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	value, err := rand.Int(rand.Reader, limit)
	if err != nil {
		panic(err)
	}
	if value.Sign() == 0 {
		return big.NewInt(1)
	}
	return value
}
