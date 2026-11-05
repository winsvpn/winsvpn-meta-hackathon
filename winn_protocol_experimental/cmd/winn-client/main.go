package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"winsvpn.local/winnprotocol/internal/awg"
	"winsvpn.local/winnprotocol/internal/bootstrap"
	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/rotation"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

func main() {
	var endpoint string
	var certPath string
	var keyPath string
	var caPath string
	var serverName string
	var deviceID string
	var peerPublicKey string
	var clientStatePath string
	var suiteName string
	var controllerID string
	var devicePQSeed string
	var controllerPQPublic string
	var controllerPQPins string
	var applyFile string
	var awgBinary string
	var awgInterface string
	var timeout time.Duration
	var labMode bool
	var echConfigPath string

	flag.StringVar(&endpoint, "endpoint", "https://localhost:9443", "controller HTTPS origin")
	flag.StringVar(&certPath, "cert", "", "device certificate PEM")
	flag.StringVar(&keyPath, "key", "", "device private key PEM")
	flag.StringVar(&caPath, "ca", "", "trusted controller CA PEM")
	flag.StringVar(&serverName, "server-name", "localhost", "controller certificate name")
	flag.StringVar(&deviceID, "device-id", "", "device ID bound to the certificate")
	flag.StringVar(&peerPublicKey, "peer-public-key", "", "base64 AWG peer public key")
	flag.StringVar(&clientStatePath, "state", "", "durable client rotation state")
	flag.StringVar(&suiteName, "suite", protocol.DefaultSuite, "strict hybrid suite")
	flag.StringVar(&controllerID, "controller-id", "winn-controller-1", "pinned controller audience identifier")
	flag.StringVar(&devicePQSeed, "device-pq-seed", "", "device ML-DSA seed for the selected suite")
	flag.StringVar(&controllerPQPublic, "controller-pq-public", "", "pinned controller ML-DSA public key")
	flag.StringVar(&controllerPQPins, "controller-pq-pins", "", "pinned controller ML-DSA public-key set for overlap rotation")
	flag.StringVar(&applyFile, "apply-file", "", "lab-only client PSK output file")
	flag.StringVar(&awgBinary, "awg-bin", "", "real awg/amneziawg/wg binary")
	flag.StringVar(&awgInterface, "interface", "", "real AWG interface name")
	flag.DurationVar(&timeout, "timeout", 20*time.Second, "complete rotation timeout")
	flag.BoolVar(&labMode, "lab-mode", false, "enable explicitly non-production test adapters")
	flag.StringVar(&echConfigPath, "ech-config-list", "", "RFC 9849 ECHConfigList")
	flag.Parse()

	for name, value := range map[string]string{
		"-cert": certPath, "-key": keyPath, "-ca": caPath, "-device-id": deviceID,
		"-peer-public-key": peerPublicKey, "-state": clientStatePath,
		"-device-pq-seed": devicePQSeed, "-ech-config-list": echConfigPath,
	} {
		if value == "" {
			exitError(name + " is required")
		}
	}
	if (controllerPQPublic == "") == (controllerPQPins == "") {
		exitError("choose exactly one controller pin source: -controller-pq-public or -controller-pq-pins")
	}
	suite, err := tlsconfig.ParseSuite(suiteName)
	if err != nil {
		exitError(err.Error())
	}
	authAlgorithm := protocol.RequiredAuthAlgorithm(suite.Name)
	deviceSigner, err := pqauth.LoadSigner(authAlgorithm, devicePQSeed)
	if err != nil {
		exitError(err.Error())
	}
	defer deviceSigner.Destroy()
	var controllerPins *pqauth.VerifierSet
	if controllerPQPins != "" {
		controllerPins, err = pqauth.LoadVerifierSet(controllerPQPins)
	} else {
		controllerVerifier, loadErr := pqauth.LoadVerifier(authAlgorithm, controllerPQPublic)
		if loadErr != nil {
			exitError(loadErr.Error())
		}
		controllerPins, err = pqauth.NewVerifierSet(controllerVerifier)
	}
	if err != nil {
		exitError(err.Error())
	}
	applier, err := selectApplier(applyFile, awgBinary, awgInterface, labMode)
	if err != nil {
		exitError(err.Error())
	}
	tlsConfiguration, err := tlsconfig.Client(certPath, keyPath, caPath, serverName, suite)
	if err != nil {
		exitError(err.Error())
	}
	echList, err := echconfig.LoadClientConfigList(echConfigPath)
	if err != nil {
		exitError(err.Error())
	}
	if err := echconfig.ConfigureClient(tlsConfiguration, echList, true); err != nil {
		clear(echList)
		exitError(err.Error())
	}
	clear(echList)
	client, err := bootstrap.NewClientWithVerifierSet(endpoint, tlsConfiguration, suite, controllerID, deviceSigner, controllerPins)
	if err != nil {
		exitError(err.Error())
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	result, err := rotation.Run(ctx, client, applier, clientStatePath, deviceID, peerPublicKey, suite.Name)
	if err != nil {
		exitError(err.Error())
	}
	output := struct {
		Status     string `json:"status"`
		TLSVersion string `json:"tls"`
		rotation.Result
	}{
		Status:     "applied",
		TLSVersion: rotation.TLSVersionName(result.TLSVersion),
		Result:     result,
	}
	encoded, err := json.Marshal(output)
	if err != nil {
		exitError(err.Error())
	}
	fmt.Println(string(encoded))
}

func selectApplier(applyFile, binary, interfaceName string, labMode bool) (awg.Applier, error) {
	if applyFile != "" {
		if !labMode {
			return nil, errors.New("-apply-file requires -lab-mode")
		}
		if binary != "" || interfaceName != "" {
			return nil, errors.New("-apply-file cannot be combined with -awg-bin or -interface")
		}
		return awg.FileApplier{Path: applyFile}, nil
	}
	if binary == "" || interfaceName == "" {
		return nil, errors.New("choose -apply-file for a lab or both -awg-bin and -interface for a real tunnel")
	}
	return awg.CommandApplier{Binary: binary, Interface: interfaceName}, nil
}

func exitError(message string) {
	fmt.Fprintln(os.Stderr, "winn-client:", message)
	os.Exit(1)
}
