package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/net/http2"

	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/privacytoken"
	"winsvpn.local/winnprotocol/internal/securefile"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

func main() {
	var issuerURL string
	var issuerPublicPath string
	var outputPath string
	var outputDirectory string
	var count int
	var certPath string
	var keyPath string
	var rootCAPath string
	var serverName string
	var deviceID string
	var deviceSeedPath string
	var deviceAlgorithm string
	var suiteName string
	var echConfigPath string
	var timeout time.Duration
	flag.StringVar(&issuerURL, "issuer-url", "", "HTTPS /winn/v1/privacy-token endpoint")
	flag.StringVar(&issuerPublicPath, "privacy-token-public-key", "", "blind RSA issuer public key PEM")
	flag.StringVar(&outputPath, "out", "", "new private token bundle path")
	flag.StringVar(
		&outputDirectory,
		"out-dir",
		"",
		"private directory for token-000001.json batch outputs",
	)
	flag.IntVar(
		&count,
		"count",
		1,
		"number of independent one-request/one-credential issuances",
	)
	flag.StringVar(&certPath, "cert", "", "device certificate PEM used only with the issuer")
	flag.StringVar(&keyPath, "key", "", "device private key PEM used only with the issuer")
	flag.StringVar(&rootCAPath, "root-ca", "", "trusted issuer server CA PEM")
	flag.StringVar(&serverName, "server-name", "", "issuer certificate DNS name or IP")
	flag.StringVar(&deviceID, "device-id", "", "device ID matching the certificate URI SAN")
	flag.StringVar(&deviceSeedPath, "device-pq-seed", "", "device ML-DSA seed")
	flag.StringVar(&deviceAlgorithm, "device-pq-algorithm", pqauth.MLDSA65, "device and ephemeral token ML-DSA algorithm")
	flag.StringVar(&suiteName, "suite", "x25519-mlkem768", "strict hybrid TLS suite")
	flag.StringVar(&echConfigPath, "ech-config-list", "", "RFC 9849 ECHConfigList")
	flag.DurationVar(&timeout, "timeout", 20*time.Second, "complete issuance timeout")
	flag.Parse()
	if issuerURL == "" || issuerPublicPath == "" ||
		certPath == "" || keyPath == "" || rootCAPath == "" ||
		serverName == "" || deviceID == "" || deviceSeedPath == "" ||
		echConfigPath == "" {
		exitError(errors.New("issuer-url, privacy-token-public-key, cert, key, root-ca, server-name, device-id, device-pq-seed, and ech-config-list are required"))
	}
	outputPaths, err := tokenOutputPaths(
		outputPath, outputDirectory, count,
	)
	if err != nil {
		exitError(err)
	}
	parsedRequest, err := http.NewRequest(http.MethodPost, issuerURL, nil)
	if err != nil || parsedRequest.URL.Scheme != "https" ||
		parsedRequest.URL.Path != privacytoken.IssuePath ||
		parsedRequest.URL.RawQuery != "" {
		exitError(errors.New("issuer-url must be an absolute HTTPS privacy-token issue URL without a query"))
	}
	issuerPublic, err := privacytoken.LoadIssuerPublicKey(issuerPublicPath)
	if err != nil {
		exitError(err)
	}
	deviceSigner, err := pqauth.LoadSigner(deviceAlgorithm, deviceSeedPath)
	if err != nil {
		exitError(err)
	}
	defer deviceSigner.Destroy()
	suite, err := tlsconfig.ParseSuite(suiteName)
	if err != nil {
		exitError(err)
	}
	tlsConfiguration, err := tlsconfig.ClientForALPN(
		certPath, keyPath, rootCAPath, serverName,
		suite, http2.NextProtoTLS,
	)
	if err != nil {
		exitError(err)
	}
	echList, err := echconfig.LoadClientConfigList(echConfigPath)
	if err != nil {
		exitError(err)
	}
	if err := echconfig.ConfigureClient(tlsConfiguration, echList, true); err != nil {
		clear(echList)
		exitError(err)
	}
	clear(echList)
	transport := &http.Transport{
		TLSClientConfig: tlsConfiguration, ForceAttemptHTTP2: true,
		DisableCompression: true, MaxConnsPerHost: 1,
		IdleConnTimeout: 15 * time.Second,
	}
	defer transport.CloseIdleConnections()
	client := tokenClient{
		issuerURL:       issuerURL,
		issuerPublic:    issuerPublic,
		deviceID:        deviceID,
		deviceAlgorithm: deviceAlgorithm,
		deviceSigner:    deviceSigner,
		suite:           suite,
		transport:       transport,
		timeout:         timeout,
	}
	for index, currentOutput := range outputPaths {
		bundle, issueErr := client.issue()
		if issueErr != nil {
			exitError(fmt.Errorf(
				"issuance %d/%d: %w",
				index+1, len(outputPaths), issueErr,
			))
		}
		encoded, encodeErr := privacytoken.EncodeBundle(bundle)
		if encodeErr != nil {
			exitError(fmt.Errorf(
				"encode issuance %d/%d: %w",
				index+1, len(outputPaths), encodeErr,
			))
		}
		if writeErr := securefile.AtomicWriteNew(
			currentOutput, encoded, 0o600,
		); writeErr != nil {
			clear(encoded)
			exitError(fmt.Errorf(
				"persist issuance %d/%d: %w",
				index+1, len(outputPaths), writeErr,
			))
		}
		clear(encoded)
		fmt.Println(currentOutput)
	}
	fmt.Printf("ISSUED count=%d\n", len(outputPaths))
}

type tokenClient struct {
	issuerURL       string
	issuerPublic    *rsa.PublicKey
	deviceID        string
	deviceAlgorithm string
	deviceSigner    *pqauth.Signer
	suite           tlsconfig.Suite
	transport       *http.Transport
	timeout         time.Duration
}

func (client tokenClient) issue() (privacytoken.Bundle, error) {
	issue, clientState, err := privacytoken.BeginIssue(
		client.issuerPublic, client.deviceAlgorithm,
	)
	if err != nil {
		return privacytoken.Bundle{}, err
	}
	body, err := json.Marshal(issue)
	if err != nil {
		return privacytoken.Bundle{}, err
	}
	defer clear(body)
	ctx, cancel := context.WithTimeout(
		context.Background(), client.timeout,
	)
	defer cancel()
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, client.issuerURL, bytes.NewReader(body),
	)
	if err != nil {
		return privacytoken.Bundle{}, err
	}
	request.Header.Set("Content-Type", privacytoken.IssueMediaType)
	request.Header.Set("Accept", privacytoken.IssueMediaType)
	if err := privacytoken.SignIssueAuthorization(
		request,
		issue,
		client.deviceID,
		client.deviceSigner,
		time.Now().UTC(),
	); err != nil {
		return privacytoken.Bundle{}, err
	}
	response, err := client.transport.RoundTrip(request)
	if err != nil {
		return privacytoken.Bundle{}, err
	}
	if response.StatusCode != http.StatusOK ||
		response.ProtoMajor != 2 ||
		response.Header.Get("Content-Type") != privacytoken.IssueMediaType {
		_ = response.Body.Close()
		return privacytoken.Bundle{}, fmt.Errorf(
			"privacy-token issuer returned invalid response "+
				"status=%d protocol=%s",
			response.StatusCode, response.Proto,
		)
	}
	if err := tlsconfig.ValidateStateForALPN(
		response.TLS, client.suite, http2.NextProtoTLS,
	); err != nil {
		_ = response.Body.Close()
		return privacytoken.Bundle{}, err
	}
	responseBody, readErr := io.ReadAll(
		io.LimitReader(response.Body, 32<<10),
	)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		clear(responseBody)
		return privacytoken.Bundle{}, errors.Join(readErr, closeErr)
	}
	defer clear(responseBody)
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	var issueResponse privacytoken.IssueResponse
	if err := decoder.Decode(&issueResponse); err != nil {
		return privacytoken.Bundle{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return privacytoken.Bundle{},
			errors.New(
				"privacy-token response contains trailing JSON",
			)
	}
	return clientState.Finalize(issueResponse)
}

func tokenOutputPaths(
	outputPath string,
	outputDirectory string,
	count int,
) ([]string, error) {
	if count < 1 || count > 8192 {
		return nil, errors.New("count must be within [1,8192]")
	}
	if (outputPath == "") == (outputDirectory == "") {
		return nil, errors.New(
			"exactly one of out or out-dir is required",
		)
	}
	if count > 1 && outputDirectory == "" {
		return nil, errors.New(
			"count greater than one requires out-dir",
		)
	}
	paths := make([]string, 0, count)
	if outputPath != "" {
		paths = append(paths, outputPath)
	} else {
		if err := securefile.EnsurePrivateDirectory(
			outputDirectory,
		); err != nil {
			return nil, err
		}
		for index := 1; index <= count; index++ {
			paths = append(
				paths,
				filepath.Join(
					outputDirectory,
					fmt.Sprintf("token-%06d.json", index),
				),
			)
		}
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); err == nil {
			return nil, fmt.Errorf(
				"refusing to overwrite token output: %s", path,
			)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf(
				"inspect token output %s: %w", path, err,
			)
		}
	}
	return paths, nil
}

func exitError(err error) {
	fmt.Fprintln(os.Stderr, "winn-token:", err)
	os.Exit(1)
}
