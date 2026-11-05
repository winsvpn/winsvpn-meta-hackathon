package identity

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"

	"winsvpn.local/winnprotocol/internal/protocol"
)

// DeviceID extracts the one valid Winn SPIFFE device identity from a verified
// certificate chain. TLS certificate validation must already have succeeded.
func DeviceID(state *tls.ConnectionState) (string, error) {
	if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return "", errors.New("no verified client certificate")
	}
	return DeviceIDFromCertificate(state.VerifiedChains[0][0])
}

func DeviceIDFromCertificate(leaf *x509.Certificate) (string, error) {
	if leaf == nil {
		return "", errors.New("client certificate is missing")
	}
	var found string
	for _, candidateURI := range leaf.URIs {
		if candidateURI == nil {
			continue
		}
		if candidateURI.Scheme != "spiffe" || candidateURI.Host != "winn.local" {
			continue
		}
		const prefix = "/device/"
		if !strings.HasPrefix(candidateURI.Path, prefix) {
			continue
		}
		candidate := strings.TrimPrefix(candidateURI.Path, prefix)
		if !protocol.ValidDeviceID(candidate) || strings.Contains(candidate, "/") {
			continue
		}
		if candidateURI.String() != "spiffe://winn.local"+prefix+candidate {
			continue
		}
		if found != "" && found != candidate {
			return "", errors.New("ambiguous device identities")
		}
		found = candidate
	}
	if found == "" {
		return "", errors.New("device URI SAN is missing")
	}
	return found, nil
}
