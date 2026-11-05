package coverlisten_test

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/coverlisten"
)

func coverLeafExpiring(t *testing.T, ca authority, in time.Duration) *tls.Certificate {
	t.Helper()
	return issue(t, ca, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "static-content-delivery.net"},
		DNSNames:    []string{"static-content-delivery.net"},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(in),
		Policies:    []x509.OID{mustOID(t, 2, 23, 140, 1, 2, 1)},
	})
}

func mentionsExpiry(notes []string) bool {
	for _, note := range notes {
		if strings.Contains(note, "expires on") {
			return true
		}
	}
	return false
}

// TestCoverCertificateNearExpiryIsAdvised: a cover leaf inside the renewal
// window is still served (it is valid) but the review says so, because the
// process never reloads it and refuses to start once it has expired.
func TestCoverCertificateNearExpiryIsAdvised(t *testing.T) {
	public := newAuthority(t, "Example Trust Services R3")
	winnCA := newAuthority(t, "Winn Protocol Experimental Lab CA")
	winnLeaf := winnStyleLeaf(t, winnCA, "gateway-7.private.example")

	soon := review(t, coverLeafExpiring(t, public, 10*24*time.Hour), winnLeaf)
	if !soon.OK() {
		t.Fatalf("a valid certificate ten days from expiry was refused: %v %v",
			soon.Identifying, soon.Implausible)
	}
	if !mentionsExpiry(soon.Advisory) {
		t.Fatalf("no expiry advisory for a leaf ten days from NotAfter: %v", soon.Advisory)
	}

	later := review(t, coverLeafExpiring(t, public, 60*24*time.Hour), winnLeaf)
	if !later.OK() || mentionsExpiry(later.Advisory) {
		t.Fatalf("a leaf sixty days from NotAfter must not be advised: ok=%v %v",
			later.OK(), later.Advisory)
	}
}

// TestApplyReportsTheCoverNotAfter: the listener carries the served leaf's
// NotAfter so a command can publish it.
func TestApplyReportsTheCoverNotAfter(t *testing.T) {
	material := newPKI(t)
	_, keys := echMaterial(t)
	winn := strictConfig(t, material, keys)

	listener, err := coverlisten.Apply(coverlisten.Options{
		Winn:                      winn,
		CoverALPN:                 []string{"h2", "http/1.1"},
		CoverCertPath:             material.coverCert,
		CoverKeyPath:              material.coverKey,
		ECHKeys:                   keys,
		RequestsClientCertificate: true,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	leaf, err := x509.ParseCertificate(listener.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if listener.CoverNotAfter.IsZero() || !listener.CoverNotAfter.Equal(leaf.NotAfter) {
		t.Fatalf("CoverNotAfter %v, want the served leaf's %v", listener.CoverNotAfter, leaf.NotAfter)
	}
}
