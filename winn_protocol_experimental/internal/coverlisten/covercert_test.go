package coverlisten_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/coverlisten"
)

// Every certificate in this file is generated here. Nothing is copied from the
// deployment's own key material, and no key material is written to the tree.
//
// The two shapes these tests reproduce are the two that were actually proposed
// as cover for this deployment, reconstructed from their properties rather
// than their contents: an Extended Validation certificate carrying a verified
// legal identity, and a self-signed CA certificate for a reserved-TLD name
// that carried no identity at all and was still unusable.

var (
	oidSubjectSerialNumber  = asn1.ObjectIdentifier{2, 5, 4, 5}
	oidBusinessCategory     = asn1.ObjectIdentifier{2, 5, 4, 15}
	oidJurisdictionCountry  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3}
	oidJurisdictionProvince = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 2}
)

func mustOID(t *testing.T, arcs ...uint64) x509.OID {
	t.Helper()
	oid, err := x509.OIDFromInts(arcs)
	if err != nil {
		t.Fatalf("OIDFromInts(%v): %v", arcs, err)
	}
	return oid
}

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func newAuthority(t *testing.T, commonName string) authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CA cert: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return authority{cert: parsed, key: key, der: der}
}

// issue signs template with ca and returns a tls.Certificate carrying the leaf
// followed by the issuing certificate, which is the chain a real origin
// serves.
func issue(t *testing.T, ca authority, template *x509.Certificate) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	if template.SerialNumber == nil {
		template.SerialNumber = big.NewInt(time.Now().UnixNano())
	}
	if template.NotBefore.IsZero() {
		template.NotBefore = time.Now().Add(-time.Hour)
	}
	if template.NotAfter.IsZero() {
		template.NotAfter = time.Now().Add(90 * 24 * time.Hour)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der, ca.der}, PrivateKey: key}
}

func selfSigned(t *testing.T, template *x509.Certificate) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	if template.SerialNumber == nil {
		template.SerialNumber = big.NewInt(time.Now().UnixNano())
	}
	if template.NotBefore.IsZero() {
		template.NotBefore = time.Now().Add(-time.Hour)
	}
	if template.NotAfter.IsZero() {
		template.NotAfter = time.Now().Add(90 * 24 * time.Hour)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-signed cert: %v", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// extendedValidationLeaf reconstructs the shape of the first bad candidate: a
// genuine EV certificate for the operator's own public domains.
func extendedValidationLeaf(t *testing.T, ca authority) *tls.Certificate {
	t.Helper()
	return issue(t, ca, &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "shop.example.com",
			Organization: []string{"Example Holdings Incorporated"},
			Country:      []string{"US"},
			Province:     []string{"Delaware"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: oidSubjectSerialNumber, Value: "N00000000000"},
				{Type: oidBusinessCategory, Value: "Private Organization"},
				{Type: oidJurisdictionCountry, Value: "US"},
				{Type: oidJurisdictionProvince, Value: "Delaware"},
			},
		},
		DNSNames:    []string{"shop.example.com", "example.com"},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Policies:    []x509.OID{mustOID(t, 2, 23, 140, 1, 1)},
	})
}

// winnStyleLeaf reproduces what internal/pki actually generates for this
// deployment: a Common Name, no organization, under a private CA.
func winnStyleLeaf(t *testing.T, ca authority, dnsName string) *x509.Certificate {
	t.Helper()
	leaf := issue(t, ca, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "Winn Protocol Experimental Controller"},
		DNSNames:    []string{dnsName},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse winn leaf: %v", err)
	}
	return parsed
}

func review(t *testing.T, cover *tls.Certificate, winn *x509.Certificate) coverlisten.CoverCertificateReview {
	t.Helper()
	result, err := coverlisten.ReviewCoverCertificate(cover, winn)
	if err != nil {
		t.Fatalf("ReviewCoverCertificate: %v", err)
	}
	return result
}

func mentions(findings []string, want string) bool {
	for _, finding := range findings {
		if strings.Contains(strings.ToLower(finding), strings.ToLower(want)) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Identity half
// ---------------------------------------------------------------------------

// TestExtendedValidationCertificateIsRefusedAsCover is the regression test for
// the first near-miss. An EV subject is a verified legal identity, which is
// the opposite of cover.
func TestExtendedValidationCertificateIsRefusedAsCover(t *testing.T) {
	public := newAuthority(t, "Example Trust Services R3")
	result := review(t, extendedValidationLeaf(t, public), nil)

	if len(result.Identifying) == 0 {
		t.Fatal("an EV certificate was accepted as cover; one handshake would " +
			"have returned the operator's registered legal identity")
	}
	for _, attribute := range []string{
		"organizationName", "serialNumber", "businessCategory",
		"jurisdictionCountryName", "countryName", "stateOrProvinceName",
	} {
		if !mentions(result.Identifying, attribute) {
			t.Errorf("refusal does not name the %s attribute: %v",
				attribute, result.Identifying)
		}
	}
	if !mentions(result.Identifying, "2.23.140.1.1") {
		t.Errorf("refusal does not name the EV policy OID: %v", result.Identifying)
	}
	if !mentions(result.Identifying, "Certificate Transparency") {
		t.Errorf("refusal does not explain that the association is publicly "+
			"enumerable without probing: %v", result.Identifying)
	}
}

// TestRelationalChecksAloneWouldNotHaveCaughtAnEVCertificate is the reason the
// primary rule is intrinsic rather than relational.
//
// The obvious rule is "a cover certificate must not share any DNS name,
// organization or issuer with the Winn profile's certificate". This test
// builds exactly the configuration this deployment has and shows all three
// relational comparisons passing while the certificate is still catastrophic.
// It exists so that nobody replaces the intrinsic rule with the relational one
// on the grounds that the relational one sounds sufficient.
func TestRelationalChecksAloneWouldNotHaveCaughtAnEVCertificate(t *testing.T) {
	winnCA := newAuthority(t, "Winn Protocol Experimental Lab CA")
	winnLeaf := winnStyleLeaf(t, winnCA, "gateway-7.winn.invalid")

	public := newAuthority(t, "Example Trust Services R3")
	cover := extendedValidationLeaf(t, public)
	coverLeaf, err := x509.ParseCertificate(cover.Certificate[0])
	if err != nil {
		t.Fatalf("parse cover: %v", err)
	}

	// The three relational comparisons, done here explicitly so the claim is
	// checked rather than asserted.
	if coverLeaf.Issuer.String() == winnLeaf.Issuer.String() {
		t.Fatal("precondition: issuers were expected to differ")
	}
	for _, coverName := range coverLeaf.DNSNames {
		for _, winnName := range winnLeaf.DNSNames {
			if strings.EqualFold(coverName, winnName) {
				t.Fatalf("precondition: %q was expected not to appear on both", coverName)
			}
		}
	}
	for _, coverOrganization := range coverLeaf.Subject.Organization {
		for _, winnOrganization := range winnLeaf.Subject.Organization {
			if strings.EqualFold(coverOrganization, winnOrganization) {
				t.Fatalf("precondition: organization %q was expected not to be shared",
					coverOrganization)
			}
		}
	}
	if len(winnLeaf.Subject.Organization) != 0 {
		t.Fatal("precondition: the Winn leaf carries no organization, so no " +
			"organization comparison against it can ever match")
	}

	// Every relational check passes. The review must still refuse.
	result := review(t, cover, winnLeaf)
	if len(result.Identifying) == 0 {
		t.Fatal("the EV certificate shares no name, organization or issuer " +
			"with the Winn certificate, and a relational-only rule therefore " +
			"accepts it; the intrinsic rule is what refuses it")
	}
	if !mentions(result.Identifying, "organizationName") {
		t.Errorf("expected the intrinsic subject rule to fire: %v", result.Identifying)
	}
}

func TestOrganizationValidatedCertificateIsRefusedAsCover(t *testing.T) {
	public := newAuthority(t, "Example Trust Services R3")
	cover := issue(t, public, &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "www.example.com",
			Organization: []string{"Example Holdings Incorporated"},
		},
		DNSNames: []string{"www.example.com"},
		Policies: []x509.OID{mustOID(t, 2, 23, 140, 1, 2, 2)},
	})
	result := review(t, cover, nil)
	if len(result.Identifying) == 0 {
		t.Fatal("an OV certificate was accepted; it names a verified legal entity")
	}
	if !mentions(result.Identifying, "2.23.140.1.2.2") {
		t.Errorf("refusal does not name the OV policy OID: %v", result.Identifying)
	}
}

func TestCoverCertificateIssuedByTheWinnCAIsRefused(t *testing.T) {
	winnCA := newAuthority(t, "Winn Protocol Experimental Lab CA")
	winnLeaf := winnStyleLeaf(t, winnCA, "gateway-7.winn.invalid")
	// A plausible-looking cover leaf, but issued from the Winn CA - so its
	// issuer DN identifies the deployment exactly as reusing the leaf would.
	cover := issue(t, winnCA, &x509.Certificate{
		Subject:  pkix.Name{CommonName: "www.example.com"},
		DNSNames: []string{"www.example.com"},
	})
	result := review(t, cover, winnLeaf)
	if !mentions(result.Identifying, "issued by the same CA") {
		t.Fatalf("a cover leaf from the Winn CA was accepted: %+v", result)
	}
}

func TestCoverCertificateSharingTheWinnNameIsRefused(t *testing.T) {
	winnCA := newAuthority(t, "Winn Protocol Experimental Lab CA")
	public := newAuthority(t, "Example Trust Services R3")
	winnLeaf := winnStyleLeaf(t, winnCA, "gateway-7.private.example")

	for _, coverName := range []string{
		"gateway-7.private.example", // identical
		"private.example",           // parent of the Winn name
	} {
		t.Run(coverName, func(t *testing.T) {
			cover := issue(t, public, &x509.Certificate{
				Subject:  pkix.Name{CommonName: coverName},
				DNSNames: []string{coverName},
			})
			result := review(t, cover, winnLeaf)
			if !mentions(result.Identifying, "ECH-inner SNI") {
				t.Fatalf("cover name %q overlapping the Winn name was accepted: %+v",
					coverName, result)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Plausibility half
// ---------------------------------------------------------------------------

// TestSelfSignedCACertificateIsRefusedAsCover is the regression test for the
// second near-miss, and the assertion that matters most is the last one: the
// certificate passes the identity half completely. It was generated to fix the
// EV problem, it did fix the EV problem, and it was still unusable. A check
// with only the identity half would have accepted it.
func TestSelfSignedCACertificateIsRefusedAsCover(t *testing.T) {
	cover := selfSigned(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "cdn-static-assets.local"},
		DNSNames:              []string{"cdn-static-assets.local", "localhost"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	})
	result := review(t, cover, nil)

	if len(result.Identifying) != 0 {
		t.Fatalf("precondition: this certificate names nobody, so the identity "+
			"half must be silent; got %v", result.Identifying)
	}
	if len(result.Implausible) == 0 {
		t.Fatal("a self-signed CA certificate for a .local name with localhost " +
			"in its SANs was accepted as cover; a prober concludes the endpoint " +
			"is improvised without needing to attribute it")
	}
	for _, signal := range []string{
		"self-signed",
		"CA certificate",
		"reserved",
		"single-label",
		"without its issuing chain",
		"no publicly resolvable DNS name",
	} {
		if !mentions(result.Implausible, signal) {
			t.Errorf("refusal does not report %q: %v", signal, result.Implausible)
		}
	}
}

func TestReservedAndUnresolvableNamesAreRefused(t *testing.T) {
	public := newAuthority(t, "Example Trust Services R3")
	for _, name := range []string{
		"assets.local", "gateway.internal", "host.test",
		"cdn.example", "thing.invalid", "cache.localhost",
		"intranet", // single label
	} {
		t.Run(name, func(t *testing.T) {
			cover := issue(t, public, &x509.Certificate{
				Subject:  pkix.Name{CommonName: name},
				DNSNames: []string{name},
			})
			result := review(t, cover, nil)
			if len(result.Identifying) != 0 {
				t.Fatalf("identity half should be silent: %v", result.Identifying)
			}
			if len(result.Implausible) == 0 {
				t.Fatalf("%q was accepted as a cover name; it can never appear "+
					"on a publicly trusted certificate", name)
			}
		})
	}
}

func TestStructurallyBrokenChainsAreRefused(t *testing.T) {
	public := newAuthority(t, "Example Trust Services R3")
	other := newAuthority(t, "Unrelated Trust Services R1")

	t.Run("no chain supplied", func(t *testing.T) {
		full := issue(t, public, &x509.Certificate{
			Subject:  pkix.Name{CommonName: "www.example.com"},
			DNSNames: []string{"www.example.com"},
		})
		leafOnly := &tls.Certificate{
			Certificate: [][]byte{full.Certificate[0]}, PrivateKey: full.PrivateKey,
		}
		result := review(t, leafOnly, nil)
		if !mentions(result.Implausible, "without its issuing chain") {
			t.Fatalf("a bare leaf was accepted: %+v", result)
		}
	})

	t.Run("chain does not link", func(t *testing.T) {
		full := issue(t, public, &x509.Certificate{
			Subject:  pkix.Name{CommonName: "www.example.com"},
			DNSNames: []string{"www.example.com"},
		})
		mismatched := &tls.Certificate{
			Certificate: [][]byte{full.Certificate[0], other.der},
			PrivateKey:  full.PrivateKey,
		}
		result := review(t, mismatched, nil)
		if !mentions(result.Implausible, "does not link") {
			t.Fatalf("an unlinked chain was accepted: %+v", result)
		}
	})

	t.Run("expired", func(t *testing.T) {
		cover := issue(t, public, &x509.Certificate{
			Subject:   pkix.Name{CommonName: "www.example.com"},
			DNSNames:  []string{"www.example.com"},
			NotBefore: time.Now().Add(-60 * 24 * time.Hour),
			NotAfter:  time.Now().Add(-time.Hour),
		})
		result := review(t, cover, nil)
		if !mentions(result.Implausible, "expired") {
			t.Fatalf("an expired cover certificate was accepted: %+v", result)
		}
	})

	t.Run("validity beyond the public maximum", func(t *testing.T) {
		cover := issue(t, public, &x509.Certificate{
			Subject:   pkix.Name{CommonName: "www.example.com"},
			DNSNames:  []string{"www.example.com"},
			NotBefore: time.Now().Add(-time.Hour),
			NotAfter:  time.Now().Add(5 * 365 * 24 * time.Hour),
		})
		result := review(t, cover, nil)
		if !mentions(result.Implausible, "CA/Browser Forum maximum") {
			t.Fatalf("a 5-year cover certificate was accepted: %+v", result)
		}
	})

	t.Run("loopback SAN", func(t *testing.T) {
		cover := issue(t, public, &x509.Certificate{
			Subject:     pkix.Name{CommonName: "www.example.com"},
			DNSNames:    []string{"www.example.com"},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		})
		result := review(t, cover, nil)
		if !mentions(result.Implausible, "loopback address") {
			t.Fatalf("a loopback SAN was accepted: %+v", result)
		}
	})
}

// ---------------------------------------------------------------------------
// The positive case, and the independence of the two halves
// ---------------------------------------------------------------------------

// TestOrdinaryPublicCertificateIsAccepted pins what the owner is being asked
// to obtain. If this test ever fails, the requirement has become impossible to
// satisfy with an ordinary ACME certificate and the checks are wrong.
func TestOrdinaryPublicCertificateIsAccepted(t *testing.T) {
	public := newAuthority(t, "Example Trust Services R3")
	winnCA := newAuthority(t, "Winn Protocol Experimental Lab CA")
	winnLeaf := winnStyleLeaf(t, winnCA, "gateway-7.private.example")

	cover := issue(t, public, &x509.Certificate{
		// Exactly what an ACME issuer produces: a Common Name and nothing else.
		Subject:     pkix.Name{CommonName: "static-content-delivery.net"},
		DNSNames:    []string{"static-content-delivery.net", "www.static-content-delivery.net"},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(90 * 24 * time.Hour),
		Policies:    []x509.OID{mustOID(t, 2, 23, 140, 1, 2, 1)}, // Domain Validation
	})
	result := review(t, cover, winnLeaf)
	if !result.OK() {
		t.Fatalf("an ordinary DV certificate was refused; the bar is not "+
			"achievable as written.\nidentifying: %v\nimplausible: %v",
			result.Identifying, result.Implausible)
	}
}

// TestEachEscapeHatchWaivesOnlyItsOwnHalf is the structural consequence of the
// second near-miss. Someone who silences the identity refusal must still be
// stopped by the plausibility refusal, and the reverse, because the whole
// failure mode was concluding that fixing one half was finishing.
func TestEachEscapeHatchWaivesOnlyItsOwnHalf(t *testing.T) {
	material := newPKI(t)
	_, keys := echMaterial(t)

	// A certificate that fails both halves at once: EV attributes and a
	// self-signed reserved-TLD name.
	both := selfSigned(t, &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "assets.local",
			Organization: []string{"Example Holdings Incorporated"},
		},
		DNSNames:              []string{"assets.local"},
		BasicConstraintsValid: true,
		IsCA:                  true,
		Policies:              []x509.OID{mustOID(t, 2, 23, 140, 1, 1)},
	})
	certPath, keyPath := writeCoverFiles(t, both)

	base := func() coverlisten.Options {
		return coverlisten.Options{
			Winn:                      strictConfig(t, material, keys),
			CoverALPN:                 []string{"h2"},
			CoverCertPath:             certPath,
			CoverKeyPath:              keyPath,
			ECHKeys:                   keys,
			RequestsClientCertificate: true,
		}
	}

	t.Run("neither waived: refuses on identity first", func(t *testing.T) {
		_, err := coverlisten.Apply(base())
		if err == nil {
			t.Fatal("accepted a certificate that fails both halves")
		}
		if !errors.Is(err, coverlisten.ErrIdentifyingCoverCertificate) {
			t.Fatalf("expected the identity refusal, got: %v", err)
		}
	})

	t.Run("identity waived: plausibility still refuses", func(t *testing.T) {
		options := base()
		options.AllowIdentifyingCoverCertificate = true
		_, err := coverlisten.Apply(options)
		if err == nil {
			t.Fatal("waiving the identity half also waived the plausibility " +
				"half; that is exactly the inference that produced the second " +
				"bad certificate")
		}
		if !errors.Is(err, coverlisten.ErrImplausibleCoverCertificate) {
			t.Fatalf("expected the plausibility refusal, got: %v", err)
		}
	})

	t.Run("plausibility waived: identity still refuses", func(t *testing.T) {
		options := base()
		options.AllowImplausibleCoverCertificate = true
		_, err := coverlisten.Apply(options)
		if err == nil {
			t.Fatal("waiving the plausibility half also waived the identity half")
		}
		if !errors.Is(err, coverlisten.ErrIdentifyingCoverCertificate) {
			t.Fatalf("expected the identity refusal, got: %v", err)
		}
	})

	t.Run("both waived by name: accepted", func(t *testing.T) {
		options := base()
		options.AllowIdentifyingCoverCertificate = true
		options.AllowImplausibleCoverCertificate = true
		if _, err := coverlisten.Apply(options); err != nil {
			t.Fatalf("both hatches passed by name and it still refused: %v", err)
		}
	})
}

// TestApplyRefusesTheRealNearMissShapesEndToEnd drives both near-miss shapes
// through the same entry point the commands use, so the gate is proven where
// it actually runs rather than only at the review function.
func TestApplyRefusesTheRealNearMissShapesEndToEnd(t *testing.T) {
	material := newPKI(t)
	_, keys := echMaterial(t)
	public := newAuthority(t, "Example Trust Services R3")

	for _, shape := range []struct {
		name    string
		cover   *tls.Certificate
		wantErr error
	}{
		{
			name:    "extended validation certificate",
			cover:   extendedValidationLeaf(t, public),
			wantErr: coverlisten.ErrIdentifyingCoverCertificate,
		},
		{
			name: "self-signed CA for a reserved-TLD name",
			cover: selfSigned(t, &x509.Certificate{
				Subject:               pkix.Name{CommonName: "cdn-static-assets.local"},
				DNSNames:              []string{"cdn-static-assets.local", "localhost"},
				BasicConstraintsValid: true,
				IsCA:                  true,
			}),
			wantErr: coverlisten.ErrImplausibleCoverCertificate,
		},
	} {
		t.Run(shape.name, func(t *testing.T) {
			certPath, keyPath := writeCoverFiles(t, shape.cover)
			_, err := coverlisten.Apply(coverlisten.Options{
				Winn:                      strictConfig(t, material, keys),
				CoverALPN:                 []string{"h2"},
				CoverCertPath:             certPath,
				CoverKeyPath:              keyPath,
				ECHKeys:                   keys,
				RequestsClientCertificate: true,
			})
			if err == nil {
				t.Fatal("the listener started with this certificate as cover")
			}
			if !errors.Is(err, shape.wantErr) {
				t.Fatalf("error %v does not wrap %v", err, shape.wantErr)
			}
			// The refusal has to tell the operator what to do instead.
			if !strings.Contains(err.Error(), "OPERATIONS.md") {
				t.Errorf("refusal does not point at the operator guidance: %v", err)
			}
		})
	}
}

// writeCoverFiles writes a generated certificate and key to a temporary
// directory in the form -cover-cert and -cover-key expect. Both are created
// fresh per test and never leave t.TempDir().
func writeCoverFiles(t *testing.T, certificate *tls.Certificate) (string, string) {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cover.pem")
	keyPath := filepath.Join(dir, "cover.key")

	var chain []byte
	for _, der := range certificate.Certificate {
		chain = append(chain, pem.EncodeToMemory(
			&pem.Block{Type: "CERTIFICATE", Bytes: der},
		)...)
	}
	if err := os.WriteFile(certPath, chain, 0o600); err != nil {
		t.Fatalf("write cover certificate: %v", err)
	}
	key, ok := certificate.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("generated cover key is not ECDSA")
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal cover key: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(
		&pem.Block{Type: "EC PRIVATE KEY", Bytes: der},
	), 0o600); err != nil {
		t.Fatalf("write cover key: %v", err)
	}
	return certPath, keyPath
}
