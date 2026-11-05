package coverlisten

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"strings"
	"time"
)

// This file decides which certificates are fit to be served to probers. The
// rest of the package decides whether a cover certificate is served at all.
//
// It exists because that question was got wrong twice in a row, in two
// different directions, and the second mistake was made by someone who had
// just been told about the first.
//
// The first candidate was the operator's genuine Extended Validation
// certificate. Serving it would have been strictly worse than the private-CA
// issuer string it was meant to hide: an EV subject carries a verified legal
// name, an incorporation number and an incorporation jurisdiction, so one
// handshake would have returned the operator's registered identity rather than
// merely the fact that some Winn CA existed. Publicly trusted certificates are
// logged to Certificate Transparency, so the association would also have been
// enumerable without probing at all.
//
// The second candidate was generated to fix that, and was reported as
// "completely neutral". It was: CN=cdn-static-assets.local, self-signed, a CA
// certificate served as a leaf, with localhost in its SANs. It named no
// operator and leaked no identity. It was also unmistakably not a real
// website.
//
// That is the lesson this file encodes. "Does not identify the operator" and
// "looks like an ordinary origin" are two different properties, and only the
// second one is the actual goal. A prober that concludes "definitely not a
// real website" blocks just as fast as one that concludes "this is Winn" -
// possibly faster, because the first conclusion needs no attribution work.
// Passing the identity half is therefore not evidence of passing at all, which
// is precisely the inference that produced the second near-miss.
//
// So the review has two halves, each fatal, each with its own named escape
// hatch, so that silencing one cannot silence the other.

// ---------------------------------------------------------------------------
// Identity half
// ---------------------------------------------------------------------------

// The obvious identity rule - "a cover certificate must not share a name,
// organization or issuer with the Winn profile's certificate" - is real but
// secondary, and on its own it would not have caught the EV certificate.
// TestRelationalChecksAloneWouldNotHaveCaughtAnEVCertificate proves that
// rather than asserting it: the Winn leaf in that deployment is
// CN=Winn Protocol Experimental Controller under a private lab CA, with no
// organization attribute and a gateway-specific name, so the EV certificate
// shares no DNS name with it, no organization with it, and no issuer with it.
// Every relational check passes.
//
// What made that certificate dangerous was intrinsic: it identified a legal
// entity in its own subject, and would have done so as cover for any
// deployment on earth. The primary rule is therefore a property of the
// certificate alone:
//
//	A cover certificate's subject may contain nothing but a Common Name.
//
// That is the shape of a domain-validated certificate, which is what ACME
// issuers produce. Every other standard subject attribute exists to identify
// an organization or a person, or to locate one. Implementing the rule as
// "reject any subject attribute that is not the Common Name", rather than as a
// list of banned attributes, means attributes nobody here has heard of - and
// attributes not yet invented - are refused by default. It also means this
// file names no operator, no company and no domain, so it is a check rather
// than a filter for one certificate.

var oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}

// subjectAttributeNames is only for readable messages. Membership is not what
// makes an attribute fatal; being present and not being the Common Name is.
var subjectAttributeNames = map[string]string{
	"2.5.4.5":                    "serialNumber",
	"2.5.4.6":                    "countryName",
	"2.5.4.7":                    "localityName",
	"2.5.4.8":                    "stateOrProvinceName",
	"2.5.4.9":                    "streetAddress",
	"2.5.4.10":                   "organizationName",
	"2.5.4.11":                   "organizationalUnitName",
	"2.5.4.15":                   "businessCategory",
	"2.5.4.17":                   "postalCode",
	"2.5.4.4":                    "surname",
	"2.5.4.42":                   "givenName",
	"1.3.6.1.4.1.311.60.2.1.1":   "jurisdictionLocalityName",
	"1.3.6.1.4.1.311.60.2.1.2":   "jurisdictionStateOrProvinceName",
	"1.3.6.1.4.1.311.60.2.1.3":   "jurisdictionCountryName",
	"0.9.2342.19200300.100.1.1":  "userID",
	"0.9.2342.19200300.100.1.25": "domainComponent",
}

// identifyingPolicies are the CA/Browser Forum validation levels that bind a
// certificate to a verified real-world identity. Domain Validation proves only
// control of a name, which is all a cover certificate should ever prove, and
// is deliberately absent.
var identifyingPolicies = map[string]string{
	"2.23.140.1.1":   "Extended Validation",
	"2.23.140.1.2.2": "Organization Validation",
	"2.23.140.1.2.3": "Individual Validation",
}

// ---------------------------------------------------------------------------
// Plausibility half
// ---------------------------------------------------------------------------

// The positive requirement is: the cover certificate must be one an ordinary
// public website could be serving. The code enforces the structural half of
// that, and the structural half alone is enough to refuse both near-misses.
//
// It deliberately does NOT verify the chain against the host's root store.
// x509.SystemCertPool returns a functioning pool whose Subjects() is empty on
// macOS, so the package cannot distinguish "no roots installed" from "roots
// present but opaque"; a fatal gate built on it would silently no-op on some
// platforms and refuse to start on a container missing ca-certificates. It
// also answers the wrong question: what matters is whether a *prober's* client
// trusts the chain, and the server's own store is a poor proxy for that. The
// structural signals below are deterministic, portable, need no external
// dependency, and catch the real failures.
//
// What the code therefore cannot check, and the owner must satisfy by
// procurement: that the name actually resolves in public DNS, and that it has
// no public link back to the operator. Neither is a fact about the certificate
// bytes.

// reservedTopLevelDomains can never appear on a publicly trusted certificate.
// RFC 2606, RFC 6761, RFC 6762, and ICANN's reservation of .internal.
var reservedTopLevelDomains = map[string]bool{
	"local": true, "localhost": true, "invalid": true, "test": true,
	"example": true, "internal": true, "onion": true, "home": true,
	"corp": true, "lan": true, "alt": true,
}

// maximumPublicValidity is the CA/Browser Forum ceiling on a publicly trusted
// server certificate. Anything longer was not issued by a public CA.
const maximumPublicValidity = 398 * 24 * time.Hour

// coverExpiryWarning is how close to NotAfter the review starts saying so.
//
// The certificate is read once, at start, into tls.Config.Certificates and is
// never reloaded, so a renewed file on disk changes nothing until the unit
// restarts; and a unit restarted after NotAfter refuses to start, because an
// expired cover leaf is implausible. Between the two a fleet serves an
// expired certificate to every prober. Thirty days is the ACME renewal
// window, so a deployment that renews on schedule never sees this note.
const coverExpiryWarning = 30 * 24 * time.Hour

// CoverCertificateReview is the verdict on a candidate cover certificate.
//
// Both halves are fatal, and each is waived by its own option, because the
// second near-miss was caused precisely by treating the identity half as the
// whole test. A single combined flag would let an operator who fixed identity
// silence plausibility without noticing they had.
//
// Advisory holds notes that are worth saying and never fatal.
type CoverCertificateReview struct {
	// Identifying: the certificate tells a prober who runs this deployment.
	Identifying []string

	// Implausible: the certificate could not belong to a real public origin,
	// so a prober concludes the endpoint is improvised even without
	// attributing it.
	Implausible []string

	// Advisory: worth reporting, never fatal.
	Advisory []string
}

// OK reports whether the certificate may be served to unauthenticated peers.
func (review CoverCertificateReview) OK() bool {
	return len(review.Identifying) == 0 && len(review.Implausible) == 0
}

// ReviewCoverCertificate inspects a candidate cover certificate, optionally
// against the strict profile's own leaf.
func ReviewCoverCertificate(
	cover *tls.Certificate, winn *x509.Certificate,
) (CoverCertificateReview, error) {
	var review CoverCertificateReview
	if cover == nil || len(cover.Certificate) == 0 {
		return review, fmt.Errorf("cover certificate is empty")
	}
	chain := make([]*x509.Certificate, 0, len(cover.Certificate))
	for index, der := range cover.Certificate {
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			return review, fmt.Errorf(
				"parse cover certificate at chain position %d: %w", index, err,
			)
		}
		chain = append(chain, parsed)
	}
	leaf := chain[0]

	review.reviewSubject(leaf)
	review.reviewPolicies(leaf)
	review.reviewRelationship(leaf, winn)
	review.reviewChain(chain)
	review.reviewNames(leaf)
	review.reviewValidity(leaf)
	return review, nil
}

func (review *CoverCertificateReview) reviewSubject(leaf *x509.Certificate) {
	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(leaf.RawSubject, &subject); err != nil {
		review.Identifying = append(review.Identifying,
			"subject could not be parsed, so it cannot be shown to be free of "+
				"identifying attributes")
		return
	}
	seen := map[string]bool{}
	for _, rdn := range subject {
		for _, attribute := range rdn {
			if attribute.Type.Equal(oidCommonName) {
				continue
			}
			oid := attribute.Type.String()
			if seen[oid] {
				continue
			}
			seen[oid] = true
			name, known := subjectAttributeNames[oid]
			if !known {
				name = "attribute " + oid
			}
			review.Identifying = append(review.Identifying, fmt.Sprintf(
				"subject carries %s=%v, which exists to identify an "+
					"organization or a person; a cover certificate's subject "+
					"may contain nothing but a Common Name",
				name, attribute.Value,
			))
		}
	}
}

func (review *CoverCertificateReview) reviewPolicies(leaf *x509.Certificate) {
	// Policies and PolicyIdentifiers are both populated for the same
	// certificate, so a policy read from each would otherwise be reported
	// twice and read as two separate problems.
	reported := map[string]bool{}
	report := func(oid string) {
		level, identifying := identifyingPolicies[oid]
		if !identifying || reported[oid] {
			return
		}
		reported[oid] = true
		review.Identifying = append(review.Identifying, fmt.Sprintf(
			"asserts the %s certificate policy (%s), whose whole purpose is to "+
				"bind this certificate to a verified real-world identity - the "+
				"opposite of cover, and published to Certificate Transparency "+
				"where the association is enumerable without probing at all",
			level, oid,
		))
	}
	for _, policy := range leaf.Policies {
		report(policy.String())
	}
	//nolint:staticcheck // Deprecated but still populated; a certificate whose
	// policies parse only into the legacy field must not slip past the gate.
	for _, policy := range leaf.PolicyIdentifiers {
		report(policy.String())
	}
}

// reviewRelationship catches a different and equally real mistake from the
// intrinsic checks: issuing the cover leaf from the Winn CA, or reusing the
// gateway's own certificate, either of which puts the deployment's identity
// back on the wire by another route.
func (review *CoverCertificateReview) reviewRelationship(leaf, winn *x509.Certificate) {
	if winn == nil {
		return
	}
	if bytes.Equal(leaf.RawIssuer, winn.RawIssuer) {
		review.Identifying = append(review.Identifying, fmt.Sprintf(
			"is issued by the same CA as the Winn profile's own certificate "+
				"(%s), so its issuer Distinguished Name identifies the "+
				"deployment exactly as reusing the Winn leaf would",
			leaf.Issuer.String(),
		))
	}
	for _, coverName := range leaf.DNSNames {
		for _, winnName := range winn.DNSNames {
			if !namesRelated(coverName, winnName) {
				continue
			}
			review.Identifying = append(review.Identifying, fmt.Sprintf(
				"carries the name %q, which is the Winn certificate's name %q "+
					"or a parent of it; that name is the private ECH-inner SNI "+
					"selecting the strict profile, and publishing it to every "+
					"prober gives away half the selector",
				coverName, winnName,
			))
		}
	}
	for _, winnOrganization := range winn.Subject.Organization {
		for _, coverOrganization := range leaf.Subject.Organization {
			if strings.EqualFold(winnOrganization, coverOrganization) {
				review.Identifying = append(review.Identifying, fmt.Sprintf(
					"shares the organization %q with the Winn certificate",
					winnOrganization,
				))
			}
		}
	}
}

// reviewChain applies the strongest and simplest plausibility signals. No real
// origin is self-signed, no real origin serves a CA certificate as its leaf,
// and a real origin supplies its intermediates.
func (review *CoverCertificateReview) reviewChain(chain []*x509.Certificate) {
	leaf := chain[0]
	if bytes.Equal(leaf.RawSubject, leaf.RawIssuer) {
		review.Implausible = append(review.Implausible,
			"is self-signed; no real public origin is, so a prober that "+
				"completes one handshake concludes the endpoint is improvised")
	}
	if leaf.BasicConstraintsValid && leaf.IsCA {
		review.Implausible = append(review.Implausible,
			"is a CA certificate (BasicConstraints CA:TRUE) being served as a "+
				"leaf; no real origin does this and browsers reject it")
	}
	if len(chain) < 2 {
		review.Implausible = append(review.Implausible,
			"was supplied without its issuing chain; a real origin serves its "+
				"intermediates, so supply the full chain (ACME clients write "+
				"this as fullchain.pem)")
		return
	}
	for index := 0; index+1 < len(chain); index++ {
		child, parent := chain[index], chain[index+1]
		if !bytes.Equal(child.RawIssuer, parent.RawSubject) {
			review.Implausible = append(review.Implausible, fmt.Sprintf(
				"chain does not link: certificate %d is issued by %q but "+
					"certificate %d is %q, so no client can build a path",
				index, child.Issuer.String(),
				index+1, parent.Subject.String(),
			))
			return
		}
		if !parent.BasicConstraintsValid || !parent.IsCA {
			review.Implausible = append(review.Implausible, fmt.Sprintf(
				"chain position %d (%q) is not a CA, so it cannot have issued "+
					"the certificate below it",
				index+1, parent.Subject.String(),
			))
			return
		}
	}
}

// reviewNames requires at least one name a real public origin could have.
func (review *CoverCertificateReview) reviewNames(leaf *x509.Certificate) {
	var plausible int
	for _, name := range leaf.DNSNames {
		normalized := strings.TrimSuffix(
			strings.ToLower(strings.TrimSpace(name)), ".",
		)
		if normalized == "" {
			continue
		}
		bare := strings.TrimPrefix(normalized, "*.")
		if !strings.Contains(bare, ".") {
			review.Implausible = append(review.Implausible, fmt.Sprintf(
				"carries the single-label name %q, which is not a public "+
					"domain and cannot resolve outside a local network", name,
			))
			continue
		}
		label := bare[strings.LastIndex(bare, ".")+1:]
		if reservedTopLevelDomains[label] {
			review.Implausible = append(review.Implausible, fmt.Sprintf(
				"carries the name %q, whose top-level domain %q is reserved "+
					"for special use and can never appear on a publicly "+
					"trusted certificate",
				name, label,
			))
			continue
		}
		if net.ParseIP(bare) != nil {
			review.Implausible = append(review.Implausible, fmt.Sprintf(
				"carries the IP literal %q as a DNS name", name,
			))
			continue
		}
		plausible++
	}
	for _, address := range leaf.IPAddresses {
		if address.IsLoopback() || address.IsUnspecified() {
			review.Implausible = append(review.Implausible, fmt.Sprintf(
				"carries the loopback address %s in its SANs, which a "+
					"public origin's certificate never does", address,
			))
		}
	}
	if plausible == 0 {
		review.Implausible = append(review.Implausible,
			"carries no publicly resolvable DNS name at all, so nothing about "+
				"it could belong to a real website")
	}
}

func (review *CoverCertificateReview) reviewValidity(leaf *x509.Certificate) {
	now := time.Now()
	switch {
	case now.After(leaf.NotAfter):
		review.Implausible = append(review.Implausible, fmt.Sprintf(
			"expired on %s; a prober's client shows it as broken, which is as "+
				"good a signal as any other anomaly",
			leaf.NotAfter.UTC().Format(time.RFC3339),
		))
	case now.Before(leaf.NotBefore):
		review.Implausible = append(review.Implausible, fmt.Sprintf(
			"is not valid until %s",
			leaf.NotBefore.UTC().Format(time.RFC3339),
		))
	}
	if leaf.NotAfter.Sub(leaf.NotBefore) > maximumPublicValidity {
		review.Implausible = append(review.Implausible, fmt.Sprintf(
			"is valid for %d days, beyond the %d-day CA/Browser Forum maximum, "+
				"so it was not issued by a public CA",
			int(leaf.NotAfter.Sub(leaf.NotBefore).Hours()/24),
			int(maximumPublicValidity.Hours()/24),
		))
	}
	if remaining := leaf.NotAfter.Sub(now); remaining > 0 && remaining <= coverExpiryWarning {
		review.Advisory = append(review.Advisory, fmt.Sprintf(
			"expires on %s, in %d days. It is loaded once and never reloaded, so "+
				"a renewed file is served only after a restart, and a restart after "+
				"the expiry is refused outright; renew it and restart the unit "+
				"before then",
			leaf.NotAfter.UTC().Format(time.RFC3339),
			int(remaining.Hours()/24),
		))
	}
}

// namesRelated reports whether two DNS names are equal or one is a parent of
// the other at a label boundary.
//
// It deliberately stops short of a public-suffix comparison: without a suffix
// list, "a.co.uk" and "b.co.uk" cannot be told apart from "a.example" and
// "b.example", and guessing would either miss real overlaps or refuse
// unrelated names. Two names under the same registrable domain, neither a
// parent of the other, are therefore not caught - one of several reasons the
// cover domain has to be procured independently rather than merely checked.
func namesRelated(first, second string) bool {
	normalize := func(name string) string {
		name = strings.ToLower(strings.TrimSpace(name))
		name = strings.TrimSuffix(name, ".")
		return strings.TrimPrefix(name, "*.")
	}
	first, second = normalize(first), normalize(second)
	if first == "" || second == "" {
		return false
	}
	return first == second ||
		strings.HasSuffix(first, "."+second) ||
		strings.HasSuffix(second, "."+first)
}
