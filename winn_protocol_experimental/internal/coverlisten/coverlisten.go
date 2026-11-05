// Package coverlisten is the single way to build the TLS configuration for a
// Winn listener that a censor can reach.
//
// The defence it wires up already existed. internal/tlsconfig has the cover
// profile, internal/echconfig has the non-mandatory ECH variant the cover
// profile needs, and internal/decoy has the cover origin. What did not exist
// was any reason for the next listener to use them: the carrier server
// assembled all three inline in its own main(), and winn-server and
// winn-token-issuer - both of which bind 0.0.0.0 in the shipped systemd unit
// templates, and both of which request a client certificate unconditionally,
// so both of which have a CA Distinguished Name to protect - simply did not.
//
// That is the bug class this package exists to close. The mechanism working in
// isolation is not the property that protects anyone; the property that
// protects anyone is that every reachable listener is behind it. So the
// assembly lives in one place, it refuses rather than warns when the
// configuration would identify the deployment, and Verify re-checks the result
// at the point of use so a listener cannot serve a configuration that only
// looks like a cover profile.
package coverlisten

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

// Options describes one reachable listener.
type Options struct {
	// Winn is the strict configuration a genuine client negotiates. It is
	// retained, not modified, and handed out by GetConfigForClient.
	Winn *tls.Config

	// CoverALPN is what an ordinary server on this port would offer:
	// {"h2","http/1.1"} for TCP, {"h3"} for QUIC.
	CoverALPN []string

	// CoverServerName is an operator override for the ECH-inner SNI that
	// selects the Winn profile. Empty derives it from the server certificate.
	CoverServerName string

	// CoverCertPath and CoverKeyPath are the certificate presented to
	// unauthenticated peers. Both are required unless AllowWinnLeafAsCover.
	CoverCertPath string
	CoverKeyPath  string

	// ECHKeys are installed on the cover listener without making ECH
	// acceptance a precondition. Go decrypts ECH from the listener's own
	// configuration, before GetConfigForClient can select the Winn profile,
	// so the keys have to be here as well as on the strict profile.
	ECHKeys []tls.EncryptedClientHelloKey

	// RequestsClientCertificate is true for a listener whose strict profile
	// asks for a client certificate. Only such a listener has a client CA
	// name to protect, and so only such a listener may fall back to selecting
	// the Winn profile on the ECH marker alone when the server certificate
	// carries no DNS name to match on.
	RequestsClientCertificate bool

	// AllowWinnLeafAsCover is the lab escape hatch described on
	// tlsconfig.CoverProfile.AllowWinnLeafAsCover. A listener that takes it is
	// identifiable to any prober that completes one handshake.
	AllowWinnLeafAsCover bool

	// AllowIdentifyingCoverCertificate serves a cover certificate that names
	// the operator - an EV or OV certificate, or any certificate whose subject
	// carries more than a Common Name.
	//
	// It is a sibling of AllowWinnLeafAsCover rather than the same flag
	// because it is a different failure. AllowWinnLeafAsCover says "this
	// listener discloses that a Winn CA exists". This says "this listener
	// discloses the operator's registered legal identity", which is strictly
	// worse and is what the certificate it exists to refuse would have done.
	AllowIdentifyingCoverCertificate bool

	// AllowImplausibleCoverCertificate serves a cover certificate that could
	// not belong to a real public origin - self-signed, a CA served as a leaf,
	// a reserved-TLD or single-label name, an unlinked chain, an expired leaf.
	//
	// It is a third flag rather than part of the second because the two
	// failures are independent and were got wrong independently: the
	// certificate that failed this check was generated specifically to fix the
	// one that failed the identity check, and passed the identity check
	// perfectly. Folding them together would let an operator who fixed one
	// silence the other without noticing they had.
	AllowImplausibleCoverCertificate bool

	// CoverOnly builds a listener on which no ClientHello selects the strict
	// profile: every peer stays on the cover profile, whatever it presents.
	//
	// It exists for a listener that has nothing to serve on the strict
	// profile. cmd/winn3-gateway is one: v3 is not an HTTP protocol, its
	// Guard routes a "Winn" connection to the same decoy as everything else,
	// and no client ever completes TLS to it, so a reachable strict profile
	// is pure exposure there. The exposure is real because Go hands
	// GetConfigForClient the OUTER ClientHello when it could not decrypt the
	// ECH extension, and that hello carries the extension and whatever SNI
	// the peer chose to send in the clear. A prober that knows the private
	// server name therefore selects the strict profile without holding the
	// ECH key, and is served the Winn leaf (issuer: the Winn CA) before the
	// strict profile's VerifyConnection can refuse it. crypto/tls exposes no
	// "ECH accepted" signal at GetConfigForClient, so the name cannot be
	// protected there; the listener that needs no strict profile must not
	// have one.
	CoverOnly bool

	// Logf receives operator warnings. Nil discards them.
	Logf func(format string, args ...any)
}

// Listener is a built cover listener and the decisions that produced it.
type Listener struct {
	// TLS is the configuration the listener must use.
	TLS *tls.Config

	// PrivateServerName is the ECH-inner SNI that selects the Winn profile,
	// and is also what the application-layer guard re-checks. Empty means no
	// name check applies.
	PrivateServerName string

	// AllowUnnamedWinnClients records that the Winn profile is selected on the
	// ECH marker alone because the certificate carries no DNS name.
	AllowUnnamedWinnClients bool

	// CoverCertificate records whether a distinct cover certificate was
	// supplied. False means the Winn leaf is being served to probers under
	// AllowWinnLeafAsCover.
	CoverCertificate bool

	// CoverNotAfter is the served cover leaf's NotAfter, so a command can
	// publish it where an operator or the hub will see it before the day the
	// unit stops starting. Zero when the Winn leaf is served instead.
	CoverNotAfter time.Time
}

// ErrNoCoverCertificate is returned when a listener would serve the Winn leaf
// to unauthenticated peers without the caller having said so.
var ErrNoCoverCertificate = errors.New("cover certificate is required")

// ErrIdentifyingCoverCertificate is returned when the supplied cover
// certificate would tell a prober who runs this deployment.
var ErrIdentifyingCoverCertificate = errors.New(
	"cover certificate identifies the operator",
)

// ErrImplausibleCoverCertificate is returned when the supplied cover
// certificate could not belong to a real public origin.
var ErrImplausibleCoverCertificate = errors.New(
	"cover certificate could not be a real public origin",
)

// reviewCoverCertificate applies both halves of the cover-certificate review
// and refuses on either, unless the matching option waives it by name.
func reviewCoverCertificate(
	cover *tls.Certificate, options Options, logf func(string, ...any),
) error {
	winnLeaf, err := parseWinnLeaf(options.Winn)
	if err != nil {
		return err
	}
	review, err := ReviewCoverCertificate(cover, winnLeaf)
	if err != nil {
		return err
	}
	for _, note := range review.Advisory {
		logf("NOTE: cover certificate %s", note)
	}
	// Both halves are reported before either refuses, so an operator fixing
	// one is not surprised by the other on the next start. That sequence -
	// fix the identity leak, believe you are done - is what produced the
	// second bad candidate.
	waive := func(
		findings []string, allowed bool, sentinel error, flag, headline string,
	) error {
		if len(findings) == 0 {
			return nil
		}
		detail := "\n  - " + strings.Join(findings, "\n  - ")
		if allowed {
			logf(
				"WARNING: serving a cover certificate that %s, because %s was "+
					"passed. This is a lab setting.%s",
				headline, flag, detail,
			)
			return nil
		}
		return fmt.Errorf("%w: it %s.%s\n\nSee OPERATIONS.md section 2.1. "+
			"Pass %s only for a lab where no censor is watching",
			sentinel, headline, detail, flag)
	}
	if err := waive(
		review.Identifying, options.AllowIdentifyingCoverCertificate,
		ErrIdentifyingCoverCertificate, "-insecure-cover-identifies-operator",
		"tells every prober who runs this deployment",
	); err != nil {
		return err
	}
	return waive(
		review.Implausible, options.AllowImplausibleCoverCertificate,
		ErrImplausibleCoverCertificate, "-insecure-cover-is-not-a-real-origin",
		"could not belong to a real public origin, so a prober concludes the "+
			"endpoint is improvised even without attributing it",
	)
}

// Apply builds the listener configuration.
//
// It refuses, rather than warning, when no cover certificate is supplied. The
// warning it replaces is the reason this was still open: a leaf carries its
// issuer's Distinguished Name in the clear to anyone who completes a
// handshake, the Winn leaf's issuer is the CA every Winn client pins, and so
// serving it to probers identifies the deployment and correlates it with every
// other deployment under that CA. For a user in a jurisdiction where being
// identified as a circumvention-tool user carries physical risk, that is a
// free, passive, permanent identification, and no amount of stderr makes it
// not ship.
func Apply(options Options) (Listener, error) {
	if options.Winn == nil {
		return Listener{}, errors.New("strict tls configuration is required")
	}
	if len(options.CoverALPN) == 0 {
		return Listener{}, errors.New("cover ALPN is required")
	}
	if len(options.ECHKeys) == 0 {
		return Listener{}, errors.New("at least one ECH server key is required")
	}
	if _, err := parseWinnLeaf(options.Winn); err != nil {
		return Listener{}, err
	}
	logf := options.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	privateServerName := ""
	if !options.CoverOnly {
		privateServerName = tlsconfig.NormalizeServerName(options.CoverServerName)
	}
	if privateServerName == "" && !options.CoverOnly {
		if derived, err := tlsconfig.PrivateServerNameFromCertificate(
			options.Winn,
		); err == nil {
			privateServerName = derived
		}
	}
	// Only a listener that requests a client certificate has a CA name to
	// protect, so only that listener may keep the strict profile reachable
	// when there is no name to match on. Anything else stays on the cover
	// profile throughout, which is the stronger position, not a weaker one.
	// A CoverOnly listener has neither a name nor the unnamed fallback, so
	// ApplyCoverProfile installs no GetConfigForClient at all.
	allowUnnamed := privateServerName == "" && options.RequestsClientCertificate &&
		!options.CoverOnly
	if allowUnnamed {
		logf(
			"WARNING: server certificate has no DNS name, so the Winn TLS profile " +
				"is selected on the ECH marker alone; the client CA name is withheld " +
				"from ordinary probers but not from a targeted one. Issue a " +
				"certificate with a DNS SAN.",
		)
	}

	var coverCertificate *tls.Certificate
	var coverNotAfter time.Time
	switch {
	case options.CoverCertPath != "" || options.CoverKeyPath != "":
		loaded, err := tlsconfig.LoadCoverCertificate(
			options.CoverCertPath, options.CoverKeyPath,
		)
		if err != nil {
			return Listener{}, err
		}
		if err := reviewCoverCertificate(loaded, options, logf); err != nil {
			return Listener{}, err
		}
		// The review above parsed the whole chain, so this cannot fail here.
		leaf, err := x509.ParseCertificate(loaded.Certificate[0])
		if err != nil {
			return Listener{}, fmt.Errorf("parse cover certificate: %w", err)
		}
		coverNotAfter = leaf.NotAfter
		coverCertificate = loaded
	case options.AllowWinnLeafAsCover:
		issuer, err := tlsconfig.CertificateIssuerName(options.Winn)
		if err != nil {
			issuer = "unknown"
		}
		logf(
			"WARNING: serving the Winn leaf to unauthenticated peers because the "+
				"cover certificate was explicitly waived. Its issuer (%s) identifies "+
				"this deployment and every other under the same CA to anyone who "+
				"completes one handshake. This is a lab setting.",
			issuer,
		)
	default:
		issuer, err := tlsconfig.CertificateIssuerName(options.Winn)
		if err != nil {
			issuer = "the Winn CA"
		}
		return Listener{}, fmt.Errorf(
			"%w: without one, every unauthenticated prober receives the Winn leaf, "+
				"whose issuer (%s) identifies this deployment and links it to every "+
				"other under the same CA. Supply -cover-cert and -cover-key with an "+
				"ordinary server certificate for the cover name, or pass "+
				"-insecure-cover-reuses-winn-leaf for a lab where no censor is "+
				"watching",
			ErrNoCoverCertificate, issuer,
		)
	}

	cover, err := tlsconfig.ApplyCoverProfile(options.Winn, tlsconfig.CoverProfile{
		PrivateServerName:       privateServerName,
		CoverALPN:               append([]string(nil), options.CoverALPN...),
		Certificate:             coverCertificate,
		AllowWinnLeafAsCover:    options.AllowWinnLeafAsCover,
		AllowUnnamedWinnClients: allowUnnamed,
	})
	if err != nil {
		return Listener{}, err
	}
	// ConfigureServerCover, not ConfigureServer: refusing a peer that did not
	// use ECH is exactly the behaviour a real ECH deployment does not have,
	// and refusing it here would reintroduce the discriminator the cover
	// profile exists to remove.
	if err := echconfig.ConfigureServerCover(cover, options.ECHKeys); err != nil {
		return Listener{}, err
	}
	built := Listener{
		TLS:                     cover,
		PrivateServerName:       privateServerName,
		AllowUnnamedWinnClients: allowUnnamed,
		CoverCertificate:        coverCertificate != nil,
		CoverNotAfter:           coverNotAfter,
	}
	if err := Verify(cover); err != nil {
		return Listener{}, err
	}
	return built, nil
}

// Verify re-checks, at the point of use, that a configuration about to be
// served really is a cover profile.
//
// Apply already calls it, so on the built path it is redundant by
// construction. That is the point: a listener calls Verify immediately before
// serving, so a configuration that reached the listener by some other route -
// a future refactor, a merge, a copied main() - cannot be served. The checks
// are the observable facts a prober collects on one connection, not the shape
// of the code that produced them.
func Verify(cover *tls.Config) error {
	if cover == nil {
		return errors.New("no listener configuration")
	}
	if cover.ClientAuth != tls.NoClientCert {
		return errors.New(
			"listener requests a client certificate from unauthenticated peers, " +
				"so certificate_authorities discloses the client CA's name",
		)
	}
	if cover.ClientCAs != nil {
		return errors.New("listener carries a client CA pool on the cover profile")
	}
	if cover.MinVersion > tls.VersionTLS12 {
		return errors.New(
			"listener refuses TLS 1.2, which is a single-probe discriminator on " +
				"its own; ordinary servers have not refused it for years",
		)
	}
	if len(cover.CurvePreferences) != 0 {
		return errors.New(
			"listener pins a named group set, which is a single-probe " +
				"discriminator; the cover profile must accept the stock set",
		)
	}
	if len(cover.CipherSuites) != 0 {
		return errors.New(
			"listener pins a cipher suite set, which is a single-probe " +
				"discriminator; the cover profile must accept the stock set",
		)
	}
	if cover.SessionTicketsDisabled {
		return errors.New(
			"listener never issues NewSessionTicket, which ordinary TLS 1.3 " +
				"servers do",
		)
	}
	if cover.VerifyConnection != nil {
		return errors.New(
			"listener imposes a connection precondition on unauthenticated " +
				"peers; mandatory ECH belongs on the strict profile only",
		)
	}
	if len(cover.EncryptedClientHelloKeys) == 0 {
		return errors.New(
			"listener has no ECH keys, so a genuine client's inner ClientHello " +
				"cannot be decrypted and the strict profile is unreachable",
		)
	}
	if _, err := leafDER(cover); err != nil {
		return fmt.Errorf("cover certificate: %w", err)
	}
	return nil
}

// ServesWinnLeaf reports whether the listener presents the same leaf to
// unauthenticated peers that it presents to Winn clients - that is, whether
// the issuer Distinguished Name of the Winn CA is on the wire for anyone who
// completes a handshake. A production listener must never do this.
func ServesWinnLeaf(cover, winn *tls.Config) (bool, error) {
	coverLeaf, err := leafDER(cover)
	if err != nil {
		return false, err
	}
	winnLeaf, err := leafDER(winn)
	if err != nil {
		return false, err
	}
	return bytes.Equal(coverLeaf, winnLeaf), nil
}

func leafDER(config *tls.Config) ([]byte, error) {
	if config == nil || len(config.Certificates) == 0 ||
		len(config.Certificates[0].Certificate) == 0 {
		return nil, errors.New("no certificate is configured")
	}
	return config.Certificates[0].Certificate[0], nil
}

// parseWinnLeaf returns the strict profile's leaf so cover-certificate review
// can compare issuers and names. A present but unparseable leaf used to be
// treated as "no Winn leaf", which skipped the relational half of the review
// and still let Apply succeed. Fail closed: if the bytes are there, they must
// parse. An empty Certificates list is not an error here; ApplyCoverProfile
// still requires a certificate or GetCertificate.
func parseWinnLeaf(winn *tls.Config) (*x509.Certificate, error) {
	if winn == nil || len(winn.Certificates) == 0 {
		return nil, nil
	}
	cert := winn.Certificates[0]
	if cert.Leaf != nil {
		return cert.Leaf, nil
	}
	if len(cert.Certificate) == 0 {
		return nil, nil
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse Winn server certificate: %w", err)
	}
	return parsed, nil
}
