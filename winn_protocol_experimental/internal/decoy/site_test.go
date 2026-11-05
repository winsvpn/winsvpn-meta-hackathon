package decoy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

// coverConfig builds, in memory, the kind of listener configuration
// coverlisten.Apply produces: an ordinary server certificate for the cover
// name, of the sort a prober receives. Nothing is written to the tree and no
// repository key material is read.
func coverConfig(t *testing.T, dnsNames ...string) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate cover key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: dnsNames[0]},
		DNSNames:              dnsNames,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cover certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cover certificate: %v", err)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf,
		}},
	}
}

// originFor builds the origin a deployment fronting coverName would serve with
// no -decoy-origin: the exact default path this work is about.
func originFor(t *testing.T, coverName string) *Origin {
	t.Helper()
	origin, err := NewOrigin(Config{
		CoverTLS:          coverConfig(t, coverName),
		PrivateServerName: "private-" + coverName,
	})
	if err != nil {
		t.Fatalf("NewOrigin(%s): %v", coverName, err)
	}
	return origin
}

func get(handler http.Handler, path string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	return recorder
}

func seedFor(index int) [32]byte {
	return sha256.Sum256(fmt.Appendf(nil, "decoy test seed %d", index))
}

var stylesheetHref = regexp.MustCompile(`<link rel="stylesheet" href="([^"]+)">`)

func stylesheetPath(document string) string {
	match := stylesheetHref.FindStringSubmatch(document)
	if match == nil {
		return ""
	}
	return match[1]
}

// deploymentFingerprint is what a censor collects from one unauthenticated
// probe and then matches against every other host it has scanned.
type deploymentFingerprint struct {
	index        string
	notFound     string
	etag         string
	lastModified string
	plaintext    string
	stylesheet   string
	robots       string
}

func fingerprint(origin *Origin) deploymentFingerprint {
	body := func(path string) string {
		recorder := get(origin, path)
		sum := sha256.Sum256(recorder.Body.Bytes())
		return fmt.Sprintf("%d:%s", recorder.Code, hex.EncodeToString(sum[:]))
	}
	index := get(origin, "/")
	stylesheet := stylesheetPath(index.Body.String())
	if stylesheet == "" {
		stylesheet = "inline"
	} else {
		stylesheet += "|" + body(stylesheet)
	}
	return deploymentFingerprint{
		index:        body("/"),
		notFound:     body("/does-not-exist"),
		etag:         index.Header().Get("ETag"),
		lastModified: index.Header().Get("Last-Modified"),
		plaintext:    hex.EncodeToString(sha256Sum(origin.PlaintextBadRequest())),
		stylesheet:   stylesheet,
		robots:       body("/robots.txt"),
	}
}

func sha256Sum(body []byte) []byte {
	sum := sha256.Sum256(body)
	return sum[:]
}

// TestDefaultDeploymentsShareNoResponse is the regression test for the bug.
//
// Before this change every deployment that did not pass -decoy-origin served
// the same index page, the same stylesheet at the same path, the same
// robots.txt, the same 404 and the same ETag, so a censor could fetch "/" from
// one known Winn gateway and then look the resulting hash up in any scan
// corpus to get the rest of the fleet. The property that has to hold is not
// "the generator varies" - it is that two deployments an operator sets up
// without doing anything special have nothing in common to match on.
func TestDefaultDeploymentsShareNoResponse(t *testing.T) {
	names := []string{
		"www.example.test",
		"status.example.invalid",
		"cdn.node7.example",
		"a.example",
		"files.example.test",
		"mirror.example.invalid",
		"gw-14.example",
		"static.example",
	}
	seen := map[string][]string{}
	for _, name := range names {
		got := fingerprint(originFor(t, name))
		for field, value := range map[string]string{
			"index page":    got.index,
			"404 page":      got.notFound,
			"ETag":          got.etag,
			"Last-Modified": got.lastModified,
			"cleartext 400": got.plaintext,
			"stylesheet":    got.stylesheet,
		} {
			key := field + "=" + value
			if previous, clash := seen[key]; clash {
				t.Errorf(
					"%s and %s serve an identical %s.\n"+
						"That is one probe and one hash lookup away from the list of "+
						"every Winn gateway running defaults, which is the correlator "+
						"this generator exists to remove.",
					previous[0], name, field,
				)
			}
			seen[key] = []string{name}
		}
	}
}

// TestSameCoverNameProducesTheSameSite pins the other half of the contract.
// The site has to be stable, or a restart rewrites the whole site and the
// change itself becomes an event a censor can watch for.
func TestSameCoverNameProducesTheSameSite(t *testing.T) {
	first := fingerprint(originFor(t, "www.example.test"))
	second := fingerprint(originFor(t, "www.example.test"))
	if first != second {
		t.Fatalf("the same cover name produced two different sites:\n%+v\n%+v", first, second)
	}
}

// TestLastModifiedDoesNotLeakUptime is the regression test for the second
// correlator in the old page: Last-Modified was the process start time, so any
// unauthenticated peer learned the host's uptime, and a fleet restarted
// together reported a cluster of near-identical timestamps.
func TestLastModifiedDoesNotLeakUptime(t *testing.T) {
	origin := originFor(t, "www.example.test")
	header := get(origin, "/").Header().Get("Last-Modified")
	if header == "" {
		t.Fatal("no Last-Modified")
	}
	modified, err := http.ParseTime(header)
	if err != nil {
		t.Fatalf("unparseable Last-Modified %q: %v", header, err)
	}
	if time.Since(modified) < 30*24*time.Hour {
		t.Fatalf(
			"Last-Modified is %s, which is close enough to now to be a start time; "+
				"it must be derived from the deployment, not from the clock",
			header,
		)
	}
	// And it does not move, which is what makes it uninformative about the
	// process rather than merely offset from it.
	again := get(originFor(t, "www.example.test"), "/").Header().Get("Last-Modified")
	if again != header {
		t.Fatalf("Last-Modified moved between builds: %q then %q", header, again)
	}
	// Nor is it a fleet-wide constant, which would reintroduce the same bug in
	// a different field.
	other := get(originFor(t, "other.example.test"), "/").Header().Get("Last-Modified")
	if other == header {
		t.Fatalf("two deployments report the same Last-Modified %q", header)
	}
}

// TestPrivateServerNameNeverSeedsTheCoverSite is the constraint that makes the
// derivation safe to do at all. The cover certificate is public - it is handed
// to every prober - but on the lab path (coverlisten's AllowWinnLeafAsCover)
// the served leaf is the Winn leaf, whose DNS name is the private ECH-inner
// name a peer must already know to reach the strict profile. Deriving public
// page bytes from it would put a function of that name on the wire.
func TestPrivateServerNameNeverSeedsTheCoverSite(t *testing.T) {
	const private = "gateway-internal.example"
	cover := coverConfig(t, private)

	if names := coverNames(cover, private); len(names) != 0 {
		t.Fatalf("coverNames returned %v, but the only name is the private one", names)
	}
	// Behavioural proof rather than an assertion about the helper: with the
	// private name excluded there is nothing left to derive from, so the site
	// is seeded from the CSPRNG and two builds cannot agree. If the name had
	// reached the seed, both builds would be identical.
	build := func() deploymentFingerprint {
		origin, err := NewOrigin(Config{CoverTLS: cover, PrivateServerName: private})
		if err != nil {
			t.Fatalf("NewOrigin: %v", err)
		}
		return fingerprint(origin)
	}
	if first, second := build(), build(); first == second {
		t.Fatal(
			"two builds from a certificate carrying only the private server name " +
				"produced the same site, so the private name is seeding the public page",
		)
	}
	// A cover certificate that does carry a public name uses it, and is
	// unaffected by the private one.
	public := coverConfig(t, "www.example.test", private)
	if names := coverNames(public, private); len(names) != 1 || names[0] != "www.example.test" {
		t.Fatalf("coverNames = %v, want only the public name", names)
	}
}

// TestCoverNameIsNotEchoedIntoThePage is the difference between varying a page
// and substituting a hostname into a template. A page that differs from every
// other only by a printed hostname is still one template, and everything
// around the substitution still matches.
func TestCoverNameIsNotEchoedIntoThePage(t *testing.T) {
	const name = "unmistakable-cover-name.example"
	origin := originFor(t, name)
	for _, path := range []string{"/", "/does-not-exist", "/robots.txt"} {
		body := strings.ToLower(get(origin, path).Body.String())
		if strings.Contains(body, "unmistakable") {
			t.Fatalf("%s echoes the cover name into the page body", path)
		}
	}
	if strings.Contains(strings.ToLower(string(origin.PlaintextBadRequest())), "unmistakable") {
		t.Fatal("the cleartext 400 body echoes the cover name")
	}
}

// TestGeneratedSitesAreInternallyConsistent runs the whole generator over many
// seeds. Every site it can produce has to be a site: a document, a stylesheet
// that resolves if it is linked, no template debris, and a 404 that is a page
// rather than a stub.
func TestGeneratedSitesAreInternallyConsistent(t *testing.T) {
	for index := range 300 {
		origin := newStaticOrigin(seedFor(index))
		document := get(origin, "/").Body.String()
		if !strings.HasPrefix(strings.ToLower(document), "<!doctype html>") {
			t.Fatalf("seed %d: page does not start with a doctype: %.40q", index, document)
		}
		// "}}" is deliberately absent: it closes a minified @media block and is
		// ordinary CSS, not debris.
		for _, debris := range []string{"{{", "%!", "<nil>", "%s", "%q"} {
			if strings.Contains(document, debris) {
				t.Fatalf("seed %d: page contains template debris %q", index, debris)
			}
		}
		if !strings.Contains(document, "<title>") || !strings.Contains(document, "<h1>") {
			t.Fatalf("seed %d: page has no title or heading", index)
		}
		if strings.Contains(document, "<link rel=\"stylesheet\"") {
			path := stylesheetPath(document)
			if path == "" {
				t.Fatalf("seed %d: stylesheet link is unparseable", index)
			}
			if code := get(origin, path).Code; code != http.StatusOK {
				t.Fatalf("seed %d: linked stylesheet %s returns %d", index, path, code)
			}
		} else if !strings.Contains(document, "<style>") {
			t.Fatalf("seed %d: page has neither a linked nor an inline stylesheet", index)
		}
		if code := get(origin, "/deep/missing/path").Code; code != http.StatusNotFound {
			t.Fatalf("seed %d: missing path returned %d", index, code)
		}
	}
}

// TestGeneratorHasEnoughFormsToHideAFleetIn measures the thing the eight-name
// test above can only sample: how many distinct bodies the generator actually
// produces. Eight deployments passing says nothing about a thousand, and an
// axis that quietly collapses - a persona list that stops being reached, a
// footer that only ever renders on one page - would leave the correlator
// half-open while the small test stayed green.
//
// The numbers are deliberately not tight. What is being defended is "a censor
// cannot cluster a fleet by body hash", and the failure it has to catch is a
// generator that has quietly gone back to producing a handful of pages.
func TestGeneratorHasEnoughFormsToHideAFleetIn(t *testing.T) {
	const deployments = 512
	distinct := map[string]map[string]bool{
		"index page":    {},
		"404 page":      {},
		"cleartext 400": {},
	}
	for index := range deployments {
		origin := newStaticOrigin(seedFor(index))
		distinct["index page"][get(origin, "/").Body.String()] = true
		distinct["404 page"][get(origin, "/missing").Body.String()] = true
		distinct["cleartext 400"][string(origin.plaintext)] = true
	}
	for what, bodies := range distinct {
		// One or two coincidences among 512 is what a large space looks like.
		// A handful of forms is what a template looks like.
		if len(bodies) < deployments-4 {
			t.Errorf(
				"%d seeds produced only %d distinct %ss.\n"+
					"A censor clusters a fleet on exactly this: too few forms and the "+
					"page hash is a group identifier again rather than a host one.",
				deployments, len(bodies), what,
			)
		}
	}
}

// TestHeadMatchesGet keeps the site behaving like a file server under the
// other method a scanner uses.
func TestHeadMatchesGet(t *testing.T) {
	origin := newStaticOrigin(seedFor(7))
	full := get(origin, "/")
	recorder := httptest.NewRecorder()
	origin.ServeHTTP(recorder, httptest.NewRequest(http.MethodHead, "/", nil))
	if recorder.Body.Len() != 0 {
		t.Fatalf("HEAD returned a body of %d bytes", recorder.Body.Len())
	}
	for _, header := range []string{"Content-Type", "Content-Length", "ETag", "Last-Modified"} {
		if got, want := recorder.Header().Get(header), full.Header().Get(header); got != want {
			t.Fatalf("HEAD %s = %q, GET = %q", header, got, want)
		}
	}
}
