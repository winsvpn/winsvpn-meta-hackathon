package decoy

import (
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"math/rand/v2"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// This file builds the built-in cover website, and it builds a different one
// for every deployment.
//
// The bug it closes is not that the page was implausible. The page was fine.
// The bug is that it was the same page everywhere: a fixed byte string
// compiled into the binary, served by every gateway that did not pass
// -decoy-origin, with an ETag that was a hash of that fixed byte string. A
// censor that wanted the list of Winn gateways fetched "/" from one known
// gateway, wrote down the hash, and then asked any scan corpus - Censys,
// Shodan, its own - which other hosts return a body with that hash. One
// request, no cryptanalysis, and the answer is the fleet.
//
// That is the same shape as the disclosure the cover certificate work just
// closed. There, the Winn CA's Distinguished Name linked every deployment at
// the TLS layer. Here, a constant HTTP body linked every deployment one layer
// up. Fixing one and leaving the other means the censor pays the same price
// for the same list over a different port.
//
// So the site is generated from a per-deployment seed derived from the cover
// certificate's DNS names - public information, on the wire in the certificate
// to anyone who completes a handshake, and stable across certificate renewal
// because it is the names and not the certificate bytes. Two deployments with
// different cover names serve different HTML, different CSS, a different
// stylesheet path, a different robots.txt, a different 404 and a different
// Last-Modified.
//
// What this does NOT do, and must not be read as doing:
//
//   - It does not make the page convincing. It is still a generated placeholder
//     page. A censor comparing structure rather than bytes - tag skeleton,
//     stylesheet shape, the fact that every one of these sites is a single
//     document with one heading and no links, no images, no favicon and no
//     second page - can still cluster them. The number of structural families
//     here is in the dozens, not the millions.
//   - It does not hide from a censor who has read this file. Winn is open
//     source; the derivation is deterministic and its only input is public. An
//     adversary who knows the generator can take a suspected host's cover
//     certificate, run the generator, and compare. That is a per-host cost
//     rather than a set-membership lookup over a corpus it already has, which
//     is a real and useful difference in bulk, and no defence at all against a
//     targeted one.
//
// The honest summary is that this removes a free, bulk, exact-match correlator.
// The thing that actually makes a gateway look like a website is a website:
// -decoy-origin pointed at a real site, and a real site behind the cover
// domain. See OPERATIONS.md.

// deploymentSeedLabel domain-separates the seed so that the same cover name
// used as an input somewhere else in the tree cannot produce a related value,
// and so that a future change to the generator can rotate every deployment's
// page by changing one string.
const deploymentSeedLabel = "winn.decoy.origin.v1\x00"

// deploymentSeed derives the per-deployment seed from the cover certificate's
// DNS names, and reports whether it managed to.
//
// The names, not the certificate. A certificate is renewed every 60 or 90 days
// under ACME, and seeding from its bytes would make the whole site's content
// change at renewal - so a fleet renewing on a common schedule would rewrite
// its pages within the same window, which is a correlator in its own right and
// a rather good one. Names survive renewal.
//
// The false return is the "operator supplied nothing usable" path. It seeds
// from the system CSPRNG instead, which still cannot be correlated across
// deployments; the cost is that the page is rebuilt on every restart, which is
// why the caller warns about it.
func deploymentSeed(names []string) ([32]byte, bool) {
	var seed [32]byte
	if len(names) == 0 {
		// crypto/rand.Read fills the buffer entirely or crashes the program; it
		// does not return a short read.
		_, _ = crand.Read(seed[:])
		return seed, false
	}
	digest := sha256.New()
	digest.Write([]byte(deploymentSeedLabel))
	for _, name := range names {
		digest.Write([]byte(name))
		digest.Write([]byte{0})
	}
	copy(seed[:], digest.Sum(nil))
	return seed, true
}

// coverNames returns the DNS names on the leaf the cover profile actually
// presents to unauthenticated peers, excluding the deployment's private
// ECH-inner server name.
//
// The exclusion is the whole reason this function exists rather than a field
// the caller fills in. The leaf a prober receives is public by definition - it
// was handed to the prober - so deriving from its names discloses nothing. But
// on the lab path (coverlisten's AllowWinnLeafAsCover) the cover profile serves
// the Winn leaf, whose DNS name is the private name that selects the strict
// profile, and that name is not public: a peer must already know it to draw a
// CertificateRequest. Seeding the public cover page from it would put a
// function of it on the wire for every prober. So it is skipped, and a
// deployment with nothing else to derive from falls back to the CSPRNG.
func coverNames(cover *tls.Config, privateServerName string) []string {
	leaf := coverLeaf(cover)
	if leaf == nil {
		return nil
	}
	private := normalizeName(privateServerName)
	names := make([]string, 0, len(leaf.DNSNames))
	for _, name := range leaf.DNSNames {
		name = normalizeName(name)
		if name == "" || name == private {
			continue
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return slices.Compact(names)
}

func normalizeName(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func coverLeaf(cover *tls.Config) *x509.Certificate {
	if cover == nil || len(cover.Certificates) == 0 ||
		len(cover.Certificates[0].Certificate) == 0 {
		return nil
	}
	if leaf := cover.Certificates[0].Leaf; leaf != nil {
		return leaf
	}
	parsed, err := x509.ParseCertificate(cover.Certificates[0].Certificate[0])
	if err != nil {
		return nil
	}
	return parsed
}

// staticResource is one document the cover site serves.
type staticResource struct {
	contentType string
	body        []byte
	tag         string
}

// staticOrigin is a small, ordinary, self-contained website. It is deliberately
// generic: it names no real organisation, claims nothing verifiable, and looks
// like the placeholder page that sits on a large share of the public internet.
type staticOrigin struct {
	resources map[string]staticResource
	notFound  staticResource

	// modified is the Last-Modified this deployment reports.
	//
	// It used to be the process start time, which leaked uptime to any
	// unauthenticated peer and made a fleet that restarts together - a rolling
	// deploy, a package upgrade, a reboot after a power event - visibly one
	// fleet. It is now derived from the same seed as the content: a fixed,
	// plausible date in the past that does not move when the process does.
	// Deriving it rather than pinning a constant matters, because a constant
	// would be exactly the fleet-wide identifier this file exists to remove.
	modified time.Time

	// plaintext is the body served to a cleartext HTTP request on the TLS
	// port. It is generated here, with the site, because it is reachable by
	// the same single probe and was the same fleet-wide constant.
	plaintext []byte
}

// newStaticOrigin builds the whole site from one seed. Every choice below is
// drawn from that seed, so the function is deterministic: the same cover names
// produce the same site on every host and across restarts, and different cover
// names produce a site that differs in its text, its markup skeleton, its
// stylesheet, its stylesheet's path, its robots.txt, its 404 and its dates.
func newStaticOrigin(seed [32]byte) *staticOrigin {
	random := rand.New(rand.NewChaCha8(seed))
	shape := newSiteShape(random)

	origin := &staticOrigin{
		resources: map[string]staticResource{},
		modified:  shape.modified,
		plaintext: shape.renderPlaintextError(),
	}
	index := newResource("text/html; charset=utf-8", shape.renderPage(shape.index))
	origin.resources["/"] = index
	origin.resources["/index.html"] = index
	origin.notFound = newResource("text/html; charset=utf-8", shape.renderPage(shape.missing))
	if shape.stylePath != "" {
		origin.resources[shape.stylePath] = newResource(
			"text/css; charset=utf-8", []byte(shape.css.render(shape.cssFormat)),
		)
	}
	if shape.robots != "" {
		origin.resources["/robots.txt"] = newResource(
			"text/plain; charset=utf-8", []byte(shape.robots),
		)
	}
	return origin
}

func newResource(contentType string, body []byte) staticResource {
	return staticResource{contentType: contentType, body: body, tag: etag(body)}
}

func etag(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:10]) + `"`
}

func (s *staticOrigin) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		s.write(writer, request, http.StatusMethodNotAllowed, staticResource{
			contentType: s.notFound.contentType, body: s.notFound.body,
		})
		return
	}
	if resource, ok := s.resources[request.URL.Path]; ok {
		s.write(writer, request, http.StatusOK, resource)
		return
	}
	s.write(writer, request, http.StatusNotFound, staticResource{
		contentType: s.notFound.contentType, body: s.notFound.body,
	})
}

func (s *staticOrigin) write(
	writer http.ResponseWriter, request *http.Request,
	status int, resource staticResource,
) {
	header := writer.Header()
	header.Set("Content-Type", resource.contentType)
	header.Set("Content-Length", strconv.Itoa(len(resource.body)))
	header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	if resource.tag != "" {
		// Cache validators go on the documents that have them and nowhere
		// else. A static file server sends Last-Modified for a file it served
		// off disk and not for a generated error page, and it answers both
		// conditional forms once it has advertised them.
		header.Set("ETag", resource.tag)
		header.Set("Last-Modified", s.modified.Format(http.TimeFormat))
		header.Set("Cache-Control", "public, max-age=3600")
		if s.notModified(request, resource.tag) {
			writer.WriteHeader(http.StatusNotModified)
			return
		}
	} else {
		header.Set("Cache-Control", "no-store")
	}
	writer.WriteHeader(status)
	if request.Method == http.MethodHead {
		return
	}
	// #nosec G705 -- every caller passes content generated at construction
	// (the index, the stylesheet, robots.txt, the 404 body). Nothing reaching
	// body derives from the request, which is read here only for its method
	// and its conditional headers, and Content-Type is carried on the resource
	// so the response is never sniffed.
	_, _ = writer.Write(resource.body)
}

func (s *staticOrigin) notModified(request *http.Request, tag string) bool {
	if match := request.Header.Get("If-None-Match"); match != "" {
		return strings.Contains(match, tag)
	}
	since := request.Header.Get("If-Modified-Since")
	if since == "" {
		return false
	}
	parsed, err := http.ParseTime(since)
	if err != nil {
		return false
	}
	return !s.modified.After(parsed)
}

// siteShape is the set of independent choices that make up one deployment's
// site. They are independent on purpose: a single template with one
// substituted hostname would still be a template, recognisable by everything
// around the substitution. What varies here is the wording, the markup
// skeleton, which elements exist at all, the stylesheet's contents, path and
// even whether it is a separate file, the robots policy, and the dates.
type siteShape struct {
	doctype     string
	htmlOpen    string
	charsetMeta string
	viewport    bool
	compactHead bool
	indent      string
	stylePath   string
	container   containerShape
	footer      footerShape
	rule        bool
	index       persona
	missing     persona
	css         styleSheet
	cssFormat   int
	robots      string
	modified    time.Time
	plaintext   persona
}

type containerShape struct {
	open     string
	close    string
	selector string
}

type footerShape struct {
	open     string
	close    string
	selector string
}

// persona is the human-readable content of one page. Each entry is a complete,
// self-consistent placeholder page of the kind that sits unremarkably on a
// large share of the public internet. None of them names a real organisation,
// claims anything verifiable, or says anything about what the host is for.
type persona struct {
	title      string
	heading    string
	paragraphs []string
	footer     string
}

var indexPersonas = []persona{
	{
		title:   "Welcome",
		heading: "Welcome",
		paragraphs: []string{
			"This server is up and running. If you are seeing this page, the web " +
				"server software is working correctly but no content has been " +
				"configured for this address yet.",
			"If you administer this host, replace this page with your own content. " +
				"Documentation for the server software is available from your " +
				"distribution or package maintainer.",
		},
		footer: "Powered by the default configuration.",
	},
	{
		title:   "It works!",
		heading: "It works!",
		paragraphs: []string{
			"This is the default landing page for this web server. The service is " +
				"installed and answering requests, and no site has been published " +
				"here yet.",
			"The owner of this host has not replaced the default document root. If " +
				"that is you, put your files in the configured document root and " +
				"reload the service.",
		},
		footer: "Default document root.",
	},
	{
		title:   "Default Page",
		heading: "Web Server Default Page",
		paragraphs: []string{
			"You have reached this page because no site has been configured for " +
				"this address. The server itself is healthy and responding normally.",
			"An administrator can replace this file at any time. Until then, every " +
				"request for this host is answered with this document.",
		},
		footer: "This page ships with the server package.",
	},
	{
		title:   "Nothing here yet",
		heading: "Nothing here yet",
		paragraphs: []string{
			"There is no site at this address at the moment. The request was " +
				"answered, which means the network path and the service are both " +
				"working.",
			"Content may appear here later. There is nothing to see in the meantime.",
		},
		footer: "Placeholder document.",
	},
	{
		title:   "Test Page",
		heading: "Test Page",
		paragraphs: []string{
			"If you can read this, the HTTP service on this machine is installed " +
				"and working. The page is served from the stock configuration and " +
				"says nothing about what the machine is used for.",
			"Replace or remove this document once a real site is in place.",
		},
		footer: "Stock configuration.",
	},
	{
		title:   "Coming soon",
		heading: "Coming soon",
		paragraphs: []string{
			"Nothing has been published at this address yet. Please try again " +
				"another time.",
			"If you expected a site here, the address may well be right but the " +
				"content is not ready.",
		},
		footer: "Under construction.",
	},
	{
		title:   "Site not configured",
		heading: "Site not configured",
		paragraphs: []string{
			"This hostname resolves to a server that has no site attached to it. " +
				"Nothing is wrong with the connection.",
			"Configuration for this address is the responsibility of whoever " +
				"operates the host.",
		},
		footer: "No virtual host matched this request.",
	},
	{
		title:   "Hello",
		heading: "Hello",
		paragraphs: []string{
			"The web server on this machine is installed and running. This is the " +
				"page it serves when no other content has been configured.",
			"There is nothing else to see at this address for now.",
		},
		footer: "Default response.",
	},
}

var missingPersonas = []persona{
	{
		title:      "404 Not Found",
		heading:    "404 Not Found",
		paragraphs: []string{"The requested URL was not found on this server."},
	},
	{
		title:   "Not Found",
		heading: "Not Found",
		paragraphs: []string{
			"The page you asked for is not on this server. Check the address and " +
				"try again.",
		},
	},
	{
		title:      "404",
		heading:    "404 - Page Not Found",
		paragraphs: []string{"That address does not exist here."},
	},
	{
		title:      "Page not found",
		heading:    "Page not found",
		paragraphs: []string{"The requested resource could not be located."},
	},
	{
		title:   "Not Found",
		heading: "404",
		paragraphs: []string{
			"Nothing is published at that path.",
			"If you followed a link to get here, the link is out of date.",
		},
	},
}

var plaintextPersonas = []persona{
	{
		title:      "400 Bad Request",
		heading:    "400 Bad Request",
		paragraphs: []string{"The plain HTTP request was sent to an HTTPS port."},
	},
	{
		title:   "400 Bad Request",
		heading: "Bad Request",
		paragraphs: []string{
			"Your browser sent a request that this server could not understand.",
		},
		footer: "Use https:// for this address.",
	},
	{
		title:      "Bad Request",
		heading:    "400 - Bad Request",
		paragraphs: []string{"The request could not be understood by this server."},
		footer:     "Check the address and try again.",
	},
	{
		title:      "400",
		heading:    "Bad Request",
		paragraphs: []string{"This port expects an encrypted connection."},
	},
	{
		title:   "400 Bad Request",
		heading: "400",
		paragraphs: []string{
			"The request was not valid for this port.",
			"An encrypted connection is required here.",
		},
	},
	{
		title:      "Bad Request",
		heading:    "Bad Request",
		paragraphs: []string{"This service only accepts requests over TLS."},
		footer:     "Encrypted connections only.",
	},
	{
		title:   "400 Bad Request",
		heading: "400 Bad Request",
		paragraphs: []string{
			"The server could not process this request.",
			"If you typed the address, try it with https:// in front.",
		},
		footer: "Bad request.",
	},
	{
		title:      "Error 400",
		heading:    "Error 400",
		paragraphs: []string{"Malformed request, or the wrong scheme for this port."},
	},
}

var containerShapes = []containerShape{
	{open: "<main>", close: "</main>", selector: "main"},
	{open: `<div class="content">`, close: "</div>", selector: ".content"},
	{open: `<div id="wrap">`, close: "</div>", selector: "#wrap"},
	{open: `<div class="container">`, close: "</div>", selector: ".container"},
	{open: `<article>`, close: "</article>", selector: "article"},
	{open: "", close: "", selector: "body"},
}

var footerShapes = []footerShape{
	{open: `<p class="footer">`, close: "</p>", selector: ".footer"},
	{open: "<footer>", close: "</footer>", selector: "footer"},
	{open: `<div class="foot">`, close: "</div>", selector: ".foot"},
	{open: `<p class="small">`, close: "</p>", selector: ".small"},
	{open: `<p class="note">`, close: "</p>", selector: ".note"},
}

var stylePaths = []string{
	"",
	"/assets/site.css",
	"/static/style.css",
	"/css/main.css",
	"/style.css",
	"/assets/css/main.css",
	"/static/css/site.css",
}

var robotsBodies = []string{
	"",
	"User-agent: *\nDisallow:\n",
	"User-agent: *\nAllow: /\n",
	"User-agent: *\nDisallow: /\n",
	"User-agent: *\nDisallow:\n\n",
	"# robots.txt\nUser-agent: *\nDisallow:\n",
}

var fontStacks = []string{
	"system-ui,-apple-system,Segoe UI,Roboto,sans-serif",
	"-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif",
	"'Helvetica Neue',Helvetica,Arial,sans-serif",
	"Georgia,'Times New Roman',serif",
	"system-ui,sans-serif",
	"Arial,Helvetica,sans-serif",
	"ui-sans-serif,system-ui,sans-serif",
}

// lastModifiedEpoch anchors the derived Last-Modified. It is a compiled-in
// constant rather than an offset from time.Now(), because anything relative to
// now moves when the process restarts and would put the restart back on the
// wire in a different shape.
var lastModifiedEpoch = time.Date(2019, time.March, 5, 0, 0, 0, 0, time.UTC)

// lastModifiedSpread is how far past the epoch a derived date may fall. Roughly
// six and a half years, so the dates a fleet reports are scattered rather than
// clustered in a window narrow enough to be a tell on its own.
const lastModifiedSpread = 2400 * 24 * time.Hour

func newSiteShape(random *rand.Rand) siteShape {
	shape := siteShape{
		doctype:     pick(random, []string{"<!doctype html>", "<!DOCTYPE html>"}),
		htmlOpen:    pick(random, []string{`<html lang="en">`, "<html>", `<html lang="en-GB">`}),
		viewport:    random.IntN(4) != 0,
		compactHead: random.IntN(3) == 0,
		indent:      pick(random, []string{"", "  ", "\t"}),
		stylePath:   pick(random, stylePaths),
		container:   pick(random, containerShapes),
		footer:      pick(random, footerShapes),
		rule:        random.IntN(2) == 0,
		index:       pick(random, indexPersonas),
		missing:     pick(random, missingPersonas),
		plaintext:   pick(random, plaintextPersonas),
		cssFormat:   random.IntN(3),
		robots:      pick(random, robotsBodies),
		modified: lastModifiedEpoch.
			Add(time.Duration(random.Int64N(int64(lastModifiedSpread)))).
			UTC().Truncate(time.Second),
	}
	shape.charsetMeta = `<meta charset="utf-8">`
	if random.IntN(5) == 0 {
		shape.charsetMeta =
			`<meta http-equiv="Content-Type" content="text/html; charset=utf-8">`
	}
	// One site, one footer line: the error pages carry the index's. This is
	// what a real site does, and it also puts the footer element and the rule
	// on every page rather than only on the index, which is where most of the
	// error pages' variety comes from - without it the 404 and the cleartext
	// 400 have markedly fewer distinct forms than the index does.
	shape.missing.footer = shape.index.footer
	shape.index = withClosingLine(random, shape.index, indexClosings)
	shape.missing = withClosingLine(random, shape.missing, missingClosings)
	shape.plaintext = withClosingLine(random, shape.plaintext, plaintextClosings)
	// A page with no footer element is a shape of its own, so allow it - but
	// keep the persona's footer text out of the markup entirely when it goes,
	// rather than leaving an empty element behind.
	if random.IntN(5) == 0 {
		shape.footer = footerShape{}
	}
	shape.css = newStyleSheet(random, shape)
	return shape
}

func pick[T any](random *rand.Rand, options []T) T {
	return options[random.IntN(len(options))]
}

// Closing lines. A page that may or may not end with one more ordinary
// sentence is a page with several more forms, and unlike most of the other
// axes this one costs nothing to read as natural: placeholder pages end with
// exactly this kind of line or do not.
var indexClosings = []string{
	"",
	"",
	"No further information is available at this address.",
	"The service is otherwise operating normally.",
	"This document is generated by the server itself.",
	"See the server documentation for configuration details.",
	"There is nothing that needs reporting here.",
	"Thank you for your patience.",
}

var missingClosings = []string{
	"",
	"",
	"No further information is available.",
	"If you followed a link to get here, it is out of date.",
	"Return to the start page to continue.",
	"Contact whoever operates this site if you believe this is an error.",
}

var plaintextClosings = []string{
	"",
	"",
	"No further information is available.",
	"Please retry over a secure connection.",
	"Contact the operator of this host if this is unexpected.",
}

func withClosingLine(random *rand.Rand, page persona, closings []string) persona {
	closing := pick(random, closings)
	if closing == "" {
		return page
	}
	paragraphs := make([]string, 0, len(page.paragraphs)+1)
	paragraphs = append(paragraphs, page.paragraphs...)
	page.paragraphs = append(paragraphs, closing)
	return page
}

// renderPage lays out one document in this deployment's markup skeleton.
func (s siteShape) renderPage(page persona) []byte {
	return s.renderDocument(page, styleAsConfigured)
}

// How a document reaches its CSS. styleAsConfigured follows the deployment's
// choice - a linked file or an inline block. styleInline forces the block,
// which is what the cleartext error page needs: it is written before any
// handshake, so a link to an https-only asset would never resolve, but an
// inline block resolves anywhere. Standalone error pages carrying their own
// styles is ordinary, and it is also what stops that page - the shortest one
// here, and the only one with no stylesheet link to vary - from having too few
// distinct forms to hide a fleet in.
const (
	styleAsConfigured = iota
	styleInline
)

func (s siteShape) renderDocument(page persona, styleMode int) []byte {
	var out strings.Builder
	out.WriteString(s.doctype + "\n")
	out.WriteString(s.htmlOpen + "\n")
	out.WriteString(s.renderHead(page.title, styleMode))
	out.WriteString("<body>\n")
	indent := ""
	if s.container.open != "" {
		out.WriteString(s.container.open + "\n")
		indent = s.indent
	}
	out.WriteString(indent + "<h1>" + page.heading + "</h1>\n")
	for _, paragraph := range page.paragraphs {
		out.WriteString(indent + "<p>" + paragraph + "</p>\n")
	}
	if s.footer.open != "" && page.footer != "" {
		if s.rule {
			out.WriteString(indent + "<hr>\n")
		}
		out.WriteString(indent + s.footer.open + page.footer + s.footer.close + "\n")
	}
	if s.container.close != "" {
		out.WriteString(s.container.close + "\n")
	}
	out.WriteString("</body>\n</html>\n")
	return []byte(out.String())
}

func (s siteShape) renderHead(title string, styleMode int) string {
	elements := []string{s.charsetMeta}
	if s.viewport {
		elements = append(elements,
			`<meta name="viewport" content="width=device-width, initial-scale=1">`)
	}
	elements = append(elements, "<title>"+title+"</title>")
	linked := styleMode == styleAsConfigured && s.stylePath != ""
	if linked {
		elements = append(elements,
			`<link rel="stylesheet" href="`+s.stylePath+`">`)
	}
	inline := !linked
	if s.compactHead {
		head := "<head>" + strings.Join(elements, "")
		if inline {
			head += "<style>" + s.css.render(cssMinified) + "</style>"
		}
		return head + "</head>\n"
	}
	var out strings.Builder
	out.WriteString("<head>\n")
	for _, element := range elements {
		out.WriteString(s.indent + element + "\n")
	}
	if inline {
		out.WriteString(s.indent + "<style>\n")
		out.WriteString(s.css.render(s.cssFormat))
		out.WriteString(s.indent + "</style>\n")
	}
	out.WriteString("</head>\n")
	return out.String()
}

// renderPlaintextError builds the body served to a cleartext HTTP request that
// arrives on the TLS port.
//
// It is generated here rather than being a package constant for the reason the
// rest of this file exists: it was a fixed byte string served identically by
// every deployment, reachable in one probe by a scanner that speaks cleartext
// to port 443, which is a thing bulk scanners routinely do. Fixing the HTTPS
// body and leaving this one would have sold the same list at the same price
// over a different request.
//
// It goes through the same skeleton as the rest of the site, which is both what
// real servers do - their error pages come out of the same template as
// everything else - and what gives a page this short enough room to vary. A
// standalone four-line error document has only its wording to differ in, and
// wording alone does not produce enough distinct bodies to stop a fleet
// clustering: the first draft of this had 48 possible bodies, and the test that
// counts forms caught it at 512 seeds.
func (s siteShape) renderPlaintextError() []byte {
	return s.renderDocument(s.plaintext, styleInline)
}

// styleSheet is the deployment's CSS as structured rules, so the formatting -
// packed, expanded or minified - is a choice made once at render time rather
// than baked into a string literal.
type styleSheet struct {
	rules []cssRule
	dark  []cssRule
}

type cssRule struct {
	selector     string
	declarations []string
}

func newStyleSheet(random *rand.Rand, shape siteShape) styleSheet {
	background := lightColour(random)
	foreground := darkColour(random)
	muted := midColour(random)
	rule := lineColour(random)

	root := []string{
		"font-family:" + pick(random, fontStacks),
		"line-height:" + pick(random, []string{"1.4", "1.45", "1.5", "1.55", "1.6"}),
		"background:" + background,
		"color:" + foreground,
	}
	padding := "padding:" + pick(random, []string{
		"2rem 1rem", "3rem 1.5rem", "40px 20px", "1.5rem", "2.5rem 1rem",
	})
	width := pick(random, []string{
		"36rem", "40rem", "44rem", "48rem", "640px", "720px", "760px",
	})
	sheet := styleSheet{}
	sheet.rules = append(sheet.rules, cssRule{selector: "html", declarations: root})
	if shape.container.selector == "body" {
		sheet.rules = append(sheet.rules, cssRule{
			selector:     "body",
			declarations: []string{"margin:0 auto", padding, "max-width:" + width},
		})
	} else {
		sheet.rules = append(sheet.rules, cssRule{
			selector:     "body",
			declarations: []string{"margin:0", padding},
		})
		sheet.rules = append(sheet.rules, cssRule{
			selector:     shape.container.selector,
			declarations: []string{"max-width:" + width, "margin:0 auto"},
		})
	}
	sheet.rules = append(sheet.rules, cssRule{
		selector: "h1",
		declarations: []string{
			"font-size:" + pick(random, []string{
				"1.5rem", "1.6rem", "1.75rem", "2rem", "28px",
			}),
			"font-weight:" + pick(random, []string{"500", "600", "700", "bold"}),
			"margin:" + pick(random, []string{"0 0 1rem", "0 0 .75rem", "0 0 16px"}),
		},
	})
	sheet.rules = append(sheet.rules, cssRule{
		selector:     "p",
		declarations: []string{"margin:" + pick(random, []string{"0 0 1rem", "0 0 .9rem", "0 0 16px"})},
	})
	if shape.rule {
		sheet.rules = append(sheet.rules, cssRule{
			selector: "hr",
			declarations: []string{
				"border:0",
				"border-top:1px solid " + rule,
				"margin:" + pick(random, []string{"2rem 0 1rem", "1.5rem 0 1rem", "32px 0 16px"}),
			},
		})
	}
	if shape.footer.selector != "" {
		sheet.rules = append(sheet.rules, cssRule{
			selector: shape.footer.selector,
			declarations: []string{
				"color:" + muted,
				"font-size:" + pick(random, []string{".875rem", ".85rem", "13px", ".9rem"}),
			},
		})
	}
	// Roughly half of these sites answer prefers-color-scheme. A site that
	// never does and a site that always does are both ordinary; what would not
	// be ordinary is every one of them making the same choice.
	if random.IntN(2) == 0 {
		sheet.dark = append(sheet.dark, cssRule{
			selector: "html",
			declarations: []string{
				"background:" + darkColour(random),
				"color:" + lightColour(random),
			},
		})
		if shape.rule {
			sheet.dark = append(sheet.dark, cssRule{
				selector:     "hr",
				declarations: []string{"border-top-color:" + lineColour(random)},
			})
		}
		if shape.footer.selector != "" {
			sheet.dark = append(sheet.dark, cssRule{
				selector:     shape.footer.selector,
				declarations: []string{"color:" + midColour(random)},
			})
		}
	}
	return sheet
}

const (
	cssPacked = iota
	cssExpanded
	cssMinified
)

func (s styleSheet) render(format int) string {
	var out strings.Builder
	writeRules(&out, s.rules, format, "")
	if len(s.dark) > 0 {
		switch format {
		case cssMinified:
			out.WriteString("@media(prefers-color-scheme:dark){")
			writeRules(&out, s.dark, format, "")
			out.WriteString("}")
		default:
			out.WriteString("@media (prefers-color-scheme: dark) {\n")
			writeRules(&out, s.dark, format, "  ")
			out.WriteString("}\n")
		}
	}
	return out.String()
}

func writeRules(out *strings.Builder, rules []cssRule, format int, indent string) {
	for _, rule := range rules {
		switch format {
		case cssMinified:
			out.WriteString(rule.selector + "{" +
				strings.Join(rule.declarations, ";") + "}")
		case cssExpanded:
			out.WriteString(indent + rule.selector + " {\n")
			for _, declaration := range rule.declarations {
				out.WriteString(indent + "  " +
					strings.Replace(declaration, ":", ": ", 1) + ";\n")
			}
			out.WriteString(indent + "}\n")
		default:
			out.WriteString(indent + rule.selector + "{" +
				strings.Join(rule.declarations, ";") + "}\n")
		}
	}
}

// Colour helpers. Both notations below occur constantly in hand-written CSS, so
// varying which one a deployment uses widens the space without making any of
// them look generated.
func lightColour(random *rand.Rand) string {
	if random.IntN(3) == 0 {
		return pick(random, []string{"#fff", "#fdfdfd", "#fafafa", "white", "#eee"})
	}
	return hexColour(random, 0xf0, 0xff)
}

func darkColour(random *rand.Rand) string {
	if random.IntN(3) == 0 {
		return pick(random, []string{"#111", "#000", "#1a1a1a", "#222", "#141414"})
	}
	return hexColour(random, 0x08, 0x30)
}

func midColour(random *rand.Rand) string {
	if random.IntN(3) == 0 {
		return pick(random, []string{"#666", "#777", "#6b6b6b", "#888", "#5f5f5f"})
	}
	return hexColour(random, 0x55, 0x99)
}

func lineColour(random *rand.Rand) string {
	if random.IntN(3) == 0 {
		return pick(random, []string{"#ddd", "#e5e5e5", "#eee", "#ccc", "#333"})
	}
	return hexColour(random, 0xcc, 0xee)
}

func hexColour(random *rand.Rand, low, high int) string {
	span := high - low + 1
	channel := func() int { return low + random.IntN(span) }
	return "#" + hex.EncodeToString([]byte{
		byte(channel()), byte(channel()), byte(channel()),
	})
}
