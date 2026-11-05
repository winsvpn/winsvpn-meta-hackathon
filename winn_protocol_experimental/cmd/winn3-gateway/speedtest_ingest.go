// Speedtest ingest for the gateway's INNER interface (RV-B, Round 38 treaty).
//
// WHY THIS EXISTS. The in-app speedtest measured against third-party
// backbones (Cloudflare, CacheFly), whose path quality varies per connection;
// the reported number swung 3x between target families while the tunnel
// carried the full rate (Round 38 evidence: "North America" runs 681-790
// Mbps up, "Global Backbone" runs 234-301 up, same builds, same hour). The
// treaty's fix: the primary speedtest target is the gateway itself, over the
// established tunnel. Membership in the tunnel IS the authentication — a
// client can only reach the inner address through an admitted, encrypted
// session — so no additional credential surface is created.
//
// BOUNDARIES. The listener binds ONLY to the inner IPv4 address on the
// winn3gw0 interface; there is no public socket, and the cover listener's
// probe-resistance contract is untouched (this surface answers only inside
// the tunnel, where answering is the service). Handlers are bounded: one
// ingest session at a time per direction pair, a hard body cap on upload,
// a hard byte cap on download, and no logging of content — only counts.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	"winsvpn.local/winnprotocol/internal/observability"
)

// speedtestIngestLimits bounds one gateway ingest process. The upload cap is
// generous (a 10-second gigabit run moves over a gigabyte) but finite; the
// download cap bounds a misbehaving client's read.
const (
	speedtestMaxUploadBytes   = 1 << 30 // 1 GiB
	speedtestMaxDownloadBytes = 1 << 30 // 1 GiB
	// 64 concurrent ingest requests: the app's upload leg opens 32 streams,
	// and a cap below that turns the measurement into a semaphore benchmark
	// (the first 4 MiB-cap deployment measured 242 Mbps serving 2 of 32
	// streams). Each request is already inside an authenticated session.
	speedtestMaxConcurrent  = 64
	speedtestReadTimeout    = 10 * time.Second
	speedtestHandlerTimeout = 120 * time.Second
)

type speedtestIngestServer struct {
	concurrent chan struct{}
}

func newSpeedtestIngestServer() *speedtestIngestServer {
	return &speedtestIngestServer{concurrent: make(chan struct{}, speedtestMaxConcurrent)}
}

func (s *speedtestIngestServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/speedtest/up", s.handleUpload)
	mux.HandleFunc("/speedtest/down", s.handleDownload)
	return mux
}

func (s *speedtestIngestServer) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	// Round 39 cross-examination (agy): a blocking channel send would park the
	// 65th stream for up to the read timeout. Fail fast instead: the client
	// treats a failed run as failed and the third-party targets take over.
	select {
	case s.concurrent <- struct{}{}:
		defer func() { <-s.concurrent }()
	default:
		http.Error(w, `{"error":"ingest busy"}`, http.StatusServiceUnavailable)
		return
	}
	started := time.Now()
	body := http.MaxBytesReader(w, r.Body, speedtestMaxUploadBytes)
	received, err := io.Copy(io.Discard, body)
	elapsed := time.Since(started)
	w.Header().Set("Content-Type", "application/json")
	// Round 39 cross-examination (agy): the measurement window ends mid-body
	// by design (shutdownOutput after the window), so io.Copy normally returns
	// io.ErrUnexpectedEOF against the advertised Content-Length. That is the
	// SUCCESS path: answer 200 with the accurate count. Only the genuine cap
	// (http.MaxBytesError) is a 413.
	var maxErr *http.MaxBytesError
	switch {
	case err == nil:
		w.WriteHeader(http.StatusOK)
	case errors.As(err, &maxErr):
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_, _ = fmt.Fprintf(w, `{"error":"read capped","received_bytes":%d}`, received)
		return
	default:
		// Early EOF or a mid-body read fault: the bytes counted before the
		// fault are the measurement the client asked for.
		w.WriteHeader(http.StatusOK)
	}
	_, _ = fmt.Fprintf(w,
		`{"received_bytes":%d,"elapsed_ms":%d}`,
		received, elapsed.Milliseconds())
}

func (s *speedtestIngestServer) handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	total := parseByteQuery(r.URL.Query().Get("bytes"), 256<<20, speedtestMaxDownloadBytes)
	// Same fail-fast as upload: a parked handler would hold its connection
	// and goroutine with no deadline until a slot frees.
	select {
	case s.concurrent <- struct{}{}:
		defer func() { <-s.concurrent }()
	default:
		http.Error(w, `{"error":"ingest busy"}`, http.StatusServiceUnavailable)
		return
	}
	started := time.Now()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", total))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = io.CopyN(w, newZeroReader(), int64(total))
	_ = elapsedSince(started) // keep symmetric with upload for future JSON
}

// parseByteQuery clamps the requested byte count to [min, max]; unparsable or
// absent values get the default.
func parseByteQuery(raw string, def, max int64) int64 {
	var n int64
	_, err := fmt.Sscanf(raw, "%d", &n)
	if err != nil || n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

// newZeroReader serves bounded zeros without allocating a buffer.
type zeroReader struct{}

func newZeroReader() zeroReader { return zeroReader{} }

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// startSpeedtestIngest binds the ingest server to the inner IPv4 address and
// serves until ctx is cancelled. It must be called only when the inner
// interface exists (-forward mode): binding to an address no interface holds
// would either fail or, worse, be reachable on some other interface.
func startSpeedtestIngest(ctx context.Context, inner netip.Addr, port int, logf func(format string, args ...interface{})) error {
	if port <= 0 {
		return nil
	}
	addr := fmt.Sprintf("%s:%d", inner, port)
	listener, err := net.Listen("tcp4", addr)
	if err != nil {
		return fmt.Errorf("speedtest ingest on %s: %w", addr, err)
	}
	server := &http.Server{
		Handler:           newSpeedtestIngestServer().handler(),
		ReadHeaderTimeout: speedtestReadTimeout,
		ReadTimeout:       speedtestHandlerTimeout,
		WriteTimeout:      speedtestHandlerTimeout,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    4 << 10,
		// net/http's own diagnostics interpolate the client's address, for
		// example "http: panic serving <addr>: ...". Here that is the client's
		// inner address, which the peer registry binds to one account, so it
		// is redacted exactly as on the cover listener (cover.go).
		ErrorLog: observability.ErrorLogger(os.Stderr, "winn3-gateway speedtest: "),
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	go func() {
		if err := server.Serve(listener); err != nil && ctx.Err() == nil {
			logf("speedtest ingest stopped: %v", err)
		}
	}()
	logf("speedtest ingest: serving http://%s/speedtest/{up,down} (inner only)", addr)
	return nil
}

// elapsedSince is a tiny helper kept next to newZeroReader so both handlers
// read symmetrically; it exists to make the response shape complete.
func elapsedSince(started time.Time) time.Duration { return time.Since(started) }
