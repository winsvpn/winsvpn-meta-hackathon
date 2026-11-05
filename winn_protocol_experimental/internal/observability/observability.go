package observability

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Registry struct {
	mu           sync.Mutex
	counters     map[string]uint64
	observations map[string]observation
	started      time.Time
	ready        atomic.Bool
}

type observation struct {
	count uint64
	sum   float64
	min   float64
	max   float64
}

func New() *Registry {
	return &Registry{
		counters:     make(map[string]uint64),
		observations: make(map[string]observation),
		started:      time.Now(),
	}
}

func (r *Registry) ObserveDuration(name string, duration time.Duration) {
	name = sanitize(name)
	value := duration.Seconds()
	if value < 0 {
		return
	}
	r.mu.Lock()
	current := r.observations[name]
	if current.count == 0 || value < current.min {
		current.min = value
	}
	if current.count == 0 || value > current.max {
		current.max = value
	}
	current.count++
	current.sum += value
	r.observations[name] = current
	r.mu.Unlock()
}

func (r *Registry) Inc(name string) {
	name = sanitize(name)
	r.mu.Lock()
	r.counters[name]++
	r.mu.Unlock()
}

func (r *Registry) SetReady(ready bool) {
	r.ready.Store(ready)
}

func (r *Registry) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !r.ready.Load() {
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte("not ready\n"))
			return
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ready\n"))
	})
	mux.HandleFunc("/metrics", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		r.mu.Lock()
		names := make([]string, 0, len(r.counters))
		for name := range r.counters {
			names = append(names, name)
		}
		sort.Strings(names)
		values := make(map[string]uint64, len(names))
		for _, name := range names {
			values[name] = r.counters[name]
		}
		observationNames := make([]string, 0, len(r.observations))
		observationValues := make(map[string]observation, len(r.observations))
		for name, value := range r.observations {
			observationNames = append(observationNames, name)
			observationValues[name] = value
		}
		sort.Strings(observationNames)
		r.mu.Unlock()
		for _, name := range names {
			_, _ = fmt.Fprintf(writer, "winn_protocol_events_total{event=%q} %d\n", name, values[name])
		}
		for _, name := range observationNames {
			value := observationValues[name]
			_, _ = fmt.Fprintf(writer, "winn_protocol_duration_seconds_count{operation=%q} %d\n", name, value.count)
			_, _ = fmt.Fprintf(writer, "winn_protocol_duration_seconds_sum{operation=%q} %.9f\n", name, value.sum)
			_, _ = fmt.Fprintf(writer, "winn_protocol_duration_seconds_min{operation=%q} %.9f\n", name, value.min)
			_, _ = fmt.Fprintf(writer, "winn_protocol_duration_seconds_max{operation=%q} %.9f\n", name, value.max)
		}
		_, _ = fmt.Fprintf(writer, "winn_protocol_uptime_seconds %.0f\n", time.Since(r.started).Seconds())
		if r.ready.Load() {
			_, _ = writer.Write([]byte("winn_protocol_ready 1\n"))
		} else {
			_, _ = writer.Write([]byte("winn_protocol_ready 0\n"))
		}
	})
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(writer, request)
	})
}

func sanitize(value string) string {
	value = strings.ToLower(value)
	var builder strings.Builder
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			character == '_' {
			builder.WriteRune(character)
		} else {
			builder.WriteByte('_')
		}
	}
	if builder.Len() == 0 {
		return "unknown"
	}
	return builder.String()
}
