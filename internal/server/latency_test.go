package server

import (
	"io"
	"log/slog"
	"net"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestLatencyDistribution measures the in-process per-query latency
// distribution (not the mean), so tail spikes — mostly GC pauses —
// are visible. Opt-in (it is heavy, and needs a high-resolution
// monotonic clock — meaningful on Linux, not on a Windows dev box):
//
//	TARKA_LATENCY=1 go test ./internal/server -run TestLatencyDistribution -v
func TestLatencyDistribution(t *testing.T) {
	if os.Getenv("TARKA_LATENCY") == "" {
		t.Skip("set TARKA_LATENCY=1 to run the latency profile")
	}
	const n = 2_000_000

	discard := slog.New(slog.NewJSONHandler(io.Discard, nil))
	// query_log off: the pure processing path.
	report(t, "query_log=off", n,
		benchServerCfg(t, discard, "server:\n  listen: [\"127.0.0.1:0\"]\n  query_log: false\n"))
	// query_log on (buffered): production default.
	report(t, "query_log=on(buffered)", n,
		benchServerCfg(t, discard, "server:\n  listen: [\"127.0.0.1:0\"]\n"))
}

func report(t *testing.T, name string, n int, s *Server) {
	t.Helper()
	w := &benchWriter{udp: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 200), Port: 5353}}
	r := benchQuery("www.example.com.", dns.TypeA)

	// Warm up (let the GC settle, fault in pages).
	for i := 0; i < 100_000; i++ {
		s.ServeDNS(w, r)
	}

	samples := make([]int64, n)
	for i := 0; i < n; i++ {
		t0 := time.Now()
		s.ServeDNS(w, r)
		samples[i] = time.Since(t0).Nanoseconds()
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })

	pct := func(p float64) float64 {
		idx := int(p * float64(n))
		if idx >= n {
			idx = n - 1
		}
		return float64(samples[idx]) / 1000.0 // µs
	}
	t.Logf("%-24s p50=%.2fµs p90=%.2fµs p99=%.2fµs p99.9=%.2fµs p99.99=%.2fµs max=%.2fµs",
		name, pct(0.50), pct(0.90), pct(0.99), pct(0.999), pct(0.9999), float64(samples[n-1])/1000.0)
}
