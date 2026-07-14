// Package metrics keeps live in-memory counters, updated on the hot
// path at near-zero cost with sync/atomic. Snapshot() is the single
// source of truth consumed by the status socket.
package metrics

import (
	"sort"
	"sync/atomic"
	"time"
)

// Standard DNS response codes tracked individually; everything else
// falls into "other". Values match the wire RCODEs (RFC 1035).
const (
	RcodeNoError  = 0
	RcodeServFail = 2
	RcodeNXDomain = 3
	RcodeRefused  = 5
)

// latencyBoundsMs are the upper edges (milliseconds) of the fixed
// query-latency histogram buckets. A query is counted in the first
// bucket whose edge is >= its latency; anything slower lands in the
// overflow bucket. Authoritative answers come from RAM, so the scale
// is tighter than a proxy's.
var latencyBoundsMs = []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000}

// histogram is a lock-free fixed-bucket latency histogram.
type histogram struct {
	buckets []atomic.Int64 // len(latencyBoundsMs)+1 (last = overflow)
}

func newHistogram() *histogram {
	return &histogram{buckets: make([]atomic.Int64, len(latencyBoundsMs)+1)}
}

func (h *histogram) observe(d time.Duration) {
	ms := float64(d) / float64(time.Millisecond)
	h.buckets[sort.SearchFloat64s(latencyBoundsMs, ms)].Add(1)
}

// percentiles returns, for each p in [0,1], the upper edge (ms) of the
// bucket where the cumulative count crosses p. Zero when no data.
func (h *histogram) percentiles(ps ...float64) []float64 {
	counts := make([]int64, len(h.buckets))
	var total int64
	for i := range h.buckets {
		counts[i] = h.buckets[i].Load()
		total += counts[i]
	}
	out := make([]float64, len(ps))
	if total == 0 {
		return out
	}
	for j, p := range ps {
		target := int64(float64(total) * p)
		if target < 1 {
			target = 1
		}
		var cum int64
		for i, c := range counts {
			cum += c
			if cum >= target {
				if i < len(latencyBoundsMs) {
					out[j] = latencyBoundsMs[i]
				} else {
					out[j] = latencyBoundsMs[len(latencyBoundsMs)-1] // overflow: report the max edge
				}
				break
			}
		}
	}
	return out
}

// Metrics is the daemon-wide collector.
type Metrics struct {
	start time.Time
	lat   *histogram

	queriesTotal atomic.Int64
	inFlight     atomic.Int64
	bytesOut     atomic.Int64

	rcodeNoError  atomic.Int64
	rcodeNXDomain atomic.Int64
	rcodeRefused  atomic.Int64
	rcodeServFail atomic.Int64
	rcodeOther    atomic.Int64

	xfrOut     atomic.Int64
	xfrIn      atomic.Int64
	notifySent atomic.Int64
	notifyRecv atomic.Int64

	rrlDropped   atomic.Int64
	rrlTruncated atomic.Int64
}

// New returns a Metrics anchored at the current time.
func New() *Metrics { return &Metrics{start: time.Now(), lat: newHistogram()} }

// Transfer counters, updated by the xfr subsystem.
func (m *Metrics) XfrOut()         { m.xfrOut.Add(1) }
func (m *Metrics) XfrIn()          { m.xfrIn.Add(1) }
func (m *Metrics) NotifySent()     { m.notifySent.Add(1) }
func (m *Metrics) NotifyReceived() { m.notifyRecv.Add(1) }

// RRL counters, updated on the UDP hot path.
func (m *Metrics) RRLDropped()   { m.rrlDropped.Add(1) }
func (m *Metrics) RRLTruncated() { m.rrlTruncated.Add(1) }

// QueryStart records an incoming query and returns the completion
// callback, to be deferred by the handler. The callback measures the
// query latency itself, so callers need not time anything.
func (m *Metrics) QueryStart() func(bytes int64, rcode int) {
	m.queriesTotal.Add(1)
	m.inFlight.Add(1)
	t0 := time.Now()
	return func(bytes int64, rcode int) {
		m.inFlight.Add(-1)
		m.bytesOut.Add(bytes)
		switch rcode {
		case RcodeNoError:
			m.rcodeNoError.Add(1)
		case RcodeNXDomain:
			m.rcodeNXDomain.Add(1)
		case RcodeRefused:
			m.rcodeRefused.Add(1)
		case RcodeServFail:
			m.rcodeServFail.Add(1)
		default:
			m.rcodeOther.Add(1)
		}
		m.lat.observe(time.Since(t0))
	}
}

// Snapshot is a coherent, JSON-serializable view of the live state.
// Field names are stable across versions: dashboards build on them.
type Snapshot struct {
	UptimeSeconds   float64   `json:"uptime_seconds"`
	QueriesTotal    int64     `json:"queries_total"`
	QueriesInFlight int64     `json:"queries_in_flight"`
	BytesOutTotal   int64     `json:"bytes_out_total"`
	RcodeNoError    int64     `json:"rcode_noerror"`
	RcodeNXDomain   int64     `json:"rcode_nxdomain"`
	RcodeRefused    int64     `json:"rcode_refused"`
	RcodeServFail   int64     `json:"rcode_servfail"`
	RcodeOther      int64     `json:"rcode_other"`
	XfrOutTotal     int64     `json:"xfr_out_total"`
	XfrInTotal      int64     `json:"xfr_in_total"`
	NotifySent      int64     `json:"notify_sent"`
	NotifyReceived  int64     `json:"notify_received"`
	RRLDropped      int64     `json:"rrl_dropped"`
	RRLTruncated    int64     `json:"rrl_truncated"`
	P50LatencyMs    float64   `json:"p50_latency_ms"`
	P95LatencyMs    float64   `json:"p95_latency_ms"`
	P99LatencyMs    float64   `json:"p99_latency_ms"`
	Timestamp       time.Time `json:"timestamp"`
}

// Snapshot reads all counters atomically.
func (m *Metrics) Snapshot() Snapshot {
	lp := m.lat.percentiles(0.50, 0.95, 0.99)
	return Snapshot{
		UptimeSeconds:   time.Since(m.start).Seconds(),
		QueriesTotal:    m.queriesTotal.Load(),
		QueriesInFlight: m.inFlight.Load(),
		BytesOutTotal:   m.bytesOut.Load(),
		RcodeNoError:    m.rcodeNoError.Load(),
		RcodeNXDomain:   m.rcodeNXDomain.Load(),
		RcodeRefused:    m.rcodeRefused.Load(),
		RcodeServFail:   m.rcodeServFail.Load(),
		RcodeOther:      m.rcodeOther.Load(),
		XfrOutTotal:     m.xfrOut.Load(),
		XfrInTotal:      m.xfrIn.Load(),
		NotifySent:      m.notifySent.Load(),
		NotifyReceived:  m.notifyRecv.Load(),
		RRLDropped:      m.rrlDropped.Load(),
		RRLTruncated:    m.rrlTruncated.Load(),
		P50LatencyMs:    lp[0],
		P95LatencyMs:    lp[1],
		P99LatencyMs:    lp[2],
		Timestamp:       time.Now().UTC(),
	}
}
