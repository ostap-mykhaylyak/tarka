package metrics

import (
	"testing"
	"time"
)

func TestQueryLifecycle(t *testing.T) {
	m := New()

	done := m.QueryStart()
	snap := m.Snapshot()
	if snap.QueriesTotal != 1 || snap.QueriesInFlight != 1 {
		t.Fatalf("in-flight accounting broken: %+v", snap)
	}

	done(512, RcodeNoError)
	done2 := m.QueryStart()
	done2(0, RcodeNXDomain)
	done3 := m.QueryStart()
	done3(0, RcodeRefused)
	done4 := m.QueryStart()
	done4(0, 4) // NOTIMP -> other

	snap = m.Snapshot()
	if snap.QueriesTotal != 4 || snap.QueriesInFlight != 0 {
		t.Fatalf("completion accounting broken: %+v", snap)
	}
	if snap.BytesOutTotal != 512 {
		t.Fatalf("bytes accounting broken: %+v", snap)
	}
	if snap.RcodeNoError != 1 || snap.RcodeNXDomain != 1 || snap.RcodeRefused != 1 || snap.RcodeOther != 1 {
		t.Fatalf("rcode accounting broken: %+v", snap)
	}
}

func TestLatencyPercentiles(t *testing.T) {
	h := newHistogram()

	// Empty histogram: percentiles are zero.
	if p := h.percentiles(0.5, 0.95); p[0] != 0 || p[1] != 0 {
		t.Fatalf("empty histogram must be zero, got %v", p)
	}

	// 100 queries spread 0..99 ms. p50 (~49.5ms) lands in the 50ms
	// bucket edge; p95 (~94ms) and p99 (~98ms) in the 100ms edge.
	for i := 0; i < 100; i++ {
		h.observe(time.Duration(i) * time.Millisecond)
	}
	p := h.percentiles(0.50, 0.95, 0.99)
	if p[0] != 50 {
		t.Fatalf("p50 = %v, want 50", p[0])
	}
	if p[1] != 100 {
		t.Fatalf("p95 = %v, want 100", p[1])
	}
	if p[2] != 100 {
		t.Fatalf("p99 = %v, want 100", p[2])
	}
}

func TestLatencyOverflow(t *testing.T) {
	h := newHistogram()
	for i := 0; i < 10; i++ {
		h.observe(30 * time.Second) // beyond the largest bucket edge
	}
	if p := h.percentiles(0.95); p[0] != 1000 {
		t.Fatalf("overflow p95 = %v, want 1000 (max edge)", p[0])
	}
}

func TestSnapshotHasLatency(t *testing.T) {
	m := New()
	done := m.QueryStart()
	done(0, RcodeNoError) // records some sub-ms latency
	snap := m.Snapshot()
	if snap.P50LatencyMs < 0 || snap.P95LatencyMs < 0 {
		t.Fatalf("latency fields must be populated: %+v", snap)
	}
}
