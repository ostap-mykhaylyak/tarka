// Package rrl implements Response Rate Limiting for the UDP path, the
// standard defense against using an authoritative server as a DNS
// amplification reflector. Identical responses to one client subnet
// are capped with a token bucket; over the cap a response is either
// dropped or, every Nth time (slip), sent truncated so a legitimate
// client behind the subnet retries over TCP.
//
// TCP is never rate-limited: it is not spoofable, so it is not a
// reflection vector.
package rrl

import (
	"net/netip"
	"sync"
	"time"
)

// Action is the limiter's verdict for one response.
type Action int

const (
	Pass     Action = iota // send the response normally
	Drop                   // send nothing (the query was likely spoofed)
	Truncate               // send an empty TC=1 response (slip): retry over TCP
)

// bucket is the per (subnet, category) token bucket.
type bucket struct {
	tokens   float64
	last     time.Time
	slipSeen int
}

// maxBuckets caps the tracking table. An attacker flooding random
// query names (each a distinct category) would otherwise grow the map
// without bound, turning the limiter itself into a memory-exhaustion
// vector. At the cap we force a sweep and, if still full, fail open
// (let the response through) so memory stays bounded — the worst case
// degrades to "no rate limiting", never to an OOM.
const maxBuckets = 500_000

// Limiter is a sharded token-bucket rate limiter.
type Limiter struct {
	rps      float64
	slip     int
	v4Prefix int
	v6Prefix int
	idle     time.Duration // evict buckets untouched for this long

	mu      sync.Mutex
	buckets map[string]*bucket
	now     func() time.Time // test override
	lastGC  time.Time
}

// New builds a limiter. window sizes the idle-eviction horizon.
func New(rps int, window time.Duration, slip, v4Prefix, v6Prefix int) *Limiter {
	return &Limiter{
		rps:      float64(rps),
		slip:     slip,
		v4Prefix: v4Prefix,
		v6Prefix: v6Prefix,
		idle:     10 * window,
		buckets:  map[string]*bucket{},
		now:      time.Now,
		lastGC:   time.Now(),
	}
}

// Check accounts one response for a client and category and returns
// the action to take. category groups equivalent responses (e.g.
// qname+qtype+rcode) so a flood of one answer is limited on its own.
func (l *Limiter) Check(client netip.Addr, category string) Action {
	key := l.subnet(client) + "|" + category

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.gcLocked(now)

	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= maxBuckets {
			// Table full: force an immediate sweep, then fail open if
			// it is still saturated. Bounds memory under a flood.
			l.lastGC = time.Time{}
			l.gcLocked(now)
			if len(l.buckets) >= maxBuckets {
				return Pass
			}
		}
		// A fresh bucket starts full (one second of allowance), so
		// isolated queries always pass.
		b = &bucket{tokens: l.rps, last: now}
		l.buckets[key] = b
	} else {
		b.tokens += l.rps * now.Sub(b.last).Seconds()
		if b.tokens > l.rps {
			b.tokens = l.rps
		}
		b.last = now
	}

	if b.tokens >= 1 {
		b.tokens--
		b.slipSeen = 0
		return Pass
	}

	// Over the cap. slip==0 drops everything; slip==1 truncates
	// everything; otherwise every Nth throttled response truncates.
	b.slipSeen++
	if l.slip > 0 && b.slipSeen%l.slip == 0 {
		return Truncate
	}
	return Drop
}

// subnet reduces a client address to its rate-limiting subnet.
func (l *Limiter) subnet(a netip.Addr) string {
	a = a.Unmap()
	bits := l.v4Prefix
	if a.Is6() {
		bits = l.v6Prefix
	}
	if p, err := a.Prefix(bits); err == nil {
		return p.String()
	}
	return a.String()
}

// gcLocked evicts idle buckets, at most once per idle horizon.
func (l *Limiter) gcLocked(now time.Time) {
	if now.Sub(l.lastGC) < l.idle {
		return
	}
	l.lastGC = now
	for k, b := range l.buckets {
		if now.Sub(b.last) > l.idle {
			delete(l.buckets, k)
		}
	}
}
