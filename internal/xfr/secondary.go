package xfr

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/ostap-mykhaylyak/tarka/internal/zone"
)

// noSOARetry paces the refresh attempts of a secondary zone that has
// never been transferred (there is no SOA to take timers from yet).
const noSOARetry = time.Minute

// maxTransferRecords caps AXFR ingestion so a malicious or
// compromised primary (or a MITM on an untrusted, non-TSIG link)
// cannot exhaust memory with an unbounded stream. Generous for any
// realistic hosting zone.
const maxTransferRecords = 500_000

// secLoop is the refresh loop of one secondary zone.
type secLoop struct {
	apex string
	quit chan struct{}
	poke chan struct{} // NOTIFY / reload trigger, capacity 1

	mu        sync.Mutex
	primaries []string
}

// wake triggers an immediate refresh; a pending wake coalesces.
func (l *secLoop) wake() {
	select {
	case l.poke <- struct{}{}:
	default:
	}
}

// fromPrimary reports whether addr matches one of the configured
// primaries (host part, ports ignored).
func (l *secLoop) fromPrimary(addr netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, p := range l.primaries {
		host, _, err := net.SplitHostPort(p)
		if err != nil {
			host = p
		}
		if pa, err := netip.ParseAddr(host); err == nil && pa.Unmap() == addr {
			return true
		}
	}
	return false
}

func (l *secLoop) getPrimaries() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.primaries
}

// ensureLoop starts (or re-arms) the refresh loop for a secondary
// zone. A YAML reload rebuilds the zone without data: waking the
// loop re-installs the cached copy and re-checks the primaries.
func (mg *Manager) ensureLoop(z *zone.Zone) {
	mg.mu.Lock()
	defer mg.mu.Unlock()
	if l, ok := mg.loops[z.Name]; ok {
		l.mu.Lock()
		l.primaries = slices.Clone(z.Primaries)
		l.mu.Unlock()
		l.wake()
		return
	}
	l := &secLoop{
		apex:      z.Name,
		quit:      make(chan struct{}),
		poke:      make(chan struct{}, 1),
		primaries: slices.Clone(z.Primaries),
	}
	mg.loops[z.Name] = l
	l.wake() // first refresh runs immediately
	go mg.run(l)
}

// secState is the loop-local zone state (owned by the run goroutine).
type secState struct {
	rrs      []dns.RR // last good transferred set
	soa      *dns.SOA
	lastGood time.Time
	failing  bool
	expired  bool
}

func (mg *Manager) run(l *secLoop) {
	st := &secState{}

	// Resume from the persisted copy so a restart answers right away
	// instead of waiting for the first transfer.
	if rrs, mtime, err := mg.loadPersisted(l.apex); err == nil {
		st.rrs, st.soa, st.lastGood = rrs, findSOA(rrs), mtime
		mg.log.Info("resumed persisted zone", "zone", l.apex,
			"serial", soaSerial(st.soa), "age", time.Since(mtime).Round(time.Second).String())
		if l.apex == mg.catalogApex {
			// Re-provision the member zones before any network: their
			// own persisted copies then resume the same way.
			mg.syncCatalog(rrs)
		}
	}

	for {
		mg.syncStore(l, st)

		select {
		case <-mg.stop:
			return
		case <-l.quit:
			return
		case <-l.poke:
		case <-time.After(st.delay()):
		}
		mg.refresh(l, st)
	}
}

// delay picks the next wait from the zone's own SOA timers.
func (st *secState) delay() time.Duration {
	switch {
	case st.soa == nil:
		return noSOARetry
	case st.failing:
		return time.Duration(st.soa.Retry) * time.Second
	default:
		return time.Duration(st.soa.Refresh) * time.Second
	}
}

// expireWindow is how long the last transfer stays valid.
func (st *secState) expireWindow() time.Duration {
	if st.soa == nil {
		return 0
	}
	return time.Duration(st.soa.Expire) * time.Second
}

// syncStore reconciles the store with the loop state: it re-installs
// the cached data after a YAML reload wiped it, and drops it once the
// expire window elapses.
func (mg *Manager) syncStore(l *secLoop, st *secState) {
	if st.soa != nil && !st.expired && time.Since(st.lastGood) > st.expireWindow() {
		st.expired = true
		mg.store.ExpireSecondary(l.apex)
		mg.log.Error("zone expired, serving SERVFAIL", "zone", l.apex,
			"last_good", st.lastGood.UTC().Format(time.RFC3339))
	}
	if st.rrs == nil || st.expired {
		return
	}
	if z := mg.store.Find(l.apex); z != nil && z.Name == l.apex && !z.Loaded() {
		if err := mg.store.SetSecondaryData(l.apex, st.rrs); err != nil {
			mg.log.Error("zone data install failed", "zone", l.apex, "error", err)
		}
	}
}

// refresh performs one SOA check against the primaries and transfers
// the zone when it is missing or stale.
func (mg *Manager) refresh(l *secLoop, st *secState) {
	defer mg.syncStore(l, st)

	primaries := l.getPrimaries()
	var lastErr error
	for _, primary := range primaries {
		addr := hostPort(primary)
		serial, err := mg.querySOA(l.apex, addr)
		if err != nil {
			lastErr = err
			continue
		}
		if st.soa != nil && !st.expired && !serialNewer(serial, st.soa.Serial) {
			// Up to date: the refresh itself renews the expire window.
			st.lastGood = time.Now()
			st.failing = false
			mg.touchPersisted(l.apex, st.lastGood)
			return
		}
		rrs, err := mg.transferIn(l.apex, addr)
		if err != nil {
			lastErr = err
			continue
		}
		if err := mg.store.SetSecondaryData(l.apex, rrs); err != nil {
			lastErr = err
			continue
		}
		st.rrs, st.soa = rrs, findSOA(rrs)
		st.lastGood, st.failing, st.expired = time.Now(), false, false
		mg.persist(l.apex, rrs)
		mg.m.XfrIn()
		mg.log.Info("zone transferred", "zone", l.apex, "primary", addr,
			"serial", soaSerial(st.soa), "records", len(rrs))
		if l.apex == mg.catalogApex {
			mg.syncCatalog(rrs)
		}
		return
	}

	st.failing = true
	if lastErr == nil {
		lastErr = fmt.Errorf("no primaries configured")
	}
	mg.log.Warn("refresh failed", "zone", l.apex, "error", lastErr)
}

// querySOA asks one primary for the zone serial (UDP, TCP fallback).
func (mg *Manager) querySOA(apex, addr string) (uint32, error) {
	for _, network := range []string{"udp", "tcp"} {
		msg := new(dns.Msg)
		msg.SetQuestion(apex, dns.TypeSOA)
		mg.signTSIG(msg)
		c := &dns.Client{Net: network, Timeout: queryTimeout, TsigSecret: mg.tsig}
		in, _, err := c.Exchange(msg, addr)
		if err != nil {
			continue
		}
		if in.Truncated && network == "udp" {
			continue // retry over TCP
		}
		if in.Rcode != dns.RcodeSuccess {
			return 0, fmt.Errorf("soa query %s: %s", addr, dns.RcodeToString[in.Rcode])
		}
		if soa := findSOA(in.Answer); soa != nil {
			return soa.Serial, nil
		}
		return 0, fmt.Errorf("soa query %s: no SOA in answer", addr)
	}
	return 0, fmt.Errorf("soa query %s: unreachable", addr)
}

// transferIn pulls the full zone from one primary via AXFR.
func (mg *Manager) transferIn(apex, addr string) ([]dns.RR, error) {
	msg := new(dns.Msg)
	msg.SetAxfr(apex)
	mg.signTSIG(msg)
	tr := &dns.Transfer{DialTimeout: queryTimeout, ReadTimeout: queryTimeout, TsigSecret: mg.tsig}
	env, err := tr.In(msg, addr)
	if err != nil {
		return nil, fmt.Errorf("axfr %s: %w", addr, err)
	}
	var rrs []dns.RR
	for e := range env {
		if e.Error != nil {
			return nil, fmt.Errorf("axfr %s: %w", addr, e.Error)
		}
		rrs = append(rrs, e.RR...)
		if len(rrs) > maxTransferRecords {
			return nil, fmt.Errorf("axfr %s: too many records (> %d), aborting", addr, maxTransferRecords)
		}
	}
	if findSOA(rrs) == nil {
		return nil, fmt.Errorf("axfr %s: no SOA in transfer", addr)
	}
	return rrs, nil
}

func findSOA(rrs []dns.RR) *dns.SOA {
	for _, rr := range rrs {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa
		}
	}
	return nil
}

func soaSerial(soa *dns.SOA) uint32 {
	if soa == nil {
		return 0
	}
	return soa.Serial
}
