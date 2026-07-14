// Package acme is the built-in ACME client: tarka obtains and renews
// TLS certificates on its own, satisfying DNS-01 challenges against
// itself — it IS the authoritative server for the zones, so the
// _acme-challenge TXT records are published directly into the zone
// store (serial bump and NOTIFY included: validation also passes
// against the secondaries). No certbot, no hooks, wildcards included.
//
// Fully automatic: every hosted primary zone is a candidate for a
// <zone> + *.<zone> certificate. Before bothering the CA, the
// delegation is verified end to end (a probe TXT published in the
// zone must be visible through public resolvers): a zone that does
// not point at this server is silently skipped, so parked zones
// neither fail nor burn CA rate limits.
//
// Certificates land in a certbot-style layout
// (<cert_dir>/live/<zone>/fullchain.pem + privkey.pem) so a reverse
// proxy can point straight at it.
package acme

import (
	"context"
	"crypto/x509"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ostap-mykhaylyak/tarka/internal/config"
)

const (
	// checkInterval paces the renewal checks; retryInterval is used
	// after a cycle with failures.
	checkInterval = 12 * time.Hour
	retryInterval = time.Hour
	// startupDelay lets the zones load and the listeners bind before
	// the first check (the CA will query us during validation).
	startupDelay = 10 * time.Second
	// issueTimeout bounds one certificate issuance end to end.
	issueTimeout = 10 * time.Minute
)

// ZoneSource is the slice of the zone store the ACME flow needs.
type ZoneSource interface {
	SetDNS01(domain, token string) error
	ClearDNS01(domain, token string) error
	PrimaryZones() []string
}

// certState is the outcome of the last check of one certificate.
type certState struct {
	err     string // issuance failed (retried next cycle)
	skipped string // delegation not pointing here: no-op by design
}

// Manager runs the issuance/renewal loop.
type Manager struct {
	mgr   *config.Manager
	zones ZoneSource
	log   *slog.Logger

	// delegated verifies that a zone's delegation reaches this
	// server; overridable in tests.
	delegated func(ctx context.Context, cfg config.Acme, zoneName string) error

	mu    sync.Mutex
	state map[string]certState // by cert name
}

// NewManager wires the ACME manager; Start launches the loop.
func NewManager(mgr *config.Manager, zones ZoneSource, log *slog.Logger) *Manager {
	m := &Manager{mgr: mgr, zones: zones, log: log, state: map[string]certState{}}
	m.delegated = m.delegationCheck
	return m
}

// Start runs the renewal loop until stop is closed. The first check
// runs shortly after startup (missing certificates are issued right
// away), then every checkInterval, sooner after failures.
func (m *Manager) Start(stop <-chan struct{}) {
	go func() {
		delay := startupDelay
		for {
			select {
			case <-stop:
				return
			case <-time.After(delay):
			}
			if m.checkAll(stop) {
				delay = checkInterval
			} else {
				delay = retryInterval
			}
		}
	}()
}

// checkAll walks the hosted primary zones and ensures each
// certificate; reports whether the cycle was fully clean.
func (m *Manager) checkAll(stop <-chan struct{}) bool {
	cfg := m.mgr.Get().Acme
	if !cfg.Enabled {
		return true
	}
	clean := true
	for _, apex := range m.zones.PrimaryZones() {
		name := certName(apex)

		ctx, cancel := context.WithTimeout(context.Background(), issueTimeout)
		done := make(chan struct{})
		go func() { // a close(stop) aborts an in-flight issuance
			select {
			case <-stop:
				cancel()
			case <-done:
			}
		}()
		st := m.ensure(ctx, cfg, apex, name)
		close(done)
		cancel()

		m.mu.Lock()
		m.state[name] = st
		m.mu.Unlock()
		if st.err != "" {
			clean = false
			m.log.Error("certificate check failed", "cert", name, "error", st.err)
		}
	}
	return clean
}

// ensure issues (or renews) the certificate of one zone when needed.
// A zone whose delegation does not reach this server is skipped: no
// certificate, no error — by design.
func (m *Manager) ensure(ctx context.Context, cfg config.Acme, apex, name string) certState {
	domains := zoneDomains(apex)
	cur, err := readCert(liveDir(cfg.CertDir, name))
	if err == nil && !needsRenew(cur, domains, cfg.RenewBefore.Std()) {
		return certState{}
	}
	reason := "missing"
	if err == nil {
		reason = renewReason(cur, domains, cfg.RenewBefore.Std())
	}

	if err := m.delegated(ctx, cfg, apex); err != nil {
		m.log.Info("zone not delegated here, certificate skipped", "zone", apex, "detail", err.Error())
		return certState{skipped: err.Error()}
	}

	m.log.Info("obtaining certificate", "cert", name, "domains", domains, "reason", reason)
	if err := m.issue(ctx, cfg, domains, name); err != nil {
		return certState{err: err.Error()}
	}
	return certState{}
}

// zoneDomains derives the certificate SANs of a zone: the apex and
// everything under it.
func zoneDomains(apex string) []string {
	base := strings.TrimSuffix(apex, ".")
	return []string{base, "*." + base}
}

// certName picks the live/ directory name from the zone apex.
func certName(apex string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '_'
		}
	}, strings.TrimSuffix(apex, "."))
}

// needsRenew reports whether the certificate must be reissued: too
// close to expiry, or the domain set changed.
func needsRenew(cert *x509.Certificate, domains []string, renewBefore time.Duration) bool {
	if time.Until(cert.NotAfter) < renewBefore {
		return true
	}
	return !sameDomains(cert.DNSNames, domains)
}

func renewReason(cert *x509.Certificate, domains []string, renewBefore time.Duration) string {
	if time.Until(cert.NotAfter) < renewBefore {
		return "expiring " + cert.NotAfter.UTC().Format(time.RFC3339)
	}
	return "domains changed"
}

func sameDomains(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as, bs := make([]string, len(a)), make([]string, len(b))
	for i, s := range a {
		as[i] = normalizeDomain(s)
	}
	for i, s := range b {
		bs[i] = normalizeDomain(s)
	}
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

// CertInfo is the per-certificate status snapshot, served by --status.
type CertInfo struct {
	Name     string    `json:"name"`
	Domains  []string  `json:"domains"`
	Issued   bool      `json:"issued"`
	NotAfter time.Time `json:"not_after,omitempty"`
	Skipped  string    `json:"skipped,omitempty"` // zone not delegated here
	Error    string    `json:"error,omitempty"`
}

// Snapshot reads the on-disk state of every candidate certificate.
// Safe on a nil receiver (acme disabled at startup).
func (m *Manager) Snapshot() []CertInfo {
	if m == nil {
		return nil
	}
	cfg := m.mgr.Get().Acme
	zones := m.zones.PrimaryZones()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]CertInfo, 0, len(zones))
	for _, apex := range zones {
		name := certName(apex)
		st := m.state[name]
		info := CertInfo{Name: name, Domains: zoneDomains(apex), Skipped: st.skipped, Error: st.err}
		if cert, err := readCert(liveDir(cfg.CertDir, name)); err == nil {
			info.Issued = true
			info.NotAfter = cert.NotAfter
		}
		out = append(out, info)
	}
	return out
}
