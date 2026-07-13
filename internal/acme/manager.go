// Package acme is the built-in ACME client: tarka obtains and renews
// TLS certificates on its own, satisfying DNS-01 challenges against
// itself — it IS the authoritative server for the zones, so the
// _acme-challenge TXT records are published directly into the zone
// store (serial bump and NOTIFY included: validation also passes
// against the secondaries). No certbot, no hooks, wildcards included.
//
// Certificates land in a certbot-style layout
// (<cert_dir>/live/<name>/fullchain.pem + privkey.pem) so a reverse
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

// DNS01Publisher is the slice of the zone store the ACME flow needs.
type DNS01Publisher interface {
	SetDNS01(domain, token string) error
	ClearDNS01(domain, token string) error
}

// Manager runs the issuance/renewal loop.
type Manager struct {
	mgr   *config.Manager
	zones DNS01Publisher
	log   *slog.Logger

	mu    sync.Mutex
	state map[string]string // last error per cert name ("" = ok)
}

// NewManager wires the ACME manager; Start launches the loop.
func NewManager(mgr *config.Manager, zones DNS01Publisher, log *slog.Logger) *Manager {
	return &Manager{mgr: mgr, zones: zones, log: log, state: map[string]string{}}
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

// checkAll ensures every configured certificate; reports whether the
// cycle was fully clean.
func (m *Manager) checkAll(stop <-chan struct{}) bool {
	cfg := m.mgr.Get().Acme
	if !cfg.Enabled {
		return true
	}
	clean := true
	for _, c := range cfg.Certificates {
		if len(c.Domains) == 0 {
			continue
		}
		name := certName(c)

		ctx, cancel := context.WithTimeout(context.Background(), issueTimeout)
		done := make(chan struct{})
		go func() { // a close(stop) aborts an in-flight issuance
			select {
			case <-stop:
				cancel()
			case <-done:
			}
		}()
		err := m.ensure(ctx, cfg, c, name)
		close(done)
		cancel()

		m.mu.Lock()
		if err != nil {
			m.state[name] = err.Error()
			clean = false
		} else {
			m.state[name] = ""
		}
		m.mu.Unlock()
		if err != nil {
			m.log.Error("certificate check failed", "cert", name, "error", err)
		}
	}
	return clean
}

// ensure issues (or renews) one certificate when needed.
func (m *Manager) ensure(ctx context.Context, cfg config.Acme, c config.AcmeCert, name string) error {
	cur, err := readCert(liveDir(cfg.CertDir, name))
	if err == nil && !needsRenew(cur, c.Domains, cfg.RenewBefore.Std()) {
		return nil
	}
	reason := "missing"
	if err == nil {
		reason = renewReason(cur, c.Domains, cfg.RenewBefore.Std())
	}
	m.log.Info("obtaining certificate", "cert", name, "domains", c.Domains, "reason", reason)
	return m.issue(ctx, cfg, c, name)
}

// needsRenew reports whether the certificate must be reissued: too
// close to expiry, or the configured domain set changed.
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

// certName picks the live/ directory name: the explicit name, or the
// first domain without any wildcard prefix.
func certName(c config.AcmeCert) string {
	name := c.Name
	if name == "" {
		name = strings.TrimPrefix(normalizeDomain(c.Domains[0]), "*.")
	}
	// The name becomes a directory: keep it to a safe charset.
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '_'
		}
	}, name)
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
	Error    string    `json:"error,omitempty"`
}

// Snapshot reads the on-disk state of every configured certificate.
// Safe on a nil receiver (acme disabled at startup).
func (m *Manager) Snapshot() []CertInfo {
	if m == nil {
		return nil
	}
	cfg := m.mgr.Get().Acme
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]CertInfo, 0, len(cfg.Certificates))
	for _, c := range cfg.Certificates {
		name := certName(c)
		info := CertInfo{Name: name, Domains: c.Domains, Error: m.state[name]}
		if cert, err := readCert(liveDir(cfg.CertDir, name)); err == nil {
			info.Issued = true
			info.NotAfter = cert.NotAfter
		}
		out = append(out, info)
	}
	return out
}
