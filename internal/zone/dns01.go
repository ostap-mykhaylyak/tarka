package zone

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNS-01 overlay: ephemeral _acme-challenge TXT records published by
// the ACME client hook (tarka --dns01-set / --dns01-clear via the
// control socket). Every change bumps the zone serial so NOTIFY goes
// out and secondaries re-transfer with the token included.
const (
	// dns01TTL is the DNS TTL of the challenge TXT records.
	dns01TTL = 60
	// dns01Lifetime is how long an unpublished token survives before
	// the sweeper drops it (the cleanup hook normally clears it much
	// earlier).
	dns01Lifetime = 30 * time.Minute
	// acmePrefix is prepended to a bare domain name.
	acmePrefix = "_acme-challenge."
)

// dns01Entry is one published challenge token.
type dns01Entry struct {
	name    string // TXT owner, lowercase FQDN
	token   string
	expires time.Time
}

// acmeName normalizes the CLI argument: certbot hands the bare domain
// being validated, so the prefix is added unless already present.
func acmeName(domain string) string {
	name := fqdn(domain)
	if !strings.HasPrefix(name, acmePrefix) {
		name = acmePrefix + name
	}
	return name
}

// SetDNS01 publishes an ACME DNS-01 TXT token for domain. Multiple
// tokens may coexist at the same name (wildcard orders validate the
// base and the wildcard together).
func (s *Store) SetDNS01(domain, token string) error {
	if domain == "" || token == "" {
		return fmt.Errorf("domain and token are required")
	}
	name := acmeName(domain)

	s.mu.Lock()
	apex, err := s.dns01ZoneLocked(name)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	entries := s.dns01[apex]
	for _, e := range entries {
		if e.name == name && e.token == token {
			s.mu.Unlock()
			return nil // already published, nothing to bump
		}
	}
	s.dns01[apex] = append(entries, dns01Entry{
		name:    name,
		token:   token,
		expires: s.now().Add(dns01Lifetime),
	})
	z := s.dns01ApplyLocked(apex)
	s.mu.Unlock()

	s.log.Info("dns01 token published", "zone", apex, "name", name, "serial", z.Serial)
	if s.OnLoad != nil {
		s.OnLoad(z) // NOTIFY the secondaries: the token must reach them too
	}
	return nil
}

// ClearDNS01 removes the token published for domain; an empty token
// removes every token at that name.
func (s *Store) ClearDNS01(domain, token string) error {
	if domain == "" {
		return fmt.Errorf("domain is required")
	}
	name := acmeName(domain)

	s.mu.Lock()
	apex, err := s.dns01ZoneLocked(name)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	kept := s.dns01[apex][:0]
	for _, e := range s.dns01[apex] {
		if e.name == name && (token == "" || e.token == token) {
			continue
		}
		kept = append(kept, e)
	}
	if len(kept) == len(s.dns01[apex]) {
		s.mu.Unlock()
		return fmt.Errorf("no such token at %s", name)
	}
	s.dns01[apex] = kept
	if len(kept) == 0 {
		delete(s.dns01, apex)
	}
	z := s.dns01ApplyLocked(apex)
	s.mu.Unlock()

	s.log.Info("dns01 token cleared", "zone", apex, "name", name, "serial", z.Serial)
	if s.OnLoad != nil {
		s.OnLoad(z)
	}
	return nil
}

// DNS01Active returns the number of currently published tokens.
func (s *Store) DNS01Active() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, entries := range s.dns01 {
		n += len(entries)
	}
	return n
}

// StartDNS01Sweeper drops expired tokens once a minute until stop is
// closed (a crashed ACME hook must not leave tokens around forever).
func (s *Store) StartDNS01Sweeper(stop <-chan struct{}) {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				s.sweepDNS01()
			}
		}
	}()
}

func (s *Store) sweepDNS01() {
	s.mu.Lock()
	now := s.now()
	var changed []*Zone
	for apex, entries := range s.dns01 {
		kept := entries[:0]
		for _, e := range entries {
			if now.Before(e.expires) {
				kept = append(kept, e)
			}
		}
		if len(kept) == len(entries) {
			continue
		}
		s.dns01[apex] = kept
		if len(kept) == 0 {
			delete(s.dns01, apex)
		}
		changed = append(changed, s.dns01ApplyLocked(apex))
	}
	s.mu.Unlock()

	for _, z := range changed {
		s.log.Info("dns01 expired tokens swept", "zone", z.Name, "serial", z.Serial)
		if s.OnLoad != nil {
			s.OnLoad(z)
		}
	}
}

// dns01ZoneLocked resolves the primary zone hosting name. Callers
// hold s.mu.
func (s *Store) dns01ZoneLocked(name string) (string, error) {
	for _, entry := range s.files {
		z := entry.zone
		if z == nil || !dns.IsSubDomain(z.Name, name) {
			continue
		}
		if z.Type != "primary" {
			return "", fmt.Errorf("zone %s is a secondary here: publish the token on its primary", z.Name)
		}
		return z.Name, nil
	}
	return "", fmt.Errorf("no hosted zone for %s", name)
}

// dns01ApplyLocked bumps the zone serial, rebuilds the lookup table
// and returns the resulting zone. Callers hold s.mu.
func (s *Store) dns01ApplyLocked(apex string) *Zone {
	// The file hash is untouched: the bump only raises the serial, so
	// an unchanged file keeps it and a future edit bumps past it.
	entry := s.serials[apex]
	serial := uint32(s.now().Unix())
	if serial <= entry.Serial {
		serial = entry.Serial + 1
	}
	entry.Serial = serial
	s.serials[apex] = entry
	s.saveSerialsLocked()
	s.rebuildLocked()
	return (*s.zones.Load())[apex]
}

// overlayRRsLocked renders the active overlay of a zone as TXT
// records. Callers hold s.mu.
func (s *Store) overlayRRsLocked(z *Zone) []dns.RR {
	if z.Type != "primary" || !z.loaded {
		return nil
	}
	entries := s.dns01[z.Name]
	now := s.now()
	var out []dns.RR
	for _, e := range entries {
		if now.After(e.expires) {
			continue
		}
		out = append(out, &dns.TXT{
			Hdr: dns.RR_Header{Name: e.name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: dns01TTL},
			Txt: []string{e.token},
		})
	}
	return out
}
