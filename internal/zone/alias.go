package zone

import (
	"sort"

	"github.com/miekg/dns"
)

// AliasZones returns, for every served primary zone with ALIAS
// records, the owner->target map. The alias manager resolves the
// targets and feeds the results back through SetAliasRecords.
func (s *Store) AliasZones() map[string]map[string]string {
	zones := *s.zones.Load()
	out := map[string]map[string]string{}
	for apex, z := range zones {
		if z.Type != "primary" || z.synthetic {
			continue
		}
		if base := s.baseZone(apex); base != nil {
			if t := base.AliasTargets(); len(t) > 0 {
				out[apex] = t
			}
		}
	}
	return out
}

// baseZone returns the file-backed (pre-overlay) zone for an apex,
// which carries the ALIAS metadata (the served zone is a copy).
func (s *Store) baseZone(apex string) *Zone {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, entry := range s.files {
		if entry.zone != nil && entry.zone.Name == apex {
			return entry.zone
		}
	}
	return nil
}

// SetAliasRecords replaces the materialized ALIAS A/AAAA overlay of a
// zone. When the set actually changes it bumps the serial, rebuilds
// and fires OnLoad (so the secondaries re-transfer the new IPs).
// Returns whether anything changed.
func (s *Store) SetAliasRecords(apex string, rrs []dns.RR) bool {
	sortRRs(rrs)

	s.mu.Lock()
	if sameRRs(s.alias[apex], rrs) {
		s.mu.Unlock()
		return false
	}
	if len(rrs) == 0 {
		delete(s.alias, apex)
	} else {
		s.alias[apex] = rrs
	}
	z := s.dns01ApplyLocked(apex) // reuse the serial-bump + rebuild path
	s.mu.Unlock()

	s.log.Info("alias records updated", "zone", apex, "records", len(rrs), "serial", z.Serial)
	if s.OnLoad != nil && z != nil {
		s.OnLoad(z)
	}
	return true
}

func sortRRs(rrs []dns.RR) {
	sort.Slice(rrs, func(i, j int) bool { return rrs[i].String() < rrs[j].String() })
}

func sameRRs(a, b []dns.RR) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].String() != b[i].String() {
			return false
		}
	}
	return true
}
