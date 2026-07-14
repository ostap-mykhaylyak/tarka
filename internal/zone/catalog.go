package zone

import (
	"crypto/sha1"
	"encoding/hex"
	"net"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// Catalog zones (RFC 9432). PRIMARY side: the Store synthesizes a
// catalog zone listing every hosted primary zone; the configured
// secondaries may transfer it (and every member zone: their IPs are
// merged into all transfer ACLs) and get NOTIFY for everything. The
// catalog serial is managed like any other: it bumps when the
// membership changes, so the secondaries re-transfer the catalog and
// reconcile their provisioned zones.
//
// SECONDARY side: AddDynamicSecondary provisions zones that have no
// YAML file — the catalog itself first, then its members as the xfr
// manager parses each transferred catalog.

// catalogSettings is the parsed primary-side configuration.
type catalogSettings struct {
	apex      string
	allowNets []netip.Prefix // explicit secondaries
	notify    []string
	auto      bool // derive secondaries from the zones' NS glue
	self      map[netip.Addr]bool
}

// SetCatalog enables catalog publishing (primary side). Call before
// LoadAll. Each explicit secondary entry is IP or IP:port: the IP
// feeds the merged transfer ACL, the whole entry (port 53 default)
// the NOTIFY fan-out. With auto, the glue IPs of every apex NS
// record are secondaries too — minus self (this machine's own
// addresses): two NS names pointing at this same server derive no
// secondaries at all.
func (s *Store) SetCatalog(zoneName string, secondaries []string, auto bool, self []netip.Addr) {
	cat := &catalogSettings{apex: fqdn(zoneName), auto: auto, self: map[netip.Addr]bool{}}
	for _, a := range self {
		cat.self[a.Unmap()] = true
	}
	for _, e := range secondaries {
		host, target := e, e
		if h, _, err := net.SplitHostPort(e); err == nil {
			host = h
		} else {
			target = net.JoinHostPort(strings.Trim(e, "[]"), "53")
		}
		if a, err := netip.ParseAddr(host); err == nil {
			a = a.Unmap()
			cat.allowNets = append(cat.allowNets, netip.PrefixFrom(a, a.BitLen()))
		}
		cat.notify = append(cat.notify, target)
	}
	s.mu.Lock()
	s.catalog = cat
	s.rebuildLocked()
	s.mu.Unlock()
}

// derivedSecondaries returns the auto-discovered slave IPs of one
// zone: the in-zone glue of the apex NS set, minus ourselves.
func (cat *catalogSettings) derivedSecondaries(z *Zone) []netip.Addr {
	if !cat.auto {
		return nil
	}
	var out []netip.Addr
	for _, a := range z.NSGlueAddrs() {
		if !cat.self[a] {
			out = append(out, a)
		}
	}
	return out
}

// CatalogZone returns the apex of the published catalog, if any.
func (s *Store) CatalogZone() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.catalog == nil {
		return ""
	}
	return s.catalog.apex
}

// buildCatalogLocked synthesizes the catalog zone from the current
// member list. Callers hold s.mu.
func (s *Store) buildCatalogLocked(members []string) *Zone {
	cat := s.catalog
	// The serial machinery is reused: the "content hash" is the
	// membership, so adding/removing a zone bumps and persists.
	serial := s.serialForLocked(cat.apex, contentHash([]byte(strings.Join(members, "\n"))))

	z := &Zone{
		Name:      cat.apex,
		Type:      "primary",
		Serial:    serial,
		File:      "(catalog)",
		Transfer:  Transfer{Notify: cat.notify},
		allowNets: cat.allowNets,
		synthetic: true,
		names:     map[string]map[uint16][]rrEntry{},
	}
	z.soa = &dns.SOA{
		Hdr:     dns.RR_Header{Name: cat.apex, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:      cat.apex,
		Mbox:    "hostmaster." + cat.apex,
		Serial:  serial,
		Refresh: 3600, Retry: 600, Expire: 2592000, Minttl: 60,
	}
	z.add(z.soa, nil)
	// RFC 9432: a catalog zone has an NS record pointing at
	// "invalid." and a version TXT of "2".
	z.add(&dns.NS{
		Hdr: dns.RR_Header{Name: cat.apex, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
		Ns:  "invalid.",
	}, nil)
	z.add(&dns.TXT{
		Hdr: dns.RR_Header{Name: "version." + cat.apex, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
		Txt: []string{"2"},
	}, nil)
	for _, member := range members {
		sum := sha1.Sum([]byte(member))
		z.add(&dns.PTR{
			Hdr: dns.RR_Header{
				Name:   hex.EncodeToString(sum[:]) + ".zones." + cat.apex,
				Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60,
			},
			Ptr: member,
		}, nil)
	}
	z.indexNonTerminals()
	z.loaded = true
	return z
}

// CatalogMembers extracts the member zones of a transferred catalog
// (secondary side). A version TXT other than "2" rejects the whole
// catalog.
func CatalogMembers(catalogApex string, rrs []dns.RR) ([]string, bool) {
	apex := fqdn(catalogApex)
	versionOK := true
	var members []string
	for _, rr := range rrs {
		owner := strings.ToLower(rr.Header().Name)
		if txt, ok := rr.(*dns.TXT); ok && owner == "version."+apex {
			if len(txt.Txt) != 1 || txt.Txt[0] != "2" {
				versionOK = false
			}
		}
		if ptr, ok := rr.(*dns.PTR); ok && strings.HasSuffix(owner, ".zones."+apex) {
			members = append(members, fqdn(ptr.Ptr))
		}
	}
	return members, versionOK
}

// dynamicKey namespaces the file-less zones in the files map. "~"
// sorts after real filenames, so an explicit YAML file always wins a
// duplicate-zone conflict.
func dynamicKey(apex string) string { return "~" + apex }

// AddDynamicSecondary provisions a secondary zone with no YAML file
// (the catalog itself, or one of its members). Idempotent: an
// existing dynamic zone with the same primaries is left untouched.
func (s *Store) AddDynamicSecondary(apex string, primaries []string) {
	apex = fqdn(apex)
	key := dynamicKey(apex)

	s.mu.Lock()
	if entry, ok := s.files[key]; ok && entry.zone != nil &&
		strings.Join(entry.zone.Primaries, ",") == strings.Join(primaries, ",") {
		s.mu.Unlock()
		return
	}
	z := &Zone{
		Name:      apex,
		Type:      "secondary",
		File:      "(catalog)",
		Primaries: append([]string(nil), primaries...),
	}
	s.files[key] = &fileEntry{zone: z}
	s.rebuildLocked()
	s.mu.Unlock()

	s.log.Info("zone provisioned from catalog", "zone", apex)
	if s.OnLoad != nil {
		s.OnLoad(z)
	}
}

// RemoveDynamicSecondary drops a catalog-provisioned zone.
func (s *Store) RemoveDynamicSecondary(apex string) {
	apex = fqdn(apex)
	s.mu.Lock()
	_, existed := s.files[dynamicKey(apex)]
	delete(s.files, dynamicKey(apex))
	s.rebuildLocked()
	s.mu.Unlock()
	if existed {
		s.log.Info("zone removed by catalog", "zone", apex)
		if s.OnRemove != nil {
			s.OnRemove(apex)
		}
	}
}

// DynamicSecondaries lists the currently provisioned file-less zones.
func (s *Store) DynamicSecondaries() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for key, entry := range s.files {
		if strings.HasPrefix(key, "~") && entry.zone != nil {
			out = append(out, entry.zone.Name)
		}
	}
	return out
}
