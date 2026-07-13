// Package zone loads the per-zone YAML files (/etc/tarka/zones/, one
// file per zone), builds the in-memory resource records and answers
// authoritative lookups.
//
// SOA serials are managed by tarka, not by the operator: the Store
// bumps the serial whenever a zone file changes and persists it so it
// never regresses across restarts.
package zone

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// maxCNAMEChain bounds in-zone CNAME chasing so a record loop cannot
// spin the handler.
const maxCNAMEChain = 8

// ClientGeo is the resolved location of the querying client (empty
// fields = unknown), used by geo-tagged records.
type ClientGeo struct {
	Country   string // ISO 3166-1 alpha-2, e.g. "IT"
	Continent string // two-letter code, e.g. "EU"
}

// rrEntry pairs one record with its optional geo tags. Untagged
// entries are the defaults; tagged entries answer only matching
// clients.
type rrEntry struct {
	rr  dns.RR
	geo []string // uppercase ISO countries or continent codes
}

// Zone is one loaded zone: immutable after build, safe for concurrent
// lookups. A reload builds a new Zone and swaps it in the Store.
type Zone struct {
	// Name is the zone apex, lowercase FQDN (e.g. "example.com.").
	Name string
	// Type is "primary" or "secondary".
	Type string
	// Serial is the SOA serial (auto-managed for primary zones).
	Serial uint32
	// File is the YAML file this zone was loaded from (base name).
	File string

	// Transfer settings, consumed by the xfr subsystem.
	Transfer  Transfer
	Primaries []string

	soa *dns.SOA
	// names maps lowercase owner FQDN -> rrtype -> entries.
	names map[string]map[uint16][]rrEntry
	// nonTerminals holds names with no records of their own but with
	// descendants (empty non-terminals answer NODATA, not NXDOMAIN).
	nonTerminals map[string]bool
	// allowNets is the precompiled transfer.allow ACL.
	allowNets []netip.Prefix
	hasGeo    bool
	loaded    bool // false for a secondary zone not yet transferred
}

// Transfer is the per-zone transfer policy (primary zones).
type Transfer struct {
	Allow  []string `yaml:"allow"`
	Notify []string `yaml:"notify"`
}

// Loaded reports whether the zone has data to answer with. It is
// false only for a secondary zone not yet (or no longer validly)
// transferred.
func (z *Zone) Loaded() bool { return z.loaded }

// HasGeo reports whether any record carries geo tags, so the server
// only pays for a GeoIP lookup when it can matter.
func (z *Zone) HasGeo() bool { return z.hasGeo }

// SOARR returns a copy of the zone's SOA record.
func (z *Zone) SOARR() dns.RR { return dns.Copy(z.soa) }

// TransferAllowed reports whether addr may AXFR this zone. An empty
// allow list refuses everyone.
func (z *Zone) TransferAllowed(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range z.allowNets {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// TransferRecords returns the full zone in AXFR wire order: SOA
// first, every other record (geo variants included: the wire format
// cannot carry the tags), SOA again as the closing sentinel.
func (z *Zone) TransferRecords() []dns.RR {
	out := []dns.RR{z.soa}
	for _, types := range z.names {
		for t, entries := range types {
			if t == dns.TypeSOA {
				continue
			}
			for _, e := range entries {
				out = append(out, e.rr)
			}
		}
	}
	return append(out, z.soa)
}

// WithData returns a copy of the zone with the transferred records
// installed (secondary zones). The serial comes from the transferred
// SOA; a set without SOA is invalid.
func (z *Zone) WithData(rrs []dns.RR) (*Zone, error) {
	nz := z.cloneMeta()
	for _, rr := range rrs {
		rr = dns.Copy(rr)
		rr.Header().Name = strings.ToLower(rr.Header().Name)
		if !dns.IsSubDomain(nz.Name, rr.Header().Name) {
			continue // never index foreign names from a transfer
		}
		if soa, ok := rr.(*dns.SOA); ok {
			if nz.soa != nil {
				continue // closing sentinel of the AXFR stream
			}
			nz.soa = soa
			nz.Serial = soa.Serial
		}
		nz.add(rr, nil)
	}
	if nz.soa == nil {
		return nil, fmt.Errorf("transferred zone %s has no SOA", nz.Name)
	}
	nz.indexNonTerminals()
	nz.loaded = true
	return nz, nil
}

// WithOverlay returns a copy of the zone with extra ephemeral records
// (the ACME DNS-01 TXT tokens) and a new serial, so secondaries see
// the change and re-transfer.
func (z *Zone) WithOverlay(serial uint32, extra []dns.RR) *Zone {
	nz := z.cloneMeta()
	nz.hasGeo = z.hasGeo
	nz.Serial = serial
	for name, types := range z.names {
		m := make(map[uint16][]rrEntry, len(types))
		for t, entries := range types {
			m[t] = entries
		}
		nz.names[name] = m
	}
	soa := dns.Copy(z.soa).(*dns.SOA)
	soa.Serial = serial
	nz.soa = soa
	nz.names[nz.Name][dns.TypeSOA] = []rrEntry{{rr: soa}}
	for _, rr := range extra {
		rr.Header().Name = strings.ToLower(rr.Header().Name)
		nz.add(rr, nil)
	}
	nz.indexNonTerminals()
	nz.loaded = true
	return nz
}

// cloneMeta copies the zone identity and policy, with empty data.
func (z *Zone) cloneMeta() *Zone {
	return &Zone{
		Name:      z.Name,
		Type:      z.Type,
		File:      z.File,
		Transfer:  z.Transfer,
		Primaries: z.Primaries,
		allowNets: z.allowNets,
		names:     map[string]map[uint16][]rrEntry{},
	}
}

// Records returns the number of records in the zone (SOA included).
func (z *Zone) Records() int {
	n := 0
	for _, types := range z.names {
		for _, entries := range types {
			n += len(entries)
		}
	}
	return n
}

// Result is the outcome of an authoritative lookup, ready to be
// copied into the response message.
type Result struct {
	Rcode         int
	Authoritative bool
	Answer        []dns.RR
	Ns            []dns.RR
	Extra         []dns.RR
}

// Lookup answers qname/qtype authoritatively for a client with no
// geo information (geo-tagged records never match: defaults answer).
func (z *Zone) Lookup(qname string, qtype uint16) Result {
	return z.LookupGeo(qname, qtype, ClientGeo{})
}

// LookupGeo answers qname/qtype authoritatively. qname must be a
// lowercase FQDN inside the zone. Geo-tagged records matching g win
// over the untagged defaults.
func (z *Zone) LookupGeo(qname string, qtype uint16, g ClientGeo) Result {
	if !z.loaded {
		// Secondary zone with no (valid) transferred data: answering
		// anything else would be lying about the zone content.
		return Result{Rcode: dns.RcodeServerFailure}
	}

	res := Result{Rcode: dns.RcodeSuccess, Authoritative: true}

	// Delegation: a name below the apex owning NS records cuts the
	// zone; anything at or under it gets a referral, not an answer.
	if del := z.delegation(qname); del != "" {
		res.Authoritative = false
		res.Ns = raw(z.names[del][dns.TypeNS])
		res.Extra = z.glue(res.Ns)
		return res
	}

	z.resolve(qname, qtype, g, 0, &res)
	return res
}

// resolve fills res for qname/qtype, following in-zone CNAMEs.
func (z *Zone) resolve(qname string, qtype uint16, g ClientGeo, depth int, res *Result) {
	if types, ok := z.names[qname]; ok {
		if cname := pick(types[dns.TypeCNAME], g); len(cname) > 0 && qtype != dns.TypeCNAME {
			z.followCNAME(cname[0].(*dns.CNAME), qtype, g, depth, res)
			return
		}
		if rrs := pick(types[qtype], g); len(rrs) > 0 {
			res.Answer = append(res.Answer, rrs...)
			return
		}
		res.Ns = append(res.Ns, z.negativeSOA())
		return // NODATA: name exists, type does not
	}

	if z.nonTerminals[qname] {
		res.Ns = append(res.Ns, z.negativeSOA())
		return // empty non-terminal: the name exists, so NODATA
	}

	// Wildcard (RFC 4592): only the wildcard at the closest encloser
	// — the longest existing ancestor of qname — may match.
	if ce := z.closestEncloser(qname); ce != "" {
		if types, ok := z.names["*."+ce]; ok {
			if cname := pick(types[dns.TypeCNAME], g); len(cname) > 0 && qtype != dns.TypeCNAME {
				z.followCNAME(synthesize(cname[0], qname).(*dns.CNAME), qtype, g, depth, res)
				return
			}
			if rrs := pick(types[qtype], g); len(rrs) > 0 {
				for _, rr := range rrs {
					res.Answer = append(res.Answer, synthesize(rr, qname))
				}
				return
			}
			res.Ns = append(res.Ns, z.negativeSOA())
			return // wildcard NODATA
		}
	}

	res.Rcode = dns.RcodeNameError
	res.Ns = append(res.Ns, z.negativeSOA())
}

// pick applies the geo selection to one RRset: tagged entries
// matching the client win; with no match, the untagged defaults
// answer. All-tagged sets with no match yield nothing (NODATA).
func pick(entries []rrEntry, g ClientGeo) []dns.RR {
	var matched, def []dns.RR
	for _, e := range entries {
		if len(e.geo) == 0 {
			def = append(def, e.rr)
			continue
		}
		for _, tag := range e.geo {
			if (g.Country != "" && tag == g.Country) || (g.Continent != "" && tag == g.Continent) {
				matched = append(matched, e.rr)
				break
			}
		}
	}
	if len(matched) > 0 {
		return matched
	}
	return def
}

// raw strips the geo metadata (delegations and glue ignore it).
func raw(entries []rrEntry) []dns.RR {
	out := make([]dns.RR, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.rr)
	}
	return out
}

// closestEncloser returns the longest existing ancestor of qname
// (empty non-terminals count as existing; the apex always exists).
func (z *Zone) closestEncloser(qname string) string {
	for p := parentName(qname); p != "" && dns.IsSubDomain(z.Name, p); p = parentName(p) {
		if _, ok := z.names[p]; ok || z.nonTerminals[p] {
			return p
		}
	}
	return ""
}

// followCNAME appends the CNAME and keeps resolving inside the zone;
// targets outside the zone are left to the client to chase.
func (z *Zone) followCNAME(cname *dns.CNAME, qtype uint16, g ClientGeo, depth int, res *Result) {
	res.Answer = append(res.Answer, cname)
	if depth >= maxCNAMEChain {
		return
	}
	target := strings.ToLower(cname.Target)
	if !dns.IsSubDomain(z.Name, target) {
		return
	}
	z.resolve(target, qtype, g, depth+1, res)
	// A chased NXDOMAIN/NODATA keeps the CNAME answer: the overall
	// response is still a positive answer for the alias itself.
	if len(res.Answer) > 0 {
		res.Rcode = dns.RcodeSuccess
	}
}

// delegation returns the closest delegation point at or above qname
// (excluding the apex), or "" when qname is inside the authoritative
// part of the zone.
func (z *Zone) delegation(qname string) string {
	del := ""
	for name := qname; name != z.Name && dns.IsSubDomain(z.Name, name); name = parentName(name) {
		if types, ok := z.names[name]; ok && len(types[dns.TypeNS]) > 0 {
			del = name // keep walking: the highest cut wins
		}
	}
	return del
}

// glue returns in-zone A/AAAA records for the NS targets.
func (z *Zone) glue(nsSet []dns.RR) []dns.RR {
	var out []dns.RR
	for _, rr := range nsSet {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		target := strings.ToLower(ns.Ns)
		if types, ok := z.names[target]; ok {
			out = append(out, raw(types[dns.TypeA])...)
			out = append(out, raw(types[dns.TypeAAAA])...)
		}
	}
	return out
}

// negativeSOA returns the SOA for the authority section of negative
// answers, with the negative-caching TTL (RFC 2308).
func (z *Zone) negativeSOA() dns.RR {
	soa := dns.Copy(z.soa).(*dns.SOA)
	if soa.Minttl < soa.Hdr.Ttl {
		soa.Hdr.Ttl = soa.Minttl
	}
	return soa
}

// synthesize copies rr with owner set to qname (wildcard expansion).
func synthesize(rr dns.RR, qname string) dns.RR {
	out := dns.Copy(rr)
	out.Header().Name = qname
	return out
}

// parentName strips the leftmost label; "" when there is no parent.
func parentName(name string) string {
	if name == "." {
		return ""
	}
	idx := dns.Split(name)
	if len(idx) < 2 {
		return "."
	}
	return name[idx[1]:]
}

// fqdn lowercases and fully qualifies a name.
func fqdn(s string) string { return strings.ToLower(dns.Fqdn(s)) }

// ownerName resolves a record name relative to the zone apex:
// "@" is the apex, a trailing dot is absolute, anything else is
// relative to the apex ("www" -> "www.example.com.").
func ownerName(name, apex string) (string, error) {
	switch {
	case name == "" || name == "@":
		return apex, nil
	case strings.HasSuffix(name, "."):
		abs := fqdn(name)
		if !dns.IsSubDomain(apex, abs) {
			return "", fmt.Errorf("name %q is outside zone %s", name, apex)
		}
		return abs, nil
	default:
		return fqdn(name) + apex, nil
	}
}
