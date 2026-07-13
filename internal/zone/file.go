package zone

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"

	"github.com/ostap-mykhaylyak/tarka/internal/config"
)

// fileZone is the YAML schema of one zone file.
type fileZone struct {
	Zone      string          `yaml:"zone"`
	Type      string          `yaml:"type"` // primary (default) | secondary
	SOA       soaSection      `yaml:"soa"`
	TTL       config.Duration `yaml:"ttl"` // default TTL for records without their own
	Records   []record        `yaml:"records"`
	Transfer  Transfer        `yaml:"transfer"`
	Primaries []string        `yaml:"primaries"`
}

// soaSection carries the SOA fields the operator controls; the serial
// is managed by tarka.
type soaSection struct {
	MName   string          `yaml:"mname"`
	RName   string          `yaml:"rname"`
	Refresh config.Duration `yaml:"refresh"`
	Retry   config.Duration `yaml:"retry"`
	Expire  config.Duration `yaml:"expire"`
	Minimum config.Duration `yaml:"minimum"`
}

// record is one RR in the zone file. Value is the presentation-format
// rdata (for MX and SRV, prio is prepended when set). Geo tags the
// record for GeoDNS: uppercase ISO country codes (IT, FR) or
// continent codes (EU, NA, AS, AF, SA, OC, AN); a tagged record
// answers only clients matching one of its tags, untagged records
// are the defaults.
type record struct {
	Name  string          `yaml:"name"`
	Type  string          `yaml:"type"`
	Value string          `yaml:"value"`
	TTL   config.Duration `yaml:"ttl"`
	Prio  *uint16         `yaml:"prio"`
	Geo   []string        `yaml:"geo"`
}

// zoneDefaults returns the fileZone production defaults applied under
// a sparse file.
func zoneDefaults() fileZone {
	return fileZone{
		Type: "primary",
		TTL:  config.Duration(time.Hour),
		SOA: soaSection{
			Refresh: config.Duration(4 * time.Hour),
			Retry:   config.Duration(15 * time.Minute),
			Expire:  config.Duration(7 * 24 * time.Hour),
			Minimum: config.Duration(time.Hour),
		},
	}
}

// Build parses one zone file and assembles the in-memory Zone.
// serialFor supplies the managed serial once the zone name is known.
// Invalid records are skipped and reported in warnings, never fatal;
// a file-level problem (bad YAML, missing zone, no SOA) is an error
// and the Store keeps the last good version.
func Build(data []byte, file string, serialFor func(zoneName string) uint32) (*Zone, []string, error) {
	fz := zoneDefaults()
	if err := yaml.Unmarshal(data, &fz); err != nil {
		return nil, nil, fmt.Errorf("parse zone file: %w", err)
	}
	if strings.TrimSpace(fz.Zone) == "" {
		return nil, nil, fmt.Errorf("zone is required")
	}
	apex := fqdn(fz.Zone)

	switch fz.Type {
	case "primary", "secondary":
	default:
		return nil, nil, fmt.Errorf("type must be \"primary\" or \"secondary\", got %q", fz.Type)
	}

	z := &Zone{
		Name:      apex,
		Type:      fz.Type,
		File:      file,
		Transfer:  fz.Transfer,
		Primaries: fz.Primaries,
	}

	var warnings []string
	z.allowNets, warnings = parseAllow(fz.Transfer.Allow)

	if fz.Type == "secondary" {
		if len(fz.Primaries) == 0 {
			return nil, nil, fmt.Errorf("secondary zone requires primaries")
		}
		// Data (and the SOA, serial included) arrives via AXFR; until
		// then the zone answers SERVFAIL.
		return z, warnings, nil
	}

	if fz.SOA.MName == "" || fz.SOA.RName == "" {
		return nil, nil, fmt.Errorf("primary zone requires soa.mname and soa.rname")
	}
	for name, d := range map[string]config.Duration{
		"soa.refresh": fz.SOA.Refresh, "soa.retry": fz.SOA.Retry,
		"soa.expire": fz.SOA.Expire, "soa.minimum": fz.SOA.Minimum, "ttl": fz.TTL,
	} {
		if d.Std() <= 0 {
			return nil, nil, fmt.Errorf("%s must be positive", name)
		}
	}

	z.Serial = serialFor(apex)
	defTTL := uint32(fz.TTL.Std() / time.Second)
	z.soa = &dns.SOA{
		Hdr:     dns.RR_Header{Name: apex, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: defTTL},
		Ns:      fqdn(fz.SOA.MName),
		Mbox:    fqdn(fz.SOA.RName),
		Serial:  z.Serial,
		Refresh: uint32(fz.SOA.Refresh.Std() / time.Second),
		Retry:   uint32(fz.SOA.Retry.Std() / time.Second),
		Expire:  uint32(fz.SOA.Expire.Std() / time.Second),
		Minttl:  uint32(fz.SOA.Minimum.Std() / time.Second),
	}

	z.names = map[string]map[uint16][]rrEntry{}
	z.add(z.soa, nil)

	for i, rec := range fz.Records {
		rr, err := buildRR(rec, apex, defTTL)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("records[%d]: skipping: %v", i, err))
			continue
		}
		geo, err := normalizeGeo(rec.Geo)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("records[%d]: skipping: %v", i, err))
			continue
		}
		if len(geo) > 0 {
			z.hasGeo = true
		}
		z.add(rr, geo)
	}

	if len(z.names[apex][dns.TypeNS]) == 0 {
		warnings = append(warnings, "no NS records at the zone apex")
	}

	z.indexNonTerminals()
	z.loaded = true
	return z, warnings, nil
}

// parseAllow precompiles the transfer.allow entries (IP or CIDR);
// invalid entries are skipped with a warning, never fatal.
func parseAllow(entries []string) ([]netip.Prefix, []string) {
	var nets []netip.Prefix
	var warnings []string
	for _, e := range entries {
		if p, err := netip.ParsePrefix(e); err == nil {
			nets = append(nets, p)
			continue
		}
		if a, err := netip.ParseAddr(e); err == nil {
			a = a.Unmap()
			nets = append(nets, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		warnings = append(warnings, fmt.Sprintf("transfer.allow: skipping invalid entry %q", e))
	}
	return nets, warnings
}

// buildRR assembles one dns.RR from a YAML record via the
// presentation format, so every record type miekg/dns knows is
// supported without per-type code.
func buildRR(rec record, apex string, defTTL uint32) (dns.RR, error) {
	if rec.Type == "" {
		return nil, fmt.Errorf("type is required")
	}
	if rec.Value == "" {
		return nil, fmt.Errorf("value is required")
	}
	owner, err := ownerName(rec.Name, apex)
	if err != nil {
		return nil, err
	}

	ttl := defTTL
	if rec.TTL.Std() > 0 {
		ttl = uint32(rec.TTL.Std() / time.Second)
	}

	rtype := strings.ToUpper(rec.Type)
	rdata := rec.Value
	if rec.Prio != nil {
		rdata = fmt.Sprintf("%d %s", *rec.Prio, rdata)
	}
	// TXT rdata must be quoted on the wire format; quote plain values
	// so the natural YAML spelling works.
	if rtype == "TXT" && !strings.HasPrefix(rdata, `"`) {
		rdata = fmt.Sprintf("%q", rdata)
	}

	rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", owner, ttl, rtype, rdata))
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", rec.Name, rtype, err)
	}
	if rr == nil {
		return nil, fmt.Errorf("%s %s: empty record", rec.Name, rtype)
	}
	rr.Header().Name = strings.ToLower(rr.Header().Name)
	return rr, nil
}

// normalizeGeo validates and uppercases the geo tags of a record.
func normalizeGeo(tags []string) ([]string, error) {
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		up := strings.ToUpper(strings.TrimSpace(tag))
		if len(up) != 2 || up[0] < 'A' || up[0] > 'Z' || up[1] < 'A' || up[1] > 'Z' {
			return nil, fmt.Errorf("invalid geo tag %q (want a 2-letter country or continent code)", tag)
		}
		out = append(out, up)
	}
	return out, nil
}

// add indexes one RR under its owner and type.
func (z *Zone) add(rr dns.RR, geo []string) {
	name := rr.Header().Name
	if z.names[name] == nil {
		z.names[name] = map[uint16][]rrEntry{}
	}
	t := rr.Header().Rrtype
	z.names[name][t] = append(z.names[name][t], rrEntry{rr: rr, geo: geo})
}

// indexNonTerminals records every ancestor of an existing name (below
// the apex) that has no records of its own: those answer NODATA.
func (z *Zone) indexNonTerminals() {
	z.nonTerminals = map[string]bool{}
	for name := range z.names {
		for p := parentName(name); p != z.Name && dns.IsSubDomain(z.Name, p); p = parentName(p) {
			if _, exists := z.names[p]; !exists {
				z.nonTerminals[p] = true
			}
		}
	}
}
