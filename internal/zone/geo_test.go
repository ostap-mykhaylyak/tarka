package zone

import (
	"testing"

	"github.com/miekg/dns"
)

const geoZone = `
zone: example.com
soa: {mname: ns1.example.com., rname: hostmaster.example.com.}
records:
  - {name: "@",  type: NS, value: ns1.example.com.}
  - {name: ns1,  type: A,  value: 203.0.113.10}
  - {name: www,  type: A,  value: 203.0.113.10}
  - {name: www,  type: A,  value: 203.0.113.20, geo: [EU]}
  - {name: www,  type: A,  value: 203.0.113.30, geo: [IT, FR]}
  - {name: only, type: A,  value: 203.0.113.40, geo: [US]}
`

func buildGeoZone(t *testing.T) *Zone {
	t.Helper()
	z, warnings, err := Build([]byte(geoZone), "example.com.yaml", func(string) uint32 { return 1 })
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if !z.HasGeo() {
		t.Fatal("zone must report geo records")
	}
	return z
}

func answerIPs(res Result) []string {
	var out []string
	for _, rr := range res.Answer {
		out = append(out, rr.(*dns.A).A.String())
	}
	return out
}

func TestGeoCountryBeatsContinentSet(t *testing.T) {
	z := buildGeoZone(t)
	// Italian client: both the EU record and the IT record match; the
	// matched set answers (defaults excluded).
	res := z.LookupGeo("www.example.com.", dns.TypeA, ClientGeo{Country: "IT", Continent: "EU"})
	ips := answerIPs(res)
	if len(ips) != 2 || ips[0] == "203.0.113.10" || ips[1] == "203.0.113.10" {
		t.Fatalf("geo client must get only tagged matches, got %v", ips)
	}
}

func TestGeoFallbackToDefault(t *testing.T) {
	z := buildGeoZone(t)
	// US client: no tag matches www -> the untagged default answers.
	res := z.LookupGeo("www.example.com.", dns.TypeA, ClientGeo{Country: "US", Continent: "NA"})
	if ips := answerIPs(res); len(ips) != 1 || ips[0] != "203.0.113.10" {
		t.Fatalf("unmatched geo must fall back to default, got %v", ips)
	}
	// Unknown location (no geoip): same fallback.
	res = z.LookupGeo("www.example.com.", dns.TypeA, ClientGeo{})
	if ips := answerIPs(res); len(ips) != 1 || ips[0] != "203.0.113.10" {
		t.Fatalf("unknown geo must fall back to default, got %v", ips)
	}
}

func TestGeoAllTaggedNoMatchIsNodata(t *testing.T) {
	z := buildGeoZone(t)
	// "only" has a US-tagged record and no default: an EU client gets
	// NODATA (the name exists).
	res := z.LookupGeo("only.example.com.", dns.TypeA, ClientGeo{Country: "IT", Continent: "EU"})
	if res.Rcode != dns.RcodeSuccess || len(res.Answer) != 0 || len(res.Ns) != 1 {
		t.Fatalf("all-tagged no-match must be NODATA: %+v", res)
	}
	// The US client gets it.
	res = z.LookupGeo("only.example.com.", dns.TypeA, ClientGeo{Country: "US", Continent: "NA"})
	if ips := answerIPs(res); len(ips) != 1 || ips[0] != "203.0.113.40" {
		t.Fatalf("tagged match broken: %v", ips)
	}
}

func TestGeoInvalidTagSkipsRecord(t *testing.T) {
	yaml := `
zone: example.com
soa: {mname: ns1.example.com., rname: hostmaster.example.com.}
records:
  - {name: "@",  type: NS, value: ns1.example.com.}
  - {name: www,  type: A,  value: 203.0.113.10, geo: [ITALY]}
`
	z, warnings, err := Build([]byte(yaml), "f.yaml", func(string) uint32 { return 1 })
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 {
		t.Fatalf("invalid geo tag must warn, got %v", warnings)
	}
	if res := z.Lookup("www.example.com.", dns.TypeA); len(res.Answer) != 0 {
		t.Fatal("record with invalid geo tag must be skipped")
	}
}

func TestGeoTransferIncludesAllVariants(t *testing.T) {
	z := buildGeoZone(t)
	// The wire format cannot carry geo tags: AXFR ships every variant.
	// SOA + NS + ns1 A + 3x www A + only A + closing SOA = 8.
	if rrs := z.TransferRecords(); len(rrs) != 8 {
		t.Fatalf("transfer must include every geo variant, got %d records", len(rrs))
	}
}
