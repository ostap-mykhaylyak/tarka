package zone

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

const aliasZone = `
zone: example.com
soa: {mname: ns1.example.com., rname: hostmaster.example.com.}
records:
  - {name: "@",  type: NS,    value: ns1.example.com.}
  - {name: ns1,  type: A,     value: 203.0.113.10}
  - {name: "@",  type: ALIAS, value: lb.provider.net.}
  - {name: www,  type: ANAME, value: lb.provider.net.}
`

func aRR(t *testing.T, owner, ip string) dns.RR {
	t.Helper()
	return &dns.A{
		Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP(ip),
	}
}

func TestAliasParsingAndExistence(t *testing.T) {
	z, warnings, err := Build([]byte(aliasZone), "example.com.yaml", func(string) uint32 { return 1 })
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	targets := z.AliasTargets()
	if targets["example.com."] != "lb.provider.net." || targets["www.example.com."] != "lb.provider.net." {
		t.Fatalf("alias targets broken: %v", targets)
	}
	// The alias owner exists: a non-alias type is NODATA, not NXDOMAIN.
	if res := z.Lookup("www.example.com.", dns.TypeMX); res.Rcode != dns.RcodeSuccess || len(res.Answer) != 0 {
		t.Fatalf("alias owner must answer NODATA for other types: %+v", res)
	}
}

func TestAliasMaterializationAndSerialBump(t *testing.T) {
	dir := t.TempDir()
	writeZoneFile(t, dir, "example.com.yaml", aliasZone)
	s := newTestStore(t, dir)
	s.LoadAll()
	before := s.Find("example.com.").Serial

	var notified int
	s.OnLoad = func(z *Zone) {
		if z.Name == "example.com." {
			notified++
		}
	}

	// The alias manager resolves and installs the apex A.
	changed := s.SetAliasRecords("example.com.", []dns.RR{aRR(t, "example.com.", "198.51.100.5")})
	if !changed {
		t.Fatal("first alias set must count as a change")
	}
	z := s.Find("example.com.")
	if !serialAfter(z.Serial, before) {
		t.Fatalf("alias change must bump the serial: %d -> %d", before, z.Serial)
	}
	if notified == 0 {
		t.Fatal("alias change must fire OnLoad (NOTIFY the secondaries)")
	}
	// The apex now answers A even though only an ALIAS was in the file.
	res := z.Lookup("example.com.", dns.TypeA)
	if len(res.Answer) != 1 || res.Answer[0].(*dns.A).A.String() != "198.51.100.5" {
		t.Fatalf("apex ALIAS must answer flattened A: %+v", res)
	}
	// And it travels in the AXFR.
	found := false
	for _, rr := range z.TransferRecords() {
		if a, ok := rr.(*dns.A); ok && a.Hdr.Name == "example.com." {
			found = true
		}
	}
	if !found {
		t.Fatal("materialized ALIAS A must be in the AXFR")
	}

	// Same IPs again: no serial bump.
	serial := s.Find("example.com.").Serial
	if s.SetAliasRecords("example.com.", []dns.RR{aRR(t, "example.com.", "198.51.100.5")}) {
		t.Fatal("unchanged alias set must not report a change")
	}
	if s.Find("example.com.").Serial != serial {
		t.Fatal("unchanged alias set must keep the serial")
	}

	// AliasZones exposes the owners for the manager to resolve.
	if az := s.AliasZones(); len(az["example.com."]) != 2 {
		t.Fatalf("AliasZones must list the alias owners: %v", az)
	}
}
