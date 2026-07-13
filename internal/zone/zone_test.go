package zone

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

const testZone = `
zone: example.com
type: primary

soa:
  mname: ns1.example.com.
  rname: hostmaster.example.com.
  refresh: 4h
  retry: 15m
  expire: 7d
  minimum: 30m

ttl: 1h

records:
  - {name: "@",    type: NS,    value: ns1.example.com.}
  - {name: ns1,    type: A,     value: 203.0.113.10}
  - {name: "@",    type: A,     value: 203.0.113.10}
  - {name: www,    type: A,     value: 203.0.113.10}
  - {name: www,    type: AAAA,  value: 2001:db8::10}
  - {name: "@",    type: MX,    value: mail.example.com., prio: 10}
  - {name: "@",    type: TXT,   value: "v=spf1 mx -all"}
  - {name: blog,   type: CNAME, value: www.example.com.}
  - {name: ext,    type: CNAME, value: cdn.example.net.}
  - {name: "*",    type: A,     value: 203.0.113.99, ttl: 5m}
  - {name: a.b,    type: A,     value: 203.0.113.11}
  - {name: sub,    type: NS,    value: ns.sub.example.com.}
  - {name: ns.sub, type: A,     value: 203.0.113.53}
`

func buildTestZone(t *testing.T) *Zone {
	t.Helper()
	z, warnings, err := Build([]byte(testZone), "example.com.yaml", func(string) uint32 { return 42 })
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		t.Fatalf("unexpected warning: %s", w)
	}
	return z
}

func TestBuildBasics(t *testing.T) {
	z := buildTestZone(t)
	if z.Name != "example.com." || z.Type != "primary" || z.Serial != 42 {
		t.Fatalf("zone metadata broken: %+v", z)
	}
	res := z.Lookup("example.com.", dns.TypeSOA)
	if len(res.Answer) != 1 {
		t.Fatal("SOA not answered at apex")
	}
	soa := res.Answer[0].(*dns.SOA)
	if soa.Serial != 42 || soa.Minttl != 1800 {
		t.Fatalf("SOA fields broken: %+v", soa)
	}
	// MX prio prepended, TXT quoted.
	if res := z.Lookup("example.com.", dns.TypeMX); len(res.Answer) != 1 || res.Answer[0].(*dns.MX).Preference != 10 {
		t.Fatalf("MX prio broken: %v", res.Answer)
	}
	if res := z.Lookup("example.com.", dns.TypeTXT); len(res.Answer) != 1 || res.Answer[0].(*dns.TXT).Txt[0] != "v=spf1 mx -all" {
		t.Fatalf("TXT broken: %v", res.Answer)
	}
}

func TestLookupPositive(t *testing.T) {
	z := buildTestZone(t)
	res := z.Lookup("www.example.com.", dns.TypeA)
	if res.Rcode != dns.RcodeSuccess || !res.Authoritative || len(res.Answer) != 1 {
		t.Fatalf("positive answer broken: %+v", res)
	}
	if res.Answer[0].(*dns.A).A.String() != "203.0.113.10" {
		t.Fatalf("wrong A record: %v", res.Answer[0])
	}
}

func TestLookupNXDomainAndNodata(t *testing.T) {
	z := buildTestZone(t)

	// NODATA: name exists, type does not. SOA in authority with the
	// negative TTL (minimum 30m < default ttl 1h).
	res := z.Lookup("www.example.com.", dns.TypeMX)
	if res.Rcode != dns.RcodeSuccess || len(res.Answer) != 0 || len(res.Ns) != 1 {
		t.Fatalf("NODATA broken: %+v", res)
	}
	if soa := res.Ns[0].(*dns.SOA); soa.Hdr.Ttl != 1800 {
		t.Fatalf("negative TTL must be SOA minimum, got %d", soa.Hdr.Ttl)
	}

	// NXDOMAIN needs a name that no wildcard covers: the wildcard is
	// at *.example.com, so a miss BELOW an existing name works.
	res = z.Lookup("missing.www.example.com.", dns.TypeA)
	if res.Rcode != dns.RcodeNameError || len(res.Ns) != 1 {
		t.Fatalf("NXDOMAIN broken: %+v", res)
	}
}

func TestLookupWildcard(t *testing.T) {
	z := buildTestZone(t)
	res := z.Lookup("anything.example.com.", dns.TypeA)
	if res.Rcode != dns.RcodeSuccess || len(res.Answer) != 1 {
		t.Fatalf("wildcard broken: %+v", res)
	}
	rr := res.Answer[0].(*dns.A)
	if rr.Hdr.Name != "anything.example.com." || rr.A.String() != "203.0.113.99" || rr.Hdr.Ttl != 300 {
		t.Fatalf("wildcard synthesis broken: %v", rr)
	}
	// Wildcard match with missing type: NODATA, not NXDOMAIN.
	res = z.Lookup("anything.example.com.", dns.TypeMX)
	if res.Rcode != dns.RcodeSuccess || len(res.Answer) != 0 || len(res.Ns) != 1 {
		t.Fatalf("wildcard NODATA broken: %+v", res)
	}
}

func TestLookupCNAME(t *testing.T) {
	z := buildTestZone(t)

	// In-zone target: CNAME + chased A in one answer.
	res := z.Lookup("blog.example.com.", dns.TypeA)
	if res.Rcode != dns.RcodeSuccess || len(res.Answer) != 2 {
		t.Fatalf("CNAME chase broken: %+v", res)
	}
	if _, ok := res.Answer[0].(*dns.CNAME); !ok {
		t.Fatalf("first answer must be the CNAME: %v", res.Answer)
	}
	if a, ok := res.Answer[1].(*dns.A); !ok || a.Hdr.Name != "www.example.com." {
		t.Fatalf("chased A broken: %v", res.Answer)
	}

	// Out-of-zone target: only the CNAME, the client chases.
	res = z.Lookup("ext.example.com.", dns.TypeA)
	if len(res.Answer) != 1 {
		t.Fatalf("external CNAME broken: %+v", res)
	}
}

func TestLookupDelegation(t *testing.T) {
	z := buildTestZone(t)
	res := z.Lookup("host.sub.example.com.", dns.TypeA)
	if res.Authoritative {
		t.Fatal("referral must not be authoritative")
	}
	if res.Rcode != dns.RcodeSuccess || len(res.Answer) != 0 || len(res.Ns) != 1 {
		t.Fatalf("referral broken: %+v", res)
	}
	if ns := res.Ns[0].(*dns.NS); ns.Ns != "ns.sub.example.com." {
		t.Fatalf("wrong NS: %v", ns)
	}
	if len(res.Extra) != 1 || res.Extra[0].(*dns.A).A.String() != "203.0.113.53" {
		t.Fatalf("glue broken: %v", res.Extra)
	}
}

func TestLookupEmptyNonTerminal(t *testing.T) {
	z := buildTestZone(t)
	// a.b.example.com exists, so b.example.com is an empty
	// non-terminal: it "exists", answers NODATA and is never covered
	// by the apex wildcard (RFC 4592).
	res := z.Lookup("b.example.com.", dns.TypeA)
	if res.Rcode != dns.RcodeSuccess || len(res.Answer) != 0 || len(res.Ns) != 1 {
		t.Fatalf("empty non-terminal broken: %+v", res)
	}
}

func TestWildcardOnlyAtClosestEncloser(t *testing.T) {
	z := buildTestZone(t)
	// www.example.com exists, so the closest encloser of
	// missing.www.example.com is www; *.www does not exist, so the
	// apex wildcard must NOT match: NXDOMAIN (RFC 4592).
	res := z.Lookup("missing.www.example.com.", dns.TypeA)
	if res.Rcode != dns.RcodeNameError {
		t.Fatalf("wildcard must not cross the closest encloser: %+v", res)
	}
	// Two labels under the wildcard's parent still match it: the
	// closest encloser of x.y.example.com is the apex.
	res = z.Lookup("x.y.example.com.", dns.TypeA)
	if res.Rcode != dns.RcodeSuccess || len(res.Answer) != 1 {
		t.Fatalf("multi-label wildcard match broken: %+v", res)
	}
}

func TestBuildInvalidRecordsSkippedWithWarning(t *testing.T) {
	yaml := `
zone: example.com
soa: {mname: ns1.example.com., rname: hostmaster.example.com.}
records:
  - {name: www, type: A, value: not-an-ip}
  - {name: www, type: A, value: 203.0.113.10}
`
	z, warnings, err := Build([]byte(yaml), "f.yaml", func(string) uint32 { return 1 })
	if err != nil {
		t.Fatal(err)
	}
	// One bad record + missing apex NS = 2 warnings.
	if len(warnings) != 2 || !strings.Contains(warnings[0], "records[0]") {
		t.Fatalf("expected skip warning, got %v", warnings)
	}
	if res := z.Lookup("www.example.com.", dns.TypeA); len(res.Answer) != 1 {
		t.Fatal("valid record must survive an invalid sibling")
	}
}

func TestBuildFatalErrors(t *testing.T) {
	for _, tc := range []struct{ name, yaml string }{
		{"missing zone", "type: primary"},
		{"bad type", "zone: x.com\ntype: banana"},
		{"primary without soa", "zone: x.com"},
		{"secondary without primaries", "zone: x.com\ntype: secondary"},
	} {
		if _, _, err := Build([]byte(tc.yaml), "f.yaml", func(string) uint32 { return 1 }); err == nil {
			t.Fatalf("%s: must fail", tc.name)
		}
	}
}

func TestSecondaryServesServfailUntilTransferred(t *testing.T) {
	yaml := "zone: example.org\ntype: secondary\nprimaries: [203.0.113.53]\n"
	z, _, err := Build([]byte(yaml), "f.yaml", func(string) uint32 { return 1 })
	if err != nil {
		t.Fatal(err)
	}
	if res := z.Lookup("www.example.org.", dns.TypeA); res.Rcode != dns.RcodeServerFailure {
		t.Fatalf("untransferred secondary must SERVFAIL, got %+v", res)
	}
}
