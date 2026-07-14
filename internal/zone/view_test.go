package zone

import (
	"testing"

	"github.com/miekg/dns"
)

const viewZone = `
zone: example.com
soa: {mname: ns1.example.com., rname: hostmaster.example.com.}
records:
  - {name: "@",  type: NS, value: ns1.example.com.}
  - {name: ns1,  type: A,  value: 203.0.113.10}
  - {name: www,  type: A,  value: 203.0.113.10}                  # default
  - {name: www,  type: A,  value: 198.51.100.10, view: [Fastweb]}
  - {name: www,  type: A,  value: 192.0.2.10,    view: [TIM], geo: [DE]}
`

func buildViewZone(t *testing.T) *Zone {
	t.Helper()
	z, warnings, err := Build([]byte(viewZone), "f.yaml", func(string) uint32 { return 1 })
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if !z.HasView() {
		t.Fatal("zone must report view records")
	}
	return z
}

func TestViewSelection(t *testing.T) {
	z := buildViewZone(t)

	// Fastweb resolver → the Fastweb record.
	res := z.LookupGeo("www.example.com.", dns.TypeA, ClientGeo{Views: []string{"fastweb"}})
	if ips := answerIPs(res); len(ips) != 1 || ips[0] != "198.51.100.10" {
		t.Fatalf("Fastweb view broken: %v", ips)
	}

	// Unknown resolver, no geo → default only.
	res = z.LookupGeo("www.example.com.", dns.TypeA, ClientGeo{})
	if ips := answerIPs(res); len(ips) != 1 || ips[0] != "203.0.113.10" {
		t.Fatalf("fallback to default broken: %v", ips)
	}
}

func TestViewGeoOrCondition(t *testing.T) {
	z := buildViewZone(t)

	// The TIM record is tagged view:[TIM] AND geo:[DE]. A German
	// client on ANY resolver matches it via geo (OR), no ECS/TIM
	// needed.
	res := z.LookupGeo("www.example.com.", dns.TypeA, ClientGeo{Country: "DE", Continent: "EU"})
	if ips := answerIPs(res); len(ips) != 1 || ips[0] != "192.0.2.10" {
		t.Fatalf("geo arm of the OR broken: %v", ips)
	}

	// A TIM resolver matches the same record via the view arm.
	res = z.LookupGeo("www.example.com.", dns.TypeA, ClientGeo{Views: []string{"tim"}})
	if ips := answerIPs(res); len(ips) != 1 || ips[0] != "192.0.2.10" {
		t.Fatalf("view arm of the OR broken: %v", ips)
	}

	// A German client on a Fastweb resolver matches BOTH tagged
	// records (geo→TIM record, view→Fastweb record): both answer.
	res = z.LookupGeo("www.example.com.", dns.TypeA,
		ClientGeo{Country: "DE", Continent: "EU", Views: []string{"fastweb"}})
	if ips := answerIPs(res); len(ips) != 2 {
		t.Fatalf("both arms should contribute, got %v", ips)
	}
}

func TestViewTransferIncludesAllVariants(t *testing.T) {
	z := buildViewZone(t)
	// SOA + NS + ns1 A + 3x www A + closing SOA = 7.
	if rrs := z.TransferRecords(); len(rrs) != 7 {
		t.Fatalf("transfer must ship every view variant, got %d", len(rrs))
	}
}
