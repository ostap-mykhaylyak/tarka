package zone

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func txtValues(res Result) []string {
	var out []string
	for _, rr := range res.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			out = append(out, txt.Txt...)
		}
	}
	return out
}

func TestDNS01SetAnswerAndSerialBump(t *testing.T) {
	dir := t.TempDir()
	writeZoneFile(t, dir, "example.com.yaml", storeZone)
	s := newTestStore(t, dir)
	s.LoadAll()
	before := s.Find("example.com.").Serial

	var notified *Zone
	s.OnLoad = func(z *Zone) { notified = z }

	if err := s.SetDNS01("example.com", "tok-1"); err != nil {
		t.Fatal(err)
	}
	z := s.Find("example.com.")
	res := z.Lookup("_acme-challenge.example.com.", dns.TypeTXT)
	if vals := txtValues(res); len(vals) != 1 || vals[0] != "tok-1" {
		t.Fatalf("challenge TXT missing: %+v", res)
	}
	if !serialAfter(z.Serial, before) {
		t.Fatalf("serial must bump: %d -> %d", before, z.Serial)
	}
	if notified == nil || notified.Serial != z.Serial {
		t.Fatal("OnLoad must fire so the secondaries get NOTIFY")
	}

	// A second token at the same name coexists (wildcard orders).
	if err := s.SetDNS01("example.com", "tok-2"); err != nil {
		t.Fatal(err)
	}
	res = s.Find("example.com.").Lookup("_acme-challenge.example.com.", dns.TypeTXT)
	if vals := txtValues(res); len(vals) != 2 {
		t.Fatalf("both tokens must answer, got %v", vals)
	}

	// The tokens travel in the AXFR too.
	found := 0
	for _, rr := range s.Find("example.com.").TransferRecords() {
		if txt, ok := rr.(*dns.TXT); ok && txt.Hdr.Name == "_acme-challenge.example.com." {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("AXFR must carry the challenge TXTs, found %d", found)
	}
}

func TestDNS01ClearAndErrors(t *testing.T) {
	dir := t.TempDir()
	writeZoneFile(t, dir, "example.com.yaml", storeZone)
	s := newTestStore(t, dir)
	s.LoadAll()

	if err := s.SetDNS01("example.com", "tok-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDNS01("example.com", "tok-2"); err != nil {
		t.Fatal(err)
	}
	if s.DNS01Active() != 2 {
		t.Fatalf("want 2 active tokens, got %d", s.DNS01Active())
	}

	// Clear one specific token.
	if err := s.ClearDNS01("example.com", "tok-1"); err != nil {
		t.Fatal(err)
	}
	res := s.Find("example.com.").Lookup("_acme-challenge.example.com.", dns.TypeTXT)
	if vals := txtValues(res); len(vals) != 1 || vals[0] != "tok-2" {
		t.Fatalf("specific clear broken: %v", vals)
	}

	// Clear all remaining tokens at the name.
	if err := s.ClearDNS01("example.com", ""); err != nil {
		t.Fatal(err)
	}
	res = s.Find("example.com.").Lookup("_acme-challenge.example.com.", dns.TypeTXT)
	if len(res.Answer) != 0 {
		t.Fatalf("clear-all broken: %+v", res)
	}
	if s.DNS01Active() != 0 {
		t.Fatal("no tokens must remain")
	}

	// Unknown zone and missing token are errors.
	if err := s.SetDNS01("nowhere.test", "x"); err == nil {
		t.Fatal("unknown zone must error")
	}
	if err := s.ClearDNS01("example.com", "ghost"); err == nil {
		t.Fatal("clearing a missing token must error")
	}
}

func TestDNS01AcceptsPrefixedName(t *testing.T) {
	dir := t.TempDir()
	writeZoneFile(t, dir, "example.com.yaml", storeZone)
	s := newTestStore(t, dir)
	s.LoadAll()

	// Some ACME clients hand the full record name: no double prefix.
	if err := s.SetDNS01("_acme-challenge.www.example.com", "tok"); err != nil {
		t.Fatal(err)
	}
	res := s.Find("example.com.").Lookup("_acme-challenge.www.example.com.", dns.TypeTXT)
	if vals := txtValues(res); len(vals) != 1 || vals[0] != "tok" {
		t.Fatalf("prefixed name broken: %+v", res)
	}
}

func TestDNS01RefusedOnSecondaryZone(t *testing.T) {
	dir := t.TempDir()
	writeZoneFile(t, dir, "example.org.yaml",
		"zone: example.org\ntype: secondary\nprimaries: [203.0.113.53]\n")
	s := newTestStore(t, dir)
	s.LoadAll()
	if err := s.SetDNS01("example.org", "tok"); err == nil {
		t.Fatal("secondary zone must refuse dns01 tokens")
	}
}

func TestDNS01SweepExpiresTokens(t *testing.T) {
	dir := t.TempDir()
	writeZoneFile(t, dir, "example.com.yaml", storeZone)
	s := newTestStore(t, dir)
	s.LoadAll()

	if err := s.SetDNS01("example.com", "tok"); err != nil {
		t.Fatal(err)
	}
	// Fast-forward past the token lifetime and sweep.
	s.now = func() time.Time { return time.Now().Add(dns01Lifetime + time.Minute) }
	s.sweepDNS01()

	res := s.Find("example.com.").Lookup("_acme-challenge.example.com.", dns.TypeTXT)
	if len(res.Answer) != 0 {
		t.Fatalf("expired token must be swept: %+v", res)
	}
	if s.DNS01Active() != 0 {
		t.Fatal("sweep must drop the entry")
	}
}

func TestDNS01SurvivesZoneReload(t *testing.T) {
	dir := t.TempDir()
	path := writeZoneFile(t, dir, "example.com.yaml", storeZone)
	s := newTestStore(t, dir)
	s.LoadAll()

	if err := s.SetDNS01("example.com", "tok"); err != nil {
		t.Fatal(err)
	}
	// A YAML edit mid-validation must not lose the published token.
	writeZoneFile(t, dir, "example.com.yaml", storeZone+"  - {name: www, type: A, value: 203.0.113.11}\n")
	s.LoadFile(path)

	res := s.Find("example.com.").Lookup("_acme-challenge.example.com.", dns.TypeTXT)
	if vals := txtValues(res); len(vals) != 1 || vals[0] != "tok" {
		t.Fatalf("token must survive a zone reload: %+v", res)
	}
}

// serialAfter is RFC 1982 "a comes after b".
func serialAfter(a, b uint32) bool { return int32(a-b) > 0 }
