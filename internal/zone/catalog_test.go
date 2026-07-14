package zone

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestCatalogSynthesis(t *testing.T) {
	dir := t.TempDir()
	writeZoneFile(t, dir, "example.com.yaml", storeZone)
	writeZoneFile(t, dir, "example.org.yaml", strings.ReplaceAll(storeZone, "example.com", "example.org"))

	s := newTestStore(t, dir)
	s.SetCatalog("catalog.tarka.", []string{"203.0.113.2"})
	s.LoadAll()

	cat := s.Find("catalog.tarka.")
	if cat == nil || cat.Type != "primary" || !cat.Loaded() {
		t.Fatalf("catalog zone missing: %+v", cat)
	}
	if cat.Serial == 0 {
		t.Fatal("catalog serial must be managed")
	}

	// Version TXT and both members as PTR.
	members, versionOK := CatalogMembers("catalog.tarka.", cat.TransferRecords())
	if !versionOK {
		t.Fatal("shipped catalog must be version 2")
	}
	if len(members) != 2 || members[0] == members[1] {
		t.Fatalf("catalog members broken: %v", members)
	}

	// The declared secondary may transfer the catalog AND the member
	// zones without any per-zone transfer.allow.
	slave := netip.MustParseAddr("203.0.113.2")
	if !cat.TransferAllowed(slave) {
		t.Fatal("catalog must allow the declared secondary")
	}
	if !s.Find("example.com.").TransferAllowed(slave) {
		t.Fatal("member zones must inherit the catalog ACL")
	}
	if s.Find("example.com.").TransferAllowed(netip.MustParseAddr("203.0.113.99")) {
		t.Fatal("strangers must stay refused")
	}
	// NOTIFY fan-out inherited too.
	if got := s.Find("example.com.").Transfer.Notify; len(got) != 1 || got[0] != "203.0.113.2:53" {
		t.Fatalf("member notify fan-out broken: %v", got)
	}

	// The catalog zone is never an ACME candidate.
	for _, apex := range s.PrimaryZones() {
		if apex == "catalog.tarka." {
			t.Fatal("catalog must not be an ACME candidate")
		}
	}
}

func TestCatalogSerialBumpsOnMembershipChange(t *testing.T) {
	dir := t.TempDir()
	writeZoneFile(t, dir, "example.com.yaml", storeZone)
	s := newTestStore(t, dir)
	s.SetCatalog("catalog.tarka.", []string{"203.0.113.2"})
	s.LoadAll()
	before := s.Find("catalog.tarka.").Serial

	var notified []string
	s.OnLoad = func(z *Zone) { notified = append(notified, z.Name) }

	// New member: serial bumps and the catalog OnLoad fires (NOTIFY).
	path := writeZoneFile(t, dir, "example.org.yaml", strings.ReplaceAll(storeZone, "example.com", "example.org"))
	s.LoadFile(path)
	after := s.Find("catalog.tarka.").Serial
	if after == before {
		t.Fatal("membership change must bump the catalog serial")
	}
	found := false
	for _, n := range notified {
		if n == "catalog.tarka." {
			found = true
		}
	}
	if !found {
		t.Fatalf("catalog change must fire OnLoad, got %v", notified)
	}

	// Unrelated reload (same membership): no bump.
	s.LoadFile(path)
	if s.Find("catalog.tarka.").Serial != after {
		t.Fatal("unchanged membership must keep the catalog serial")
	}
}

func TestDynamicSecondaries(t *testing.T) {
	s := newTestStore(t, t.TempDir())
	s.LoadAll()

	var loaded, removed []string
	s.OnLoad = func(z *Zone) { loaded = append(loaded, z.Name) }
	s.OnRemove = func(apex string) { removed = append(removed, apex) }

	s.AddDynamicSecondary("member.example.", []string{"198.51.100.1:53"})
	z := s.Find("www.member.example.")
	if z == nil || z.Type != "secondary" || z.Loaded() {
		t.Fatalf("dynamic secondary broken: %+v", z)
	}
	if len(loaded) != 1 || loaded[0] != "member.example." {
		t.Fatalf("OnLoad must fire for provisioning: %v", loaded)
	}

	// Idempotent: same primaries, no second OnLoad.
	s.AddDynamicSecondary("member.example.", []string{"198.51.100.1:53"})
	if len(loaded) != 1 {
		t.Fatalf("re-provisioning must be idempotent: %v", loaded)
	}

	// Transferred data flows in like any secondary.
	rrs := []dns.RR{mustRR(t, "member.example. 60 IN SOA ns1.member.example. h.member.example. 7 4h 15m 7d 1h"),
		mustRR(t, "www.member.example. 60 IN A 203.0.113.10")}
	if err := s.SetSecondaryData("member.example.", rrs); err != nil {
		t.Fatal(err)
	}
	if res := s.Find("member.example.").Lookup("www.member.example.", dns.TypeA); len(res.Answer) != 1 {
		t.Fatalf("provisioned zone must answer after transfer: %+v", res)
	}

	s.RemoveDynamicSecondary("member.example.")
	if s.Find("member.example.") != nil {
		t.Fatal("removed dynamic zone must unload")
	}
	if len(removed) != 1 || removed[0] != "member.example." {
		t.Fatalf("OnRemove must fire: %v", removed)
	}
}

// A YAML file explicitly defining a zone wins over a catalog-
// provisioned one.
func TestExplicitFileBeatsDynamicZone(t *testing.T) {
	dir := t.TempDir()
	writeZoneFile(t, dir, "example.com.yaml", storeZone)
	s := newTestStore(t, dir)
	s.LoadAll()
	s.AddDynamicSecondary("example.com.", []string{"198.51.100.1"})
	if z := s.Find("example.com."); z.Type != "primary" {
		t.Fatalf("explicit file must win the conflict: %+v", z)
	}
}

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}
