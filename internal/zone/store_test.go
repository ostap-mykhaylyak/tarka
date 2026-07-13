package zone

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func discard() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

func writeZoneFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}

const storeZone = `
zone: example.com
soa: {mname: ns1.example.com., rname: hostmaster.example.com.}
records:
  - {name: "@", type: NS, value: ns1.example.com.}
  - {name: ns1, type: A,  value: 203.0.113.10}
`

func newTestStore(t *testing.T, dir string) *Store {
	t.Helper()
	return NewStore(dir, filepath.Join(dir, "serials.json"), discard())
}

func TestLoadAllAndFind(t *testing.T) {
	dir := t.TempDir()
	writeZoneFile(t, dir, "example.com.yaml", storeZone)
	writeZoneFile(t, dir, "skipme.yaml.example", storeZone) // shipped example: ignored

	s := newTestStore(t, dir)
	s.LoadAll()
	if s.Count() != 1 {
		t.Fatalf("want 1 zone, got %d", s.Count())
	}
	if z := s.Find("www.example.com."); z == nil || z.Name != "example.com." {
		t.Fatal("Find must match a name inside the zone")
	}
	if z := s.Find("example.net."); z != nil {
		t.Fatal("Find must miss a foreign name")
	}
}

func TestFindLongestMatch(t *testing.T) {
	dir := t.TempDir()
	writeZoneFile(t, dir, "example.com.yaml", storeZone)
	writeZoneFile(t, dir, "sub.example.com.yaml", `
zone: sub.example.com
soa: {mname: ns1.sub.example.com., rname: hostmaster.example.com.}
records:
  - {name: "@", type: NS, value: ns1.sub.example.com.}
  - {name: ns1, type: A,  value: 203.0.113.20}
`)
	s := newTestStore(t, dir)
	s.LoadAll()
	if z := s.Find("www.sub.example.com."); z == nil || z.Name != "sub.example.com." {
		t.Fatalf("longest match broken: %+v", z)
	}
	if z := s.Find("www.example.com."); z == nil || z.Name != "example.com." {
		t.Fatalf("parent zone lost: %+v", z)
	}
}

func TestSerialBumpPersistNoRegress(t *testing.T) {
	dir := t.TempDir()
	path := writeZoneFile(t, dir, "example.com.yaml", storeZone)
	serials := filepath.Join(dir, "serials.json")

	s := NewStore(dir, serials, discard())
	s.LoadAll()
	first := s.Find("example.com.").Serial
	if first == 0 {
		t.Fatal("serial must be set")
	}

	// Unchanged file, same store: serial stays.
	s.LoadFile(path)
	if got := s.Find("example.com.").Serial; got != first {
		t.Fatalf("unchanged content must keep serial: %d != %d", got, first)
	}

	// New store, same serials file: serial survives the restart.
	s2 := NewStore(dir, serials, discard())
	s2.LoadAll()
	if got := s2.Find("example.com.").Serial; got != first {
		t.Fatalf("serial must survive restart: %d != %d", got, first)
	}

	// Changed content: serial bumps, even with a frozen clock (the
	// +1 fallback guards against regressions and same-second edits).
	s2.now = func() time.Time { return time.Unix(int64(first), 0) }
	writeZoneFile(t, dir, "example.com.yaml", storeZone+"  - {name: www, type: A, value: 203.0.113.11}\n")
	s2.LoadFile(path)
	if got := s2.Find("example.com.").Serial; got != first+1 {
		t.Fatalf("changed content must bump serial past the old one: %d, want %d", got, first+1)
	}
}

func TestInvalidReloadKeepsLastGood(t *testing.T) {
	dir := t.TempDir()
	path := writeZoneFile(t, dir, "example.com.yaml", storeZone)
	s := newTestStore(t, dir)
	s.LoadAll()

	writeZoneFile(t, dir, "example.com.yaml", "zone: [broken")
	s.LoadFile(path)

	if z := s.Find("ns1.example.com."); z == nil {
		t.Fatal("last good zone must survive a broken rewrite")
	}
	infos := s.Snapshot()
	if len(infos) != 1 || infos[0].Error == "" || infos[0].Zone != "example.com." {
		t.Fatalf("snapshot must report the error and the last good zone: %+v", infos)
	}
}

func TestDuplicateZoneFlagged(t *testing.T) {
	dir := t.TempDir()
	writeZoneFile(t, dir, "a.yaml", storeZone)
	writeZoneFile(t, dir, "b.yaml", storeZone)
	s := newTestStore(t, dir)
	s.LoadAll()
	if s.Count() != 1 {
		t.Fatalf("duplicate zone must load once, got %d", s.Count())
	}
	var flagged bool
	for _, info := range s.Snapshot() {
		if info.File == "b.yaml" && info.Error != "" {
			flagged = true
		}
	}
	if !flagged {
		t.Fatalf("loser file must be flagged: %+v", s.Snapshot())
	}
}

func TestRemoveFileUnloadsZone(t *testing.T) {
	dir := t.TempDir()
	path := writeZoneFile(t, dir, "example.com.yaml", storeZone)
	s := newTestStore(t, dir)
	s.LoadAll()

	os.Remove(path)
	s.RemoveFile(path)
	if s.Count() != 0 || s.Find("example.com.") != nil {
		t.Fatal("removed file must unload its zone")
	}
}

func TestSkelExampleZoneBuilds(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "bootstrap", "skel", "etc", "tarka",
		"zones", "example.com.yaml.example"))
	if err != nil {
		t.Fatal(err)
	}
	z, warnings, err := Build(data, "example.com.yaml", func(string) uint32 { return 1 })
	if err != nil {
		t.Fatalf("shipped example zone must build: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("shipped example zone must have no warnings, got %v", warnings)
	}
	if res := z.Lookup("www.example.com.", dns.TypeA); len(res.Answer) != 1 {
		t.Fatal("shipped example zone must answer www A")
	}
}
