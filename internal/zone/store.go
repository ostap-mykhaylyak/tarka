package zone

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/miekg/dns"
)

// Store loads and serves the zones of a directory (one YAML file per
// zone). Files are hot-reloaded; an invalid rewrite never unloads the
// last good version of its zone.
type Store struct {
	dir         string
	serialsPath string
	log         *slog.Logger

	// OnLoad and OnRemove, when set BEFORE LoadAll/Watch, are invoked
	// (outside the store lock) after a zone file is loaded or removed.
	// The xfr subsystem hooks them for NOTIFY and secondary refresh.
	OnLoad   func(z *Zone)
	OnRemove func(apex string)

	mu      sync.Mutex
	files   map[string]*fileEntry // by base filename ("~"+apex for dynamic zones)
	serials map[string]serialEntry
	dns01   map[string][]dns01Entry // ephemeral ACME TXT overlay, by apex
	alias   map[string][]dns.RR     // materialized ALIAS A/AAAA overlay, by apex
	catalog *catalogSettings        // non-nil when publishing a catalog (primary side)
	// catalogDirty is set by rebuildLocked when the catalog serial
	// bumped; the caller fires OnLoad outside the lock so NOTIFY
	// reaches the secondaries.
	catalogDirty bool
	now          func() time.Time // test override

	// zones is the lookup table (apex -> Zone), rebuilt on every
	// change and swapped atomically: Find is hot-path cheap.
	zones atomic.Pointer[map[string]*Zone]
}

// fileEntry is the per-file state: the last good zone plus the error
// of the most recent failed load, if any.
type fileEntry struct {
	zone    *Zone
	lastErr string
}

// serialEntry persists the managed serial together with the hash of
// the file content that produced it.
type serialEntry struct {
	Serial uint32 `json:"serial"`
	Hash   string `json:"hash"`
}

// Info is the per-file status snapshot, served by --status.
type Info struct {
	File    string `json:"file"`
	Zone    string `json:"zone,omitempty"`
	Type    string `json:"type,omitempty"`
	Serial  uint32 `json:"serial,omitempty"`
	Records int    `json:"records,omitempty"`
	Loaded  bool   `json:"loaded"`
	Error   string `json:"error,omitempty"`
}

// NewStore returns a Store over dir, persisting serials at
// serialsPath (production: paths.SerialsFile).
func NewStore(dir, serialsPath string, log *slog.Logger) *Store {
	s := &Store{
		dir:         dir,
		serialsPath: serialsPath,
		log:         log,
		files:       map[string]*fileEntry{},
		serials:     map[string]serialEntry{},
		dns01:       map[string][]dns01Entry{},
		alias:       map[string][]dns.RR{},
		now:         time.Now,
	}
	s.loadSerials()
	empty := map[string]*Zone{}
	s.zones.Store(&empty)
	return s
}

// LoadAll (re)loads every *.yaml file in the directory. Missing dir
// is not fatal: it simply means zero zones.
func (s *Store) LoadAll() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if !os.IsNotExist(err) {
			s.log.Error("zones dir unreadable", "dir", s.dir, "error", err)
		}
		return
	}
	for _, e := range entries {
		if e.IsDir() || !isZoneFile(e.Name()) {
			continue
		}
		s.LoadFile(filepath.Join(s.dir, e.Name()))
	}
}

// isZoneFile filters for active zone files: *.yaml, not dotfiles.
// Shipped examples (*.example) and editor droppings are ignored.
func isZoneFile(name string) bool {
	return strings.HasSuffix(name, ".yaml") && !strings.HasPrefix(name, ".")
}

// LoadFile (re)loads a single zone file. On error the previous good
// version of the file stays loaded and the error is retained for the
// status snapshot.
func (s *Store) LoadFile(path string) {
	base := filepath.Base(path)

	data, err := os.ReadFile(path)
	if err != nil {
		s.setError(base, fmt.Sprintf("read: %v", err))
		return
	}
	hash := contentHash(data)

	s.mu.Lock()
	z, warnings, err := Build(data, base, func(name string) uint32 {
		return s.serialForLocked(name, hash)
	})
	s.mu.Unlock()
	if err != nil {
		s.setError(base, err.Error())
		return
	}
	for _, w := range warnings {
		s.log.Warn("zone warning", "file", base, "zone", z.Name, "warning", w)
	}

	s.mu.Lock()
	entry := s.files[base]
	if entry == nil {
		entry = &fileEntry{}
		s.files[base] = entry
	}
	entry.zone, entry.lastErr = z, ""
	s.rebuildLocked()
	// Hand the hook the SERVING zone (overlay and catalog transfer
	// targets applied), so the NOTIFY fan-out reaches the catalog
	// secondaries too — unless this file lost a duplicate conflict.
	loaded := (*s.zones.Load())[z.Name]
	s.mu.Unlock()

	s.log.Info("zone loaded", "file", base, "zone", z.Name, "type", z.Type,
		"serial", z.Serial, "records", z.Records())
	if s.OnLoad != nil && loaded != nil && loaded.File == z.File {
		s.OnLoad(loaded)
	}
	s.notifyCatalogChange()
}

// RemoveFile unloads the zone of a deleted file.
func (s *Store) RemoveFile(path string) {
	base := filepath.Base(path)
	s.mu.Lock()
	entry, existed := s.files[base]
	delete(s.files, base)
	s.rebuildLocked()
	s.mu.Unlock()
	if existed {
		s.log.Info("zone file removed", "file", base)
		if s.OnRemove != nil && entry.zone != nil {
			s.OnRemove(entry.zone.Name)
		}
	}
	s.notifyCatalogChange()
}

// SetSecondaryData installs transferred records into the secondary
// zone with the given apex. Called by the xfr subsystem after a
// successful AXFR (or when resuming from the persisted copy).
func (s *Store) SetSecondaryData(apex string, rrs []dns.RR) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, entry := range s.files {
		if entry.zone == nil || entry.zone.Name != apex || entry.zone.Type != "secondary" {
			continue
		}
		z, err := entry.zone.WithData(rrs)
		if err != nil {
			return err
		}
		entry.zone = z
		s.rebuildLocked()
		return nil
	}
	return fmt.Errorf("no secondary zone %s", apex)
}

// ExpireSecondary drops the data of a secondary zone whose SOA expire
// window elapsed without a successful refresh: serving stale data is
// worse than SERVFAIL.
func (s *Store) ExpireSecondary(apex string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, entry := range s.files {
		if entry.zone == nil || entry.zone.Name != apex || entry.zone.Type != "secondary" {
			continue
		}
		z := *entry.zone
		z.names, z.nonTerminals, z.soa, z.Serial, z.loaded = nil, nil, nil, 0, false
		entry.zone = &z
		s.rebuildLocked()
		return
	}
}

func (s *Store) setError(base, msg string) {
	s.mu.Lock()
	entry := s.files[base]
	if entry == nil {
		entry = &fileEntry{}
		s.files[base] = entry
	}
	entry.lastErr = msg
	hadZone := entry.zone != nil
	s.mu.Unlock()
	if hadZone {
		s.log.Error("zone reload failed, keeping last good version", "file", base, "error", msg)
	} else {
		s.log.Error("zone load failed", "file", base, "error", msg)
	}
}

// rebuildLocked recomputes the apex lookup table. Two files claiming
// the same zone: the first in filename order wins, the other is
// flagged. The ephemeral DNS-01 overlay and the catalog (merged
// transfer ACL + the synthesized catalog zone itself) are applied
// here, on top of the immutable per-file zones. Callers hold s.mu.
func (s *Store) rebuildLocked() {
	zones := map[string]*Zone{}
	var members []string
	derivedAll := map[netip.Addr]bool{} // union of auto-discovered slaves
	for _, base := range sortedFilesLocked(s.files) {
		entry := s.files[base]
		if entry.zone == nil {
			continue
		}
		if other, dup := zones[entry.zone.Name]; dup {
			entry.lastErr = fmt.Sprintf("zone %s already defined by %s", entry.zone.Name, other.File)
			s.log.Error("duplicate zone, file ignored", "file", base, "zone", entry.zone.Name, "winner", other.File)
			continue
		}
		z := entry.zone
		if txt := s.overlayRRsLocked(z); len(txt) > 0 {
			z = z.WithOverlay(s.serials[z.Name].Serial, txt)
		}
		if s.catalog != nil && z.Type == "primary" {
			nets := s.catalog.allowNets
			notify := s.catalog.notify
			for _, a := range s.catalog.derivedSecondaries(z) {
				derivedAll[a] = true
				nets = append(nets, netip.PrefixFrom(a, a.BitLen()))
				notify = append(notify, net.JoinHostPort(a.String(), "53"))
			}
			if len(nets) > 0 || len(notify) > 0 {
				z = z.withExtraTransfer(nets, notify)
			}
			members = append(members, z.Name)
		}
		zones[z.Name] = z
	}
	// The catalog is worth publishing only when someone may fetch it.
	if s.catalog != nil && (len(s.catalog.allowNets) > 0 || len(derivedAll) > 0) {
		before := s.serials[s.catalog.apex].Serial
		cat := s.buildCatalogLocked(members)
		for a := range derivedAll {
			cat.allowNets = append(cat.allowNets, netip.PrefixFrom(a, a.BitLen()))
			cat.Transfer.Notify = appendUnique(cat.Transfer.Notify, net.JoinHostPort(a.String(), "53"))
		}
		zones[cat.Name] = cat
		if cat.Serial != before {
			s.catalogDirty = true
		}
	}
	s.zones.Store(&zones)
}

func appendUnique(list []string, v string) []string {
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}

// notifyCatalogChange fires OnLoad for the catalog zone when the last
// rebuild bumped its serial (membership changed): the secondaries get
// NOTIFY and reconcile. Call OUTSIDE the store lock.
func (s *Store) notifyCatalogChange() {
	s.mu.Lock()
	dirty := s.catalogDirty
	s.catalogDirty = false
	var cat *Zone
	if dirty && s.catalog != nil {
		cat = (*s.zones.Load())[s.catalog.apex]
	}
	s.mu.Unlock()
	if cat != nil && s.OnLoad != nil {
		s.OnLoad(cat)
	}
}

func sortedFilesLocked(files map[string]*fileEntry) []string {
	out := make([]string, 0, len(files))
	for base := range files {
		out = append(out, base)
	}
	sort.Strings(out)
	return out
}

// Find returns the zone with the longest match for qname (lowercase
// FQDN), or nil when no hosted zone contains it. Hot path: one atomic
// load plus a label walk.
func (s *Store) Find(qname string) *Zone {
	zones := *s.zones.Load()
	for name := qname; name != ""; name = parentName(name) {
		if z, ok := zones[name]; ok {
			return z
		}
	}
	return nil
}

// Count returns the number of zones currently answering.
func (s *Store) Count() int { return len(*s.zones.Load()) }

// PrimaryStatus describes a served primary zone and the secondaries
// that should be tracking it (the merged NOTIFY targets).
type PrimaryStatus struct {
	Apex        string
	Serial      uint32
	Secondaries []string // host:port
}

// PrimaryStatuses lists the served primary zones (catalog excluded)
// with their current serial and secondary targets. The master-side
// lag monitor probes these.
func (s *Store) PrimaryStatuses() []PrimaryStatus {
	zones := *s.zones.Load()
	var out []PrimaryStatus
	for _, z := range zones {
		if z.Type != "primary" || z.synthetic || !z.loaded {
			continue
		}
		out = append(out, PrimaryStatus{
			Apex:        z.Name,
			Serial:      z.Serial,
			Secondaries: append([]string(nil), z.Transfer.Notify...),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Apex < out[j].Apex })
	return out
}

// PrimaryZones returns the apexes (lowercase FQDN) of the loaded
// primary zones, sorted. The ACME manager derives its certificate
// candidates from this list; the synthetic catalog zone is not a
// real domain and is excluded.
func (s *Store) PrimaryZones() []string {
	zones := *s.zones.Load()
	out := make([]string, 0, len(zones))
	for name, z := range zones {
		if z.Type == "primary" && z.loaded && !z.synthetic {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// Snapshot returns the per-file status, sorted by filename.
func (s *Store) Snapshot() []Info {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Info, 0, len(s.files))
	for _, base := range sortedFilesLocked(s.files) {
		entry := s.files[base]
		info := Info{File: base, Error: entry.lastErr}
		if entry.zone != nil {
			info.Zone = entry.zone.Name
			info.Type = entry.zone.Type
			info.Serial = entry.zone.Serial
			info.Records = entry.zone.Records()
			info.Loaded = entry.zone.loaded
		}
		out = append(out, info)
	}
	return out
}

// Watch hot-reloads zone files until stop is closed. Events for
// non-zone files are ignored; a removed file unloads its zone.
func (s *Store) Watch(stop <-chan struct{}) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("zones watch: %w", err)
	}
	if err := w.Add(s.dir); err != nil {
		w.Close()
		return fmt.Errorf("zones watch: %w", err)
	}

	go func() {
		defer w.Close()
		for {
			select {
			case <-stop:
				return
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				if !isZoneFile(filepath.Base(ev.Name)) {
					continue
				}
				switch {
				case ev.Op&(fsnotify.Create|fsnotify.Write) != 0:
					s.LoadFile(ev.Name)
				case ev.Op&(fsnotify.Remove|fsnotify.Rename) != 0:
					// A rename can be either an atomic replace (target
					// re-appears) or a move-away: trust the filesystem.
					if _, err := os.Stat(ev.Name); err == nil {
						s.LoadFile(ev.Name)
					} else {
						s.RemoveFile(ev.Name)
					}
				}
			case err, ok := <-w.Errors:
				if !ok {
					return
				}
				s.log.Error("zones watch error", "error", err)
			}
		}
	}()
	return nil
}

// --- managed serials -------------------------------------------------

// serialForLocked returns the persisted serial for a zone, bumping it
// when the file content changed. Serials never regress: the bump is
// max(now, previous+1). Callers hold s.mu.
func (s *Store) serialForLocked(zoneName, hash string) uint32 {
	entry, ok := s.serials[zoneName]
	if ok && entry.Hash == hash {
		return entry.Serial
	}
	serial := uint32(s.now().Unix())
	if serial <= entry.Serial {
		serial = entry.Serial + 1
	}
	s.serials[zoneName] = serialEntry{Serial: serial, Hash: hash}
	s.saveSerialsLocked()
	return serial
}

func (s *Store) loadSerials() {
	data, err := os.ReadFile(s.serialsPath)
	if err != nil {
		if !os.IsNotExist(err) {
			s.log.Warn("serials file unreadable, starting fresh", "path", s.serialsPath, "error", err)
		}
		return
	}
	if err := json.Unmarshal(data, &s.serials); err != nil {
		s.log.Warn("serials file corrupt, starting fresh", "path", s.serialsPath, "error", err)
		s.serials = map[string]serialEntry{}
	}
}

// saveSerialsLocked persists the serials atomically (tmp + rename).
// A write failure is logged, not fatal: the zone still serves, only
// the persistence is degraded.
func (s *Store) saveSerialsLocked() {
	data, err := json.MarshalIndent(s.serials, "", "  ")
	if err != nil {
		s.log.Error("serials marshal failed", "error", err)
		return
	}
	tmp := s.serialsPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		s.log.Error("serials write failed", "path", s.serialsPath, "error", err)
		return
	}
	if err := os.Rename(tmp, s.serialsPath); err != nil {
		s.log.Error("serials write failed", "path", s.serialsPath, "error", err)
	}
}

func contentHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
