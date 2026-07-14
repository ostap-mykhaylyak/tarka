// Package views resolves a querying resolver's IP to the named
// provider "views" it belongs to (Fastweb, TIM, …). A record tagged
// with view: [Fastweb] is then served only to clients arriving
// through a Fastweb resolver — a resolver-IP split, complementary to
// ECS-based GeoDNS (the two combine as OR on the record).
//
// The provider table is a single YAML file (map name -> resolver
// CIDRs), hot-reloaded. A missing or empty file is not fatal: no
// resolver matches any view and view-tagged records fall back to
// their untagged defaults.
package views

import (
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

// table maps a lowercase provider name to its resolver prefixes.
type table map[string][]netip.Prefix

// Manager holds the provider table behind an atomic pointer and
// reloads it on change.
type Manager struct {
	path string
	log  *slog.Logger
	cur  atomic.Pointer[table]
}

// New loads the table at path (production: paths.ViewsFile). Always
// returns a usable Manager, even when the file is absent.
func New(path string, log *slog.Logger) *Manager {
	m := &Manager{path: path, log: log}
	empty := table{}
	m.cur.Store(&empty)
	m.load()
	return m
}

// Loaded reports whether at least one provider is loaded.
func (m *Manager) Loaded() bool { return m != nil && len(*m.cur.Load()) > 0 }

// Count returns the number of providers currently loaded.
func (m *Manager) Count() int {
	if m == nil {
		return 0
	}
	return len(*m.cur.Load())
}

// Lookup returns the provider views whose resolver ranges contain
// addr, sorted. Empty when none match. Hot path: one atomic load.
func (m *Manager) Lookup(addr netip.Addr) []string {
	if m == nil {
		return nil
	}
	addr = addr.Unmap()
	tbl := *m.cur.Load()
	var out []string
	for name, prefixes := range tbl {
		for _, p := range prefixes {
			if p.Contains(addr) {
				out = append(out, name)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// load parses the file and swaps the table atomically. Errors keep
// the previous table.
func (m *Manager) load() {
	data, err := os.ReadFile(m.path)
	if err != nil {
		if !os.IsNotExist(err) {
			m.log.Error("views file unreadable", "path", m.path, "error", err)
		}
		return
	}
	var raw map[string][]string
	if err := yaml.Unmarshal(data, &raw); err != nil {
		m.log.Error("views file invalid, keeping previous", "path", m.path, "error", err)
		return
	}
	tbl := table{}
	for name, entries := range raw {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" {
			continue
		}
		for _, e := range entries {
			if p, err := netip.ParsePrefix(e); err == nil {
				tbl[key] = append(tbl[key], p)
				continue
			}
			if a, err := netip.ParseAddr(e); err == nil {
				a = a.Unmap()
				tbl[key] = append(tbl[key], netip.PrefixFrom(a, a.BitLen()))
				continue
			}
			m.log.Warn("views: skipping invalid range", "provider", key, "entry", e)
		}
	}
	m.cur.Store(&tbl)
	m.log.Info("views loaded", "providers", len(tbl))
}

// Watch reloads the table when the file changes, until stop.
func (m *Manager) Watch(stop <-chan struct{}) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	if err := w.Add(filepath.Dir(m.path)); err != nil {
		w.Close()
		return err
	}
	target := filepath.Clean(m.path)
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
				if filepath.Clean(ev.Name) == target &&
					ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
					m.load()
				}
			case err, ok := <-w.Errors:
				if !ok {
					return
				}
				m.log.Error("views watch error", "error", err)
			}
		}
	}()
	return nil
}
