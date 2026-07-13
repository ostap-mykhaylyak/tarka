// Package geoip resolves a client IP to its country and continent
// using the MaxMind GeoLite2-Country database from the conventional
// Ubuntu location (/usr/share/GeoIP/, kept fresh by geoipupdate).
//
// The database is hot-swapped: a background poller reopens the file
// when its mtime changes (geoipupdate replaces it atomically), so a
// weekly refresh is picked up without a restart. A missing database
// is not fatal: lookups return an empty Geo and geo-tagged records
// simply never match (the default records answer).
package geoip

import (
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// Geo is the resolved location of an IP. Empty fields mean "unknown"
// (database missing, private IP, or not found).
type Geo struct {
	Country   string // ISO 3166-1 alpha-2, e.g. "IT"
	Continent string // two-letter code, e.g. "EU"
}

// Resolver holds the open database and reloads it on change.
type Resolver struct {
	path string
	log  *slog.Logger

	cur  atomic.Pointer[maxminddb.Reader]
	mu   sync.Mutex
	mod  time.Time
	once sync.Once
	stop chan struct{}
}

// New opens the database at path. It always returns a usable
// Resolver, even if the file is missing.
func New(path string, log *slog.Logger) *Resolver {
	r := &Resolver{path: path, log: log, stop: make(chan struct{})}
	r.reload()
	return r
}

// Loaded reports whether the database is currently open. Safe on a
// nil receiver (geoip disabled).
func (r *Resolver) Loaded() bool { return r != nil && r.cur.Load() != nil }

// Lookup resolves addr. Never errors: unknown pieces are left empty.
func (r *Resolver) Lookup(addr netip.Addr) Geo {
	if r == nil {
		return Geo{}
	}
	rd := r.cur.Load()
	if rd == nil || !addr.IsValid() {
		return Geo{}
	}
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		Continent struct {
			Code string `maxminddb:"code"`
		} `maxminddb:"continent"`
	}
	if err := rd.Lookup(addr.Unmap().AsSlice(), &rec); err != nil {
		return Geo{}
	}
	return Geo{Country: rec.Country.ISOCode, Continent: rec.Continent.Code}
}

// Watch reloads the database when the file changes, until stop.
func (r *Resolver) Watch(stop <-chan struct{}) {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-r.stop:
				return
			case <-t.C:
				r.reload()
			}
		}
	}()
}

// reload opens the database if its mtime changed and swaps the
// reader atomically. The old reader is closed after a grace period
// so in-flight lookups holding the previous pointer are unaffected.
func (r *Resolver) reload() {
	r.mu.Lock()
	defer r.mu.Unlock()

	fi, err := os.Stat(r.path)
	if err != nil {
		return
	}
	if fi.ModTime().Equal(r.mod) {
		return
	}
	rd, err := maxminddb.Open(r.path)
	if err != nil {
		r.log.Error("geoip database open failed", "path", r.path, "error", err)
		return
	}
	r.log.Info("geoip database loaded", "path", r.path, "nodes", rd.Metadata.NodeCount)
	old := r.cur.Swap(rd)
	r.mod = fi.ModTime()
	if old != nil {
		time.AfterFunc(30*time.Second, func() { old.Close() })
	}
}

// Close stops the poller and closes the open database.
func (r *Resolver) Close() {
	r.once.Do(func() {
		close(r.stop)
		if rd := r.cur.Load(); rd != nil {
			rd.Close()
		}
	})
}
