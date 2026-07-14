package xfr

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/ostap-mykhaylyak/tarka/internal/zone"
)

// persistPath is where the transferred copy of a secondary zone
// lives: one presentation-format record per line, under the writable
// state dir. The file mtime tracks the last successful refresh.
// Returns "" for a name that is not safe as a filename (defense in
// depth: names reaching here are already validated upstream).
func (mg *Manager) persistPath(apex string) string {
	if !zone.ValidZoneName(apex) {
		return ""
	}
	return filepath.Join(mg.dir, strings.TrimSuffix(apex, ".")+".zone")
}

// persist writes the transferred zone atomically (tmp + rename). A
// failure only degrades restart behavior, never the running zone.
func (mg *Manager) persist(apex string, rrs []dns.RR) {
	path := mg.persistPath(apex)
	if path == "" {
		mg.log.Error("refusing to persist zone with invalid name", "zone", apex)
		return
	}
	if err := os.MkdirAll(mg.dir, 0o750); err != nil {
		mg.log.Error("zone persist failed", "zone", apex, "error", err)
		return
	}
	var b strings.Builder
	for _, rr := range rrs {
		b.WriteString(rr.String())
		b.WriteByte('\n')
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o640); err != nil {
		mg.log.Error("zone persist failed", "zone", apex, "error", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		mg.log.Error("zone persist failed", "zone", apex, "error", err)
	}
}

// touchPersisted renews the file mtime after a successful SOA check
// with an unchanged serial, so the freshness survives a restart.
func (mg *Manager) touchPersisted(apex string, when time.Time) {
	if path := mg.persistPath(apex); path != "" {
		os.Chtimes(path, when, when)
	}
}

// loadPersisted reads the persisted copy back; the mtime tells how
// fresh it was. Unparsable lines fail the whole load: a corrupt copy
// must not resurrect a partial zone.
func (mg *Manager) loadPersisted(apex string) ([]dns.RR, time.Time, error) {
	path := mg.persistPath(apex)
	if path == "" {
		return nil, time.Time{}, fmt.Errorf("invalid zone name %q", apex)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer f.Close()

	var rrs []dns.RR
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		rr, err := dns.NewRR(line)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("persisted zone %s: %w", path, err)
		}
		if rr != nil {
			rrs = append(rrs, rr)
		}
		if len(rrs) > maxTransferRecords {
			return nil, time.Time{}, fmt.Errorf("persisted zone %s: too many records", path)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, time.Time{}, err
	}
	if findSOA(rrs) == nil {
		return nil, time.Time{}, fmt.Errorf("persisted zone %s: no SOA", path)
	}
	return rrs, fi.ModTime(), nil
}
