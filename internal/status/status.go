// Package status implements the daemon's status snapshot, the local
// Unix socket that serves it, and the CLI client behind --status.
//
// The daemon is the single source of truth about its own state: the
// client never reconstructs state from disk (beyond a minimal "is the
// config on disk valid" hint when the daemon is down).
package status

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ostap-mykhaylyak/tarka/internal/acme"
	"github.com/ostap-mykhaylyak/tarka/internal/config"
	"github.com/ostap-mykhaylyak/tarka/internal/metrics"
	"github.com/ostap-mykhaylyak/tarka/internal/xfr"
	"github.com/ostap-mykhaylyak/tarka/internal/zone"
)

// ZonesProvider is the subset of the zone store the status collector
// needs (kept as an interface to avoid a hard dependency).
type ZonesProvider interface {
	Snapshot() []zone.Info
	Count() int
	DNS01Active() int
}

// GeoIPProvider is the subset of the geoip resolver the collector
// needs. May be nil (geoip disabled).
type GeoIPProvider interface {
	Loaded() bool
}

// AcmeProvider is the subset of the ACME manager the collector
// needs. May be nil (acme disabled).
type AcmeProvider interface {
	Snapshot() []acme.CertInfo
}

// LagProvider is the subset of the xfr manager the collector needs
// for the secondary-lag view.
type LagProvider interface {
	LagSnapshot() []xfr.LagInfo
}

// Check statuses, ordered by severity. Exit codes follow the Nagios
// convention: 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN.
const (
	OK       = "ok"
	Warn     = "warn"
	Crit     = "crit"
	Unknown  = "unknown"
	ExitOK   = 0
	ExitWarn = 1
	ExitCrit = 2
	ExitUnk  = 3
)

// Check is a single named health check; monitors can alert on
// individual checks as well as on the aggregate status.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok | warn | crit
	Detail string `json:"detail"`
}

// ServiceInfo describes the running daemon.
type ServiceInfo struct {
	Active        bool    `json:"active"`
	PID           int     `json:"pid,omitempty"`
	UptimeSeconds float64 `json:"uptime_seconds,omitempty"`
}

// ConfigInfo describes the loaded (or on-disk) configuration.
type ConfigInfo struct {
	Path     string   `json:"path"`
	Valid    bool     `json:"valid"`
	Error    string   `json:"error,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// ZonesSection describes the loaded zones.
type ZonesSection struct {
	Files       int         `json:"files"`
	Zones       int         `json:"zones"`
	DNS01Active int         `json:"dns01_active"`
	Items       []zone.Info `json:"items"`
}

// GeoIPSection describes the GeoIP resolver state.
type GeoIPSection struct {
	Enabled bool `json:"enabled"`
	Loaded  bool `json:"loaded"`
}

// AcmeSection describes the managed certificates.
type AcmeSection struct {
	Enabled      bool            `json:"enabled"`
	Certificates []acme.CertInfo `json:"certificates"`
}

// Snapshot is the full status document served over the socket.
// Field names are stable across versions.
type Snapshot struct {
	Status      string            `json:"status"` // ok | warn | crit | unknown
	Version     string            `json:"version"`
	Service     ServiceInfo       `json:"service"`
	Config      ConfigInfo        `json:"config"`
	Zones       *ZonesSection     `json:"zones,omitempty"`       // only when the daemon answered
	GeoIP       *GeoIPSection     `json:"geoip,omitempty"`       // only when enabled
	Acme        *AcmeSection      `json:"acme,omitempty"`        // only when enabled
	Secondaries []xfr.LagInfo     `json:"secondaries,omitempty"` // master-side lag view
	Checks      []Check           `json:"checks"`
	Live        *metrics.Snapshot `json:"live,omitempty"` // only when the daemon answered
	Timestamp   time.Time         `json:"timestamp"`
}

// ExitCode maps the aggregate status onto the Nagios exit codes.
func ExitCode(status string) int {
	switch status {
	case OK:
		return ExitOK
	case Warn:
		return ExitWarn
	case Crit:
		return ExitCrit
	default:
		return ExitUnk
	}
}

// worst aggregates check statuses; the worst one wins.
func worst(checks []Check) string {
	agg := OK
	for _, c := range checks {
		switch c.Status {
		case Crit:
			return Crit
		case Warn:
			agg = Warn
		}
	}
	return agg
}

// NewCollector builds the snapshot function the daemon serves on the
// socket. It computes the checks at request time from state the daemon
// already holds. The zone store adds its own section when it lands.
func NewCollector(version string, mgr *config.Manager, zones ZonesProvider, geo GeoIPProvider, acmeMgr AcmeProvider, lag LagProvider, m *metrics.Metrics, logDir string) func() *Snapshot {
	start := time.Now()
	return func() *Snapshot {
		cfg := mgr.Get()
		snap := &Snapshot{
			Version: version,
			Service: ServiceInfo{
				Active:        true,
				PID:           os.Getpid(),
				UptimeSeconds: time.Since(start).Seconds(),
			},
			Config: ConfigInfo{
				Path:     mgr.Path(),
				Valid:    true,
				Warnings: cfg.Warnings,
			},
			Timestamp: time.Now().UTC(),
		}

		var checks []Check
		if e := mgr.LastError(); e != "" {
			// The running config is still the previous valid one, but a
			// reload is pending with an error the operator must fix.
			checks = append(checks, Check{"config", Crit, "pending reload error: " + e})
			snap.Config.Error = e
		} else {
			checks = append(checks, Check{"config", OK, "loaded and valid"})
		}
		if len(cfg.Warnings) > 0 {
			checks = append(checks, Check{"config_warnings", Warn, cfg.Warnings[0]})
		}
		if err := checkWritable(logDir); err != nil {
			checks = append(checks, Check{"log_dir", Crit, "not writable: " + err.Error()})
		} else {
			checks = append(checks, Check{"log_dir", OK, "writable"})
		}

		if cfg.GeoIP.Enabled {
			loaded := geo != nil && geo.Loaded()
			snap.GeoIP = &GeoIPSection{Enabled: true, Loaded: loaded}
			if !loaded {
				checks = append(checks, Check{"geoip", Warn, "enabled but database not loaded"})
			} else {
				checks = append(checks, Check{"geoip", OK, "database loaded"})
			}
		}

		if cfg.Acme.Enabled && acmeMgr != nil {
			certs := acmeMgr.Snapshot()
			snap.Acme = &AcmeSection{Enabled: true, Certificates: certs}
			for _, c := range certs {
				switch {
				case c.Error != "":
					checks = append(checks, Check{"acme_" + c.Name, Warn, c.Error})
				case !c.Issued:
					checks = append(checks, Check{"acme_" + c.Name, Warn, "not yet issued"})
				case time.Until(c.NotAfter) < 7*24*time.Hour:
					checks = append(checks, Check{"acme_" + c.Name, Crit,
						"expires " + c.NotAfter.UTC().Format(time.RFC3339) + " and renewal is not succeeding"})
				default:
					checks = append(checks, Check{"acme_" + c.Name, OK,
						"valid until " + c.NotAfter.UTC().Format("2006-01-02")})
				}
			}
		}

		items := zones.Snapshot()
		snap.Zones = &ZonesSection{
			Files: len(items), Zones: zones.Count(),
			DNS01Active: zones.DNS01Active(), Items: items,
		}
		failing, waiting := 0, 0
		for _, it := range items {
			if it.Error != "" {
				failing++
			}
			if it.Error == "" && !it.Loaded {
				waiting++ // secondary without (valid) transferred data
			}
		}
		switch {
		case failing > 0:
			checks = append(checks, Check{"zones", Warn, fmt.Sprintf("%d zone file(s) failing", failing)})
		case waiting > 0:
			checks = append(checks, Check{"zones", Warn, fmt.Sprintf("%d secondary zone(s) without data", waiting)})
		case len(items) == 0:
			checks = append(checks, Check{"zones", Warn, "no zones loaded (answering REFUSED only)"})
		default:
			checks = append(checks, Check{"zones", OK, fmt.Sprintf("%d file(s), %d zone(s)", len(items), zones.Count())})
		}

		// Secondary-lag view (master side): unreachable or lagging
		// slaves surface as WARN so the monitor catches a stuck
		// transfer that the slave's own logs would hide.
		if lag != nil {
			if lags := lag.LagSnapshot(); len(lags) > 0 {
				snap.Secondaries = lags
				unreachable, behind := 0, 0
				for _, l := range lags {
					switch {
					case !l.Reachable:
						unreachable++
					case l.Behind:
						behind++
					}
				}
				switch {
				case unreachable > 0:
					checks = append(checks, Check{"secondaries", Warn, fmt.Sprintf("%d secondary probe(s) unreachable", unreachable)})
				case behind > 0:
					checks = append(checks, Check{"secondaries", Warn, fmt.Sprintf("%d secondary/ies behind on serial", behind)})
				default:
					checks = append(checks, Check{"secondaries", OK, fmt.Sprintf("%d secondary probe(s) in sync", len(lags))})
				}
			}
		}

		live := m.Snapshot()
		snap.Live = &live
		snap.Checks = checks
		snap.Status = worst(checks)
		return snap
	}
}

func checkWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".tarka-writecheck-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

// notRunning builds the fallback snapshot when the socket is
// unreachable: the service is considered down; the only extra hint is
// whether a config exists on disk and parses, to distinguish
// "installed but stopped" from "not installed".
func notRunning(version, cfgPath string) *Snapshot {
	snap := &Snapshot{
		Status:    Crit,
		Version:   version,
		Service:   ServiceInfo{Active: false},
		Config:    ConfigInfo{Path: cfgPath},
		Timestamp: time.Now().UTC(),
	}
	snap.Checks = append(snap.Checks, Check{"service", Crit, "not running (status socket unreachable)"})

	if _, err := os.Stat(cfgPath); err != nil {
		snap.Checks = append(snap.Checks, Check{"config_on_disk", Warn, "absent (not installed?)"})
		return snap
	}
	if _, err := config.Load(cfgPath); err != nil {
		snap.Config.Error = err.Error()
		snap.Checks = append(snap.Checks, Check{"config_on_disk", Crit, err.Error()})
		return snap
	}
	snap.Config.Valid = true
	snap.Checks = append(snap.Checks, Check{"config_on_disk", OK, "valid (installed but stopped)"})
	return snap
}

// socketDir returns the directory that must exist before listening.
func socketDir(sock string) string { return filepath.Dir(sock) }
