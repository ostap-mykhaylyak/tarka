// tarka - authoritative DNS server.
//
// Without flags the binary starts the daemon (what the systemd unit
// does). Lifecycle flags (--init, --purge) act on the filesystem from
// the standalone binary; client flags (--status, --watch) query the
// RUNNING daemon through its local Unix socket.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ostap-mykhaylyak/tarka/internal/acme"
	"github.com/ostap-mykhaylyak/tarka/internal/alias"
	"github.com/ostap-mykhaylyak/tarka/internal/bootstrap"
	"github.com/ostap-mykhaylyak/tarka/internal/config"
	"github.com/ostap-mykhaylyak/tarka/internal/geoip"
	"github.com/ostap-mykhaylyak/tarka/internal/logging"
	"github.com/ostap-mykhaylyak/tarka/internal/metrics"
	"github.com/ostap-mykhaylyak/tarka/internal/paths"
	"github.com/ostap-mykhaylyak/tarka/internal/server"
	"github.com/ostap-mykhaylyak/tarka/internal/status"
	"github.com/ostap-mykhaylyak/tarka/internal/xfr"
	"github.com/ostap-mykhaylyak/tarka/internal/zone"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	// --- lifecycle: act on the filesystem, standalone binary ---
	initOnly := flag.Bool("init", false, "create the default filesystem layout and install the service, then exit")
	purge := flag.Bool("purge", false, "remove ALL config, data and logs, then exit")
	assumeYes := flag.Bool("yes", false, "skip the confirmation prompt for --purge")

	// --- client: talk to the running daemon via its local socket ---
	statusFlag := flag.Bool("status", false, "query the running service, print status, exit")
	statusJSON := flag.Bool("status-json", false, "machine-readable status (implies --status)")
	watch := flag.Duration("watch", 0, "refresh --status every interval (e.g. 2s), like top")
	dns01Set := flag.Bool("dns01-set", false, "publish an ACME DNS-01 token: tarka --dns01-set <domain> <token>")
	dns01Clear := flag.Bool("dns01-clear", false, "remove ACME DNS-01 token(s): tarka --dns01-clear <domain> [token]")

	// --- misc ---
	showVersion := flag.Bool("version", false, "print version and exit")
	cfgPath := flag.String("config", paths.ConfigFile, "config file (testing override)")
	flag.Parse()

	switch {
	case *showVersion:
		fmt.Println("tarka", version)
		return
	case *initOnly:
		fatalIf(bootstrap.Init(version, os.Stdout))
		return
	case *purge:
		fatalIf(bootstrap.Purge(*assumeYes, os.Stdin, os.Stdout))
		return
	case *statusFlag || *statusJSON || *watch > 0:
		os.Exit(status.Run(version, paths.Socket, *cfgPath, *statusJSON, *watch))
	case *dns01Set:
		os.Exit(status.RunDNS01(paths.Socket, "dns01-set", flag.Args()))
	case *dns01Clear:
		os.Exit(status.RunDNS01(paths.Socket, "dns01-clear", flag.Args()))
	}

	fatalIf(runDaemon(*cfgPath))
}

func runDaemon(cfgPath string) (err error) {
	// First execution without a config: auto-provision the default
	// layout from the embedded skel, warn on stderr and keep going.
	if cfgPath == paths.ConfigFile {
		if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "tarka: no config found, provisioning default layout")
			if err := bootstrap.EnsureLayout(os.Stderr); err != nil {
				return err
			}
		}
	}

	mgr, err := config.NewManager(cfgPath)
	if err != nil {
		return err
	}

	logs, err := logging.Open(paths.LogDir)
	if err != nil {
		return err
	}
	defer logs.Close()
	// Surface a fatal startup error (e.g. port 53 already in use) in
	// the service log too, not only on stderr — otherwise a crash loop
	// is invisible to anyone reading tarka.log. Runs before logs.Close.
	defer func() {
		if err != nil {
			logs.Service.Error("fatal error, exiting", "error", err.Error())
		}
	}()

	logs.Service.Info("starting", "version", version, "config", cfgPath, "pid", os.Getpid())
	for _, w := range mgr.Get().Warnings {
		logs.Service.Warn("config warning", "warning", w)
	}
	// Hardening advisory: a public authoritative server without RRL is
	// an open amplification reflector.
	if mgr.Get().PublicBind() && !mgr.Get().RRL.Enabled {
		logs.Service.Warn("public bind without Response Rate Limiting: enable rrl to avoid being used as an amplification reflector")
	}

	m := metrics.New()
	stop := make(chan struct{})

	// GeoIP resolver (nil when disabled), consumed by the geo: field
	// of zone records; hot-swapped when geoipupdate refreshes the db.
	var geo *geoip.Resolver
	if gc := mgr.Get().GeoIP; gc.Enabled {
		geo = geoip.New(gc.CountryDB, logs.Service)
		geo.Watch(stop)
		defer geo.Close()
		if !geo.Loaded() {
			logs.Service.Warn("geoip enabled but country database not loaded", "path", gc.CountryDB)
		}
	}

	// Zone store (one YAML per zone, hot-reloaded, last-good on
	// errors; serials managed and persisted under LogDir) plus the
	// transfer manager: NOTIFY fan-out for primaries, refresh loops
	// for secondaries. Hooks go in before LoadAll so existing zones
	// are picked up.
	zones := zone.NewStore(mgr.Get().Zones.Dir, paths.SerialsFile, logs.Service)
	xfrMgr := xfr.NewManager(zones, m, logs.Xfr, paths.SecondaryDir, stop)
	if t := mgr.Get().TSIG; t.Enabled() {
		xfrMgr.SetTSIG(t.SecretMap(), t.KeyName(), t.AlgorithmFQDN())
	}
	zones.OnLoad = xfrMgr.ZoneLoaded
	zones.OnRemove = xfrMgr.ZoneRemoved
	// Catalog zones (RFC 9432): publish ours to the slaves — declared
	// and/or auto-derived from the NS glue of each zone (this
	// machine's own addresses never count as slaves) — and/or
	// subscribe to a master's catalog, auto-provisioning its zones.
	if cat := mgr.Get().Catalog; cat.AutoSecondaries || len(cat.Secondaries) > 0 {
		zones.SetCatalog(cat.Zone, cat.Secondaries, cat.AutoSecondaries, localAddrs())
	}
	zones.LoadAll()
	if cat := mgr.Get().Catalog; len(cat.Primaries) > 0 {
		xfrMgr.SubscribeCatalog(cat.Zone, cat.Primaries)
	}
	if err := zones.Watch(stop); err != nil {
		return err
	}
	// Drop expired ACME DNS-01 tokens left behind by a crashed hook.
	zones.StartDNS01Sweeper(stop)
	// Master-side lag monitor: track how far the secondaries trail.
	xfrMgr.StartMonitor()

	// ALIAS/ANAME flattening: resolve targets and materialize their
	// A/AAAA into the zones, refreshed in the background.
	alias.NewManager(mgr, zones, logs.Service).Start(stop)

	// Built-in ACME client: obtains and renews the configured
	// certificates, validating DNS-01 against itself.
	var acmeMgr *acme.Manager
	if mgr.Get().Acme.Enabled {
		acmeMgr = acme.NewManager(mgr, zones, logs.Acme)
		acmeMgr.Start(stop)
	}

	err = mgr.Watch(stop,
		func(err error) { logs.Service.Error("config reload failed", "error", err) },
		func(cfg *config.Config) {
			logs.Service.Info("config reloaded", "warnings", len(cfg.Warnings))
			for _, w := range cfg.Warnings {
				logs.Service.Warn("config warning", "warning", w)
			}
		})
	if err != nil {
		return err
	}

	// Local control socket: the IPC channel behind --status and the
	// ACME dns01 hook commands. If it fails the daemon still serves;
	// --status will report not running.
	collect := status.NewCollector(version, mgr, zones, geo, acmeMgr, xfrMgr, m, paths.LogDir)
	statusSrv, err := status.Serve(paths.Socket, status.Handlers{
		Status:     collect,
		DNS01Set:   zones.SetDNS01,
		DNS01Clear: zones.ClearDNS01,
	})
	if err != nil {
		logs.Service.Error("control socket unavailable", "error", err)
	}

	// Authoritative DNS listeners (UDP + TCP on every address).
	srv := server.New(mgr, zones, geo, m, logs.Query, logs.Xfr, logs.Service)
	srv.SetNotifyReceiver(xfrMgr)
	if err := srv.Start(); err != nil {
		return err
	}

	// Single signal loop: SIGHUP reopens logs (logrotate hook),
	// SIGTERM/SIGINT shut down gracefully.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for s := range sig {
		if s == syscall.SIGHUP {
			logs.Service.Info("SIGHUP received, reopening log files")
			if err := logs.Reopen(); err != nil {
				logs.Service.Error("log reopen failed", "error", err)
			}
			continue
		}
		logs.Service.Info("shutting down", "signal", s.String())
		close(stop)
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		srv.Shutdown(ctx)
		cancel()
		if statusSrv != nil {
			statusSrv.Close()
		}
		logs.Service.Info("shutdown complete")
		return nil
	}
	return nil
}

// localAddrs collects this machine's own IPs: with catalog
// auto-discovery, an NS glue pointing at ourselves is not a slave.
func localAddrs() []netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "tarka:", err)
		os.Exit(1)
	}
}
