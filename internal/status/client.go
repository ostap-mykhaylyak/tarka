package status

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// Query connects to the daemon's control socket and returns the
// status snapshot it serves. Read-only, no side effects, safe to run
// in parallel with the daemon.
func Query(sock string, timeout time.Duration) (*Snapshot, error) {
	conn, err := net.DialTimeout("unix", sock, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if err := json.NewEncoder(conn).Encode(request{Cmd: "status"}); err != nil {
		return nil, err
	}
	var snap Snapshot
	if err := json.NewDecoder(conn).Decode(&snap); err != nil {
		return nil, err
	}
	return &snap, nil
}

// RunDNS01 implements the --dns01-set / --dns01-clear client CLI
// (the ACME hook surface) and returns the process exit code. args
// are the positional arguments: <domain> <token> for set, <domain>
// [token] for clear.
func RunDNS01(sock, cmd string, args []string) int {
	req := request{Cmd: cmd}
	switch {
	case cmd == "dns01-set" && len(args) == 2:
		req.Name, req.Token = args[0], args[1]
	case cmd == "dns01-clear" && len(args) >= 1 && len(args) <= 2:
		req.Name = args[0]
		if len(args) == 2 {
			req.Token = args[1]
		}
	default:
		fmt.Fprintf(os.Stderr, "usage: tarka --dns01-set <domain> <token> | --dns01-clear <domain> [token]\n")
		return ExitUnk
	}

	conn, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tarka: service not running:", err)
		return ExitCrit
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		fmt.Fprintln(os.Stderr, "tarka:", err)
		return ExitCrit
	}
	var res opResult
	if err := json.NewDecoder(conn).Decode(&res); err != nil {
		fmt.Fprintln(os.Stderr, "tarka:", err)
		return ExitCrit
	}
	if !res.OK {
		fmt.Fprintln(os.Stderr, "tarka:", res.Error)
		return ExitCrit
	}
	fmt.Println("ok")
	return ExitOK
}

// Run implements the --status / --status-json / --watch CLI and
// returns the process exit code (Nagios convention).
func Run(version, sock, cfgPath string, jsonOut bool, watch time.Duration) int {
	if watch <= 0 {
		snap := fetch(version, sock, cfgPath)
		print(snap, jsonOut, nil, 0)
		return ExitCode(snap.Status)
	}

	// Live mode: redraw in a loop like top (or one JSON line per tick
	// with --status-json, suitable for piping to a collector).
	// Ctrl-C exits.
	var prev *Snapshot
	var prevAt time.Time
	for {
		snap := fetch(version, sock, cfgPath)
		if !jsonOut {
			fmt.Print("\033[2J\033[H") // clear screen, home cursor
		}
		print(snap, jsonOut, prev, time.Since(prevAt))
		prev, prevAt = snap, time.Now()
		time.Sleep(watch)
	}
}

func fetch(version, sock, cfgPath string) *Snapshot {
	snap, err := Query(sock, 2*time.Second)
	if err != nil {
		return notRunning(version, cfgPath)
	}
	return snap
}

func print(snap *Snapshot, jsonOut bool, prev *Snapshot, elapsed time.Duration) {
	if jsonOut {
		json.NewEncoder(os.Stdout).Encode(snap)
		return
	}
	if prev == nil {
		fmt.Println(summaryLine(snap))
		return
	}
	// watch mode: multi-line view with rates computed between ticks.
	fmt.Println(summaryLine(snap))
	fmt.Printf("config:   %s (%s)\n", boolWord(snap.Config.Valid, "valid", "INVALID"), snap.Config.Path)
	if snap.Live != nil {
		var qRate float64
		if prev.Live != nil && elapsed > 0 {
			qRate = float64(snap.Live.QueriesTotal-prev.Live.QueriesTotal) / elapsed.Seconds()
		}
		fmt.Printf("queries:  %d total, %d in-flight, %.1f q/s\n",
			snap.Live.QueriesTotal, snap.Live.QueriesInFlight, qRate)
		fmt.Printf("rcodes:   %d noerror, %d nxdomain, %d refused, %d servfail, %d other\n",
			snap.Live.RcodeNoError, snap.Live.RcodeNXDomain, snap.Live.RcodeRefused,
			snap.Live.RcodeServFail, snap.Live.RcodeOther)
		fmt.Printf("latency:  p50 %.2fms, p95 %.2fms, p99 %.2fms\n",
			snap.Live.P50LatencyMs, snap.Live.P95LatencyMs, snap.Live.P99LatencyMs)
		if snap.Live.XfrOutTotal+snap.Live.XfrInTotal+snap.Live.NotifySent+snap.Live.NotifyReceived > 0 {
			fmt.Printf("xfr:      %d out, %d in, notify %d sent / %d received\n",
				snap.Live.XfrOutTotal, snap.Live.XfrInTotal,
				snap.Live.NotifySent, snap.Live.NotifyReceived)
		}
		fmt.Printf("bytes:    %s out\n", humanBytes(snap.Live.BytesOutTotal))
	}
	if snap.GeoIP != nil && snap.GeoIP.Enabled {
		fmt.Printf("geoip:    database %s\n", boolWord(snap.GeoIP.Loaded, "loaded", "NOT loaded"))
	}
	if snap.Acme != nil && snap.Acme.Enabled {
		for _, c := range snap.Acme.Certificates {
			switch {
			case c.Error != "":
				fmt.Printf("cert %-24s ERROR: %s\n", c.Name+":", c.Error)
			case !c.Issued:
				fmt.Printf("cert %-24s pending first issuance\n", c.Name+":")
			default:
				fmt.Printf("cert %-24s valid until %s (%dd)\n", c.Name,
					c.NotAfter.UTC().Format("2006-01-02"),
					int(time.Until(c.NotAfter).Hours()/24))
			}
		}
	}
	if snap.Zones != nil {
		if snap.Zones.DNS01Active > 0 {
			fmt.Printf("dns01:    %d active token(s)\n", snap.Zones.DNS01Active)
		}
		for _, z := range snap.Zones.Items {
			if z.Error != "" {
				fmt.Printf("zone %-24s ERROR: %s\n", z.File+":", z.Error)
				continue
			}
			if !z.Loaded {
				fmt.Printf("zone %-24s %s WAITING for transfer\n", z.Zone, z.Type)
				continue
			}
			fmt.Printf("zone %-24s %s serial %d, %d records\n", z.Zone, z.Type, z.Serial, z.Records)
		}
	}
	parts := make([]string, 0, len(snap.Checks))
	for _, c := range snap.Checks {
		parts = append(parts, c.Name+"="+c.Status)
	}
	fmt.Printf("checks:   %s\n", strings.Join(parts, " "))
}

func summaryLine(snap *Snapshot) string {
	label := map[string]string{OK: "OK", Warn: "WARNING", Crit: "CRITICAL"}[snap.Status]
	if label == "" {
		label = "UNKNOWN"
	}
	if !snap.Service.Active {
		detail := "config on disk: absent"
		for _, c := range snap.Checks {
			if c.Name == "config_on_disk" {
				switch c.Status {
				case OK:
					detail = "config on disk: valid"
				case Crit:
					detail = "config on disk: invalid"
				}
			}
		}
		return fmt.Sprintf("tarka %s - service not running (%s)", label, detail)
	}
	uptime := time.Duration(snap.Service.UptimeSeconds * float64(time.Second)).Round(time.Second)
	line := fmt.Sprintf("tarka %s - active, pid %d, uptime %s, config %s",
		label, snap.Service.PID, uptime, boolWord(snap.Config.Valid && snap.Config.Error == "", "valid", "reload pending"))
	if snap.Zones != nil {
		line += fmt.Sprintf(", %d zone(s)", snap.Zones.Zones)
	}
	if snap.Live != nil {
		line += fmt.Sprintf(", queries %d, in-flight %d, servfail %d",
			snap.Live.QueriesTotal, snap.Live.QueriesInFlight, snap.Live.RcodeServFail)
	}
	return line
}

func boolWord(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
