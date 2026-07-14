// Package paths centralizes the hardcoded FHS layout of tarka.
//
// Production code relies ONLY on these constants; overrides (e.g. the
// --config flag) exist solely for testing.
package paths

const (
	// Binary is where the installed executable lives.
	Binary = "/sbin/tarka"

	// ConfigDir holds all configuration (read-only at runtime).
	ConfigDir  = "/etc/tarka"
	ConfigFile = ConfigDir + "/config.yaml"

	// ZonesDir holds one YAML file per DNS zone.
	ZonesDir = ConfigDir + "/zones"

	// ViewsFile maps provider names to their resolver IP ranges, for
	// the view: record tag (resolver-IP-based split answers).
	ViewsFile = ConfigDir + "/views.yaml"

	// LogDir holds all log files and runtime state. It is the only
	// path the daemon is guaranteed to be able to write to.
	LogDir = "/var/log/tarka"

	// SecondaryDir persists zones transferred in secondary mode, so a
	// restart resumes from the last good copy instead of an empty zone.
	SecondaryDir = LogDir + "/secondary"

	// SerialsFile persists the auto-managed zone serials, so a serial
	// never regresses across restarts.
	SerialsFile = LogDir + "/serials.json"

	// CertsDir holds the ACME account key and the issued certificates
	// (live/<name>/fullchain.pem + privkey.pem, certbot-style layout
	// so a reverse proxy can point straight at it).
	CertsDir = LogDir + "/certs"

	// RunDir holds the local status socket (tmpfs, managed by systemd
	// via RuntimeDirectory=).
	RunDir = "/run/tarka"
	Socket = RunDir + "/tarka.sock"

	// Deploy targets used by --init.
	UnitFile      = "/etc/systemd/system/tarka.service"
	LogrotateFile = "/etc/logrotate.d/tarka"
)

// Log file names, to be joined with LogDir.
const (
	ServiceLog = "tarka.log"
	QueryLog   = "query.log"
	XfrLog     = "xfr.log"
	AcmeLog    = "acme.log"
)
