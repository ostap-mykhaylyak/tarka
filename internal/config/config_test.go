package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDefaultIsValid(t *testing.T) {
	cfg := Default()
	if err := cfg.validate(); err != nil {
		t.Fatalf("Default() must validate: %v", err)
	}
	if len(cfg.Warnings) != 0 {
		t.Fatalf("Default() must have no warnings, got %v", cfg.Warnings)
	}
}

func TestSkelConfigLoads(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "bootstrap", "skel", "etc", "tarka", "config.yaml"))
	if err != nil {
		t.Fatalf("shipped skel config must load: %v", err)
	}
	if len(cfg.Warnings) != 0 {
		t.Fatalf("shipped skel config must have no warnings, got %v", cfg.Warnings)
	}
}

func TestDurationUnmarshal(t *testing.T) {
	var s struct {
		D Duration `yaml:"d"`
	}
	if err := yaml.Unmarshal([]byte(`d: 30m`), &s); err != nil {
		t.Fatal(err)
	}
	if s.D.Std() != 30*time.Minute {
		t.Fatalf("want 30m, got %s", s.D.Std())
	}
	if err := yaml.Unmarshal([]byte(`d: 7d`), &s); err != nil {
		t.Fatal(err)
	}
	if s.D.Std() != 7*24*time.Hour {
		t.Fatalf("want 7 days, got %s", s.D.Std())
	}
	if err := yaml.Unmarshal([]byte(`d: banana`), &s); err == nil {
		t.Fatal("invalid duration must error")
	}
	if err := yaml.Unmarshal([]byte(`d: xd`), &s); err == nil {
		t.Fatal("invalid day count must error")
	}
}

func TestLoadPartialOverride(t *testing.T) {
	path := writeTemp(t, "server:\n  udp_payload_size: 4096\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.UDPPayloadSize != 4096 {
		t.Fatal("override not applied")
	}
	// Defaults must survive a sparse file.
	if len(cfg.Server.Listen) != 1 || cfg.Server.Listen[0] != ":53" {
		t.Fatal("listen default lost on partial load")
	}
	if cfg.Server.TCPTimeout.Std() != 10*time.Second {
		t.Fatal("tcp_timeout default lost on partial load")
	}
	if cfg.Zones.Dir == "" {
		t.Fatal("zones.dir default lost on partial load")
	}
}

func TestListenInvalidEntriesSkipped(t *testing.T) {
	path := writeTemp(t, "server:\n  listen: [\"0.0.0.0:53\", \"not-an-address\", \"127.0.0.1:5353\"]\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Server.Listen) != 2 {
		t.Fatalf("valid entries must be kept, got %v", cfg.Server.Listen)
	}
	if len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], "not-an-address") {
		t.Fatalf("invalid entry must produce a warning, got %v", cfg.Warnings)
	}
}

func TestListenNoValidAddressFatal(t *testing.T) {
	path := writeTemp(t, "server:\n  listen: [\"broken\"]\n")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "server.listen") {
		t.Fatalf("empty valid listen set must fail, got %v", err)
	}
}

func TestUDPPayloadSizeBounds(t *testing.T) {
	path := writeTemp(t, "server:\n  udp_payload_size: 100\n")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "udp_payload_size") {
		t.Fatalf("out-of-range payload size must fail, got %v", err)
	}
}

func TestAcmeValidation(t *testing.T) {
	// Enabled without email.
	path := writeTemp(t, "acme:\n  enabled: true\n")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "acme.email") {
		t.Fatalf("acme without email must fail, got %v", err)
	}
	// ZeroSSL requires EAB.
	path = writeTemp(t, "acme:\n  enabled: true\n  email: a@b.c\n  directory: zerossl\n")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "eab") {
		t.Fatalf("zerossl without EAB must fail, got %v", err)
	}
	// Invalid resolvers are skipped with a warning; none left = fatal.
	path = writeTemp(t, "acme:\n  enabled: true\n  email: a@b.c\n  resolvers: [\"9.9.9.9:53\", \"broken\"]\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Acme.Resolvers) != 1 || len(cfg.Warnings) != 1 {
		t.Fatalf("invalid resolver must be skipped with a warning: %+v %v", cfg.Acme.Resolvers, cfg.Warnings)
	}
	path = writeTemp(t, "acme:\n  enabled: true\n  email: a@b.c\n  resolvers: [broken]\n")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "resolvers") {
		t.Fatalf("no valid resolver must fail, got %v", err)
	}
	// Minimal valid config keeps defaults (no domain lists: automatic).
	path = writeTemp(t, "acme:\n  enabled: true\n  email: a@b.c\n")
	cfg, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Acme.Directory != "letsencrypt" || cfg.Acme.RenewBefore.Std() != 30*24*time.Hour ||
		len(cfg.Acme.Resolvers) != 2 {
		t.Fatalf("acme defaults lost: %+v", cfg.Acme)
	}
}

func TestManagerReloadKeepsLastGood(t *testing.T) {
	path := writeTemp(t, "server:\n  udp_payload_size: 1400\n")
	m, err := NewManager(path)
	if err != nil {
		t.Fatal(err)
	}
	if m.Get().Server.UDPPayloadSize != 1400 {
		t.Fatal("initial load broken")
	}

	// A broken rewrite must not replace the running config.
	if err := os.WriteFile(path, []byte("server:\n  udp_payload_size: 9\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := m.Reload(); err == nil {
		t.Fatal("invalid reload must error")
	}
	if m.Get().Server.UDPPayloadSize != 1400 {
		t.Fatal("running config replaced by a broken one")
	}
	if m.LastError() == "" {
		t.Fatal("LastError must report the pending reload error")
	}

	// A valid rewrite clears the error and swaps the config.
	if err := os.WriteFile(path, []byte("server:\n  udp_payload_size: 1232\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := m.Reload(); err != nil {
		t.Fatal(err)
	}
	if m.Get().Server.UDPPayloadSize != 1232 || m.LastError() != "" {
		t.Fatal("valid reload must swap config and clear LastError")
	}
}
