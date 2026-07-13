package status

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// shortSocketPath returns a socket path under the length limit of
// AF_UNIX (108 bytes; t.TempDir can exceed it).
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "tk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

func TestControlSocketRoundTrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket dial unsupported on Windows dev machines; covered in CI")
	}
	sock := shortSocketPath(t)

	set := map[string]string{}
	srv, err := Serve(sock, Handlers{
		Status: func() *Snapshot {
			return &Snapshot{Status: OK, Version: "test", Timestamp: time.Now()}
		},
		DNS01Set: func(domain, token string) error {
			set[domain] = token
			return nil
		},
		DNS01Clear: func(domain, token string) error {
			if _, ok := set[domain]; !ok {
				return fmt.Errorf("no such token")
			}
			delete(set, domain)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	snap, err := Query(sock, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Status != OK || snap.Version != "test" {
		t.Fatalf("status round-trip broken: %+v", snap)
	}

	if code := RunDNS01(sock, "dns01-set", []string{"example.com", "tok"}); code != ExitOK {
		t.Fatalf("dns01-set exit %d", code)
	}
	if set["example.com"] != "tok" {
		t.Fatalf("handler not invoked: %v", set)
	}
	if code := RunDNS01(sock, "dns01-clear", []string{"example.com"}); code != ExitOK {
		t.Fatalf("dns01-clear exit %d", code)
	}
	// Handler error surfaces as a non-zero exit.
	if code := RunDNS01(sock, "dns01-clear", []string{"example.com"}); code != ExitCrit {
		t.Fatalf("handler error must exit CRITICAL, got %d", code)
	}
	// Bad usage.
	if code := RunDNS01(sock, "dns01-set", []string{"example.com"}); code != ExitUnk {
		t.Fatalf("missing token must exit UNKNOWN, got %d", code)
	}
}
