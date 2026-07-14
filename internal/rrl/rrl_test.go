package rrl

import (
	"net/netip"
	"testing"
	"time"
)

func TestBucketRefillAndCap(t *testing.T) {
	l := New(5, 15*time.Second, 0, 24, 56)
	now := time.Now()
	l.now = func() time.Time { return now }

	client := netip.MustParseAddr("203.0.113.7")
	// A fresh bucket starts full: 5 responses pass, the 6th is capped.
	for i := 0; i < 5; i++ {
		if a := l.Check(client, "cat"); a != Pass {
			t.Fatalf("response %d must pass, got %v", i, a)
		}
	}
	if a := l.Check(client, "cat"); a != Drop {
		t.Fatalf("over-cap response must drop (slip 0), got %v", a)
	}

	// One second later the bucket refilled by rps (5): passes again.
	now = now.Add(time.Second)
	if a := l.Check(client, "cat"); a != Pass {
		t.Fatalf("refilled bucket must pass, got %v", a)
	}
}

func TestSlipTruncates(t *testing.T) {
	l := New(1, 15*time.Second, 2, 24, 56) // slip 2: every 2nd drop truncates
	now := time.Now()
	l.now = func() time.Time { return now }
	client := netip.MustParseAddr("203.0.113.7")

	l.Check(client, "c") // consumes the initial token
	got := []Action{l.Check(client, "c"), l.Check(client, "c"), l.Check(client, "c"), l.Check(client, "c")}
	// throttled sequence: drop, truncate, drop, truncate
	want := []Action{Drop, Truncate, Drop, Truncate}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("slip sequence[%d] = %v, want %v (%v)", i, got[i], want[i], got)
		}
	}
}

func TestSubnetAggregation(t *testing.T) {
	l := New(3, 15*time.Second, 0, 24, 56)
	now := time.Now()
	l.now = func() time.Time { return now }

	// Two addresses in the same /24 share one bucket.
	a := netip.MustParseAddr("203.0.113.1")
	b := netip.MustParseAddr("203.0.113.250")
	l.Check(a, "c")
	l.Check(b, "c")
	l.Check(a, "c")
	if act := l.Check(b, "c"); act != Drop {
		t.Fatalf("a spoofed /24 must share the cap, got %v", act)
	}
	// A different /24 has its own allowance.
	if act := l.Check(netip.MustParseAddr("198.51.100.1"), "c"); act != Pass {
		t.Fatalf("a different subnet must pass, got %v", act)
	}
}

func TestCategorySeparation(t *testing.T) {
	l := New(1, 15*time.Second, 0, 24, 56)
	now := time.Now()
	l.now = func() time.Time { return now }
	client := netip.MustParseAddr("203.0.113.7")

	l.Check(client, "A|example.com")
	// A different category (qname/qtype/rcode) is a separate bucket.
	if act := l.Check(client, "AAAA|example.com"); act != Pass {
		t.Fatalf("distinct category must pass, got %v", act)
	}
}

func TestIPv6Prefix(t *testing.T) {
	l := New(1, 15*time.Second, 0, 24, 56)
	now := time.Now()
	l.now = func() time.Time { return now }

	a := netip.MustParseAddr("2001:db8:abcd:1::1")
	b := netip.MustParseAddr("2001:db8:abcd:1:ffff::9") // same /56
	l.Check(a, "c")
	if act := l.Check(b, "c"); act != Drop {
		t.Fatalf("same /56 must share the bucket, got %v", act)
	}
}
