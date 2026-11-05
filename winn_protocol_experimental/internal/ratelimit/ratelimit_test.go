package ratelimit

import (
	"testing"
	"time"
)

func TestTokenBucketRefillAndIsolation(t *testing.T) {
	limiter, err := New(2, 60, 10)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	limiter.now = func() time.Time { return now }
	if allowed, _ := limiter.Allow("device-a"); !allowed {
		t.Fatal("first request rejected")
	}
	if allowed, _ := limiter.Allow("device-a"); !allowed {
		t.Fatal("second request rejected")
	}
	if allowed, retry := limiter.Allow("device-a"); allowed || retry != time.Second {
		t.Fatalf("exhausted bucket allowed=%v retry=%s", allowed, retry)
	}
	if allowed, _ := limiter.Allow("device-b"); !allowed {
		t.Fatal("independent device bucket was exhausted")
	}
	now = now.Add(time.Second)
	if allowed, _ := limiter.Allow("device-a"); !allowed {
		t.Fatal("token did not refill")
	}
}

func TestLimiterBoundsAttackerControlledKeys(t *testing.T) {
	limiter, err := New(1, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	limiter.now = func() time.Time { return now }
	limiter.idleExpiry = time.Minute
	if allowed, _ := limiter.Allow("one"); !allowed {
		t.Fatal("first key rejected")
	}
	if allowed, _ := limiter.Allow("two"); !allowed {
		t.Fatal("second key rejected")
	}
	if allowed, _ := limiter.Allow("three"); allowed {
		t.Fatal("third key bypassed maximum key count")
	}
	now = now.Add(2 * time.Minute)
	if allowed, _ := limiter.Allow("three"); !allowed {
		t.Fatal("idle entries were not pruned")
	}
}
