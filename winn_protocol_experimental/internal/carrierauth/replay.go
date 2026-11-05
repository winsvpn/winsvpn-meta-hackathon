package carrierauth

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrReplay        = errors.New("carrier request replay detected")
	ErrReplayAtLimit = errors.New("carrier replay cache is at capacity")
)

type ReplayCache struct {
	mu      sync.Mutex
	limit   int
	entries map[string]time.Time
}

func NewReplayCache(limit int) (*ReplayCache, error) {
	if limit < 1 {
		return nil, errors.New("replay cache limit must be positive")
	}
	return &ReplayCache{
		limit:   limit,
		entries: make(map[string]time.Time, min(limit, 1024)),
	}, nil
}

// Use atomically consumes a nonce. Expired entries are removed before the hard
// limit is enforced, so unauthenticated input cannot grow memory without bound.
func (c *ReplayCache) Use(key string, expires, now time.Time) error {
	if c == nil {
		return errors.New("replay cache is nil")
	}
	if key == "" || !expires.After(now) {
		return errors.New("invalid replay cache entry")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.entries[key]; ok && existing.After(now) {
		return ErrReplay
	}
	delete(c.entries, key)
	if len(c.entries) >= c.limit {
		for candidate, expiry := range c.entries {
			if !expiry.After(now) {
				delete(c.entries, candidate)
			}
		}
	}
	if len(c.entries) >= c.limit {
		return ErrReplayAtLimit
	}
	c.entries[key] = expires
	return nil
}

func (c *ReplayCache) Len(now time.Time) int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, expiry := range c.entries {
		if !expiry.After(now) {
			delete(c.entries, key)
		}
	}
	return len(c.entries)
}
