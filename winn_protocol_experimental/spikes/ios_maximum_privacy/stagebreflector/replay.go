package stagebreflector

import "sync"

// MaxReplayCacheCapacity is a hard allocation and cardinality bound for every
// request or response replay cache.
const MaxReplayCacheCapacity = 4096

// ReplayCache is a concurrency-safe, bounded, fail-closed single-use cache.
// Entries are removed only when now is strictly later than their expiry. Its
// clock watermark never decreases; callers cannot roll time back after
// pruning to make an old tag acceptable again.
type ReplayCache struct {
	mu           sync.Mutex
	capacity     int
	entries      map[[TagLength]byte]uint64
	watermark    uint64
	hasWatermark bool
}

func NewReplayCache(capacity int) (*ReplayCache, error) {
	if capacity <= 0 || capacity > MaxReplayCacheCapacity {
		return nil, ErrCacheCapacity
	}
	return &ReplayCache{
		capacity: capacity,
		entries:  make(map[[TagLength]byte]uint64, capacity),
	}, nil
}

// Use records tag if it has not previously been used. Expired entries are
// removed before the capacity decision, but never at their exact expiry.
func (cache *ReplayCache) Use(tag [TagLength]byte, expiresAt, now uint64) error {
	if cache == nil {
		return ErrReplay
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()

	if cache.hasWatermark && now < cache.watermark {
		return ErrClockRollback
	}
	cache.watermark = now
	cache.hasWatermark = true
	if _, exists := cache.entries[tag]; exists {
		return ErrReplay
	}
	if now > expiresAt {
		return ErrClock
	}
	for cachedTag, cachedExpiry := range cache.entries {
		if now > cachedExpiry {
			delete(cache.entries, cachedTag)
		}
	}
	if len(cache.entries) >= cache.capacity {
		return ErrCacheFull
	}
	cache.entries[tag] = expiresAt
	return nil
}

func (cache *ReplayCache) Len() int {
	if cache == nil {
		return 0
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return len(cache.entries)
}
