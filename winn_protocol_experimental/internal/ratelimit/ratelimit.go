package ratelimit

import (
	"errors"
	"math"
	"sync"
	"time"
)

type Limiter interface {
	Allow(string) (bool, time.Duration)
}

type BucketLimiter struct {
	mu         sync.Mutex
	capacity   float64
	refillRate float64
	maxKeys    int
	idleExpiry time.Duration
	now        func() time.Time
	buckets    map[string]*bucket
}

type bucket struct {
	tokens   float64
	updated  time.Time
	lastSeen time.Time
}

func New(capacity int, refillPerMinute float64, maxKeys int) (*BucketLimiter, error) {
	if capacity < 1 {
		return nil, errors.New("rate-limit capacity must be positive")
	}
	if refillPerMinute <= 0 || math.IsNaN(refillPerMinute) || math.IsInf(refillPerMinute, 0) {
		return nil, errors.New("rate-limit refill must be finite and positive")
	}
	if maxKeys < 1 {
		return nil, errors.New("rate-limit maximum key count must be positive")
	}
	return &BucketLimiter{
		capacity:   float64(capacity),
		refillRate: refillPerMinute / 60,
		maxKeys:    maxKeys,
		idleExpiry: 15 * time.Minute,
		now:        time.Now,
		buckets:    make(map[string]*bucket),
	}, nil
}

func (l *BucketLimiter) Allow(key string) (bool, time.Duration) {
	if key == "" {
		return false, time.Minute
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	entry, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			l.prune(now)
			if len(l.buckets) >= l.maxKeys {
				return false, time.Minute
			}
		}
		entry = &bucket{tokens: l.capacity, updated: now, lastSeen: now}
		l.buckets[key] = entry
	}
	elapsed := now.Sub(entry.updated).Seconds()
	if elapsed > 0 {
		entry.tokens = math.Min(l.capacity, entry.tokens+elapsed*l.refillRate)
		entry.updated = now
	}
	entry.lastSeen = now
	if entry.tokens >= 1 {
		entry.tokens--
		return true, 0
	}
	waitSeconds := (1 - entry.tokens) / l.refillRate
	if waitSeconds < 1 {
		waitSeconds = 1
	}
	return false, time.Duration(math.Ceil(waitSeconds)) * time.Second
}

func (l *BucketLimiter) prune(now time.Time) {
	for key, entry := range l.buckets {
		if now.Sub(entry.lastSeen) > l.idleExpiry {
			delete(l.buckets, key)
		}
	}
}
