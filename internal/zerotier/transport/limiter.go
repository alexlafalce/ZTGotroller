package transport

import (
	"net/netip"
	"sync"
	"time"
)

const (
	helloBurst           = 4.0
	helloRefillPerSecond = 1.0
	limiterCleanupAfter  = 10 * time.Minute
)

type helloBucket struct {
	tokens   float64
	observed time.Time
}

type helloLimiter struct {
	mu      sync.Mutex
	buckets map[netip.Addr]helloBucket
}

func newHelloLimiter() *helloLimiter {
	return &helloLimiter{buckets: make(map[netip.Addr]helloBucket)}
}

func (limiter *helloLimiter) allow(address netip.Addr, now time.Time) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	bucket, exists := limiter.buckets[address]
	if !exists || now.Sub(bucket.observed) >= limiterCleanupAfter {
		bucket = helloBucket{tokens: helloBurst, observed: now}
	} else if elapsed := now.Sub(bucket.observed).Seconds(); elapsed > 0 {
		bucket.tokens += elapsed * helloRefillPerSecond
		if bucket.tokens > helloBurst {
			bucket.tokens = helloBurst
		}
		bucket.observed = now
	}
	if bucket.tokens < 1 {
		limiter.buckets[address] = bucket
		return false
	}
	bucket.tokens--
	limiter.buckets[address] = bucket
	return true
}
