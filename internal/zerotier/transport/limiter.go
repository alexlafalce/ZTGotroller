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
	helloLimiterSlots    = 1 << 14
)

type helloBucket struct {
	tokens   float64
	observed time.Time
}

type helloLimiter struct {
	mu      sync.Mutex
	buckets [helloLimiterSlots]helloBucket
}

func newHelloLimiter() *helloLimiter {
	return &helloLimiter{}
}

func (limiter *helloLimiter) allow(address netip.Addr, now time.Time) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	index := helloRateGateHash(address)
	bucket := limiter.buckets[index]
	if bucket.observed.IsZero() || now.Sub(bucket.observed) >= limiterCleanupAfter {
		bucket = helloBucket{tokens: helloBurst, observed: now}
	} else if elapsed := now.Sub(bucket.observed).Seconds(); elapsed > 0 {
		bucket.tokens += elapsed * helloRefillPerSecond
		if bucket.tokens > helloBurst {
			bucket.tokens = helloBurst
		}
		bucket.observed = now
	}
	if bucket.tokens < 1 {
		limiter.buckets[index] = bucket
		return false
	}
	bucket.tokens--
	limiter.buckets[index] = bucket
	return true
}

// helloRateGateHash deliberately groups IPv4 /24 and IPv6 /48 prefixes into a
// fixed table. Untrusted source addresses can cause collisions, but can never
// grow controller memory.
func helloRateGateHash(address netip.Addr) uint16 {
	if !address.IsValid() {
		return 0
	}
	address = address.Unmap()
	value := address.As16()
	length := 6
	start := 0
	if address.Is4() {
		length = 3
		start = 12
	}
	hash := uint32(2166136261)
	for _, octet := range value[start : start+length] {
		hash ^= uint32(octet)
		hash *= 16777619
	}
	return uint16(hash & (helloLimiterSlots - 1))
}
