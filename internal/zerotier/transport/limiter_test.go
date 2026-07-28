package transport

import (
	"net/netip"
	"testing"
	"time"
)

func TestHelloLimiterBurstAndRefill(t *testing.T) {
	limiter := newHelloLimiter()
	address := netip.MustParseAddr("192.0.2.1")
	now := time.Unix(1_700_000_000, 0)
	for count := 0; count < int(helloBurst); count++ {
		if !limiter.allow(address, now) {
			t.Fatalf("burst request %d was rejected", count)
		}
	}
	if limiter.allow(address, now) {
		t.Fatal("request beyond burst was accepted")
	}
	if !limiter.allow(address, now.Add(time.Second)) {
		t.Fatal("one token was not refilled")
	}
}

func TestHelloLimiterUsesFixedPrefixBuckets(t *testing.T) {
	limiter := newHelloLimiter()
	now := time.Unix(1_700_000_000, 0)
	for count := 0; count < int(helloBurst); count++ {
		if !limiter.allow(netip.MustParseAddr("192.0.2.1"), now) {
			t.Fatal("prefix burst was rejected")
		}
	}
	if limiter.allow(netip.MustParseAddr("192.0.2.254"), now) {
		t.Fatal("IPv4 addresses in the same /24 did not share a bucket")
	}
	if len(limiter.buckets) != helloLimiterSlots {
		t.Fatalf("bucket count = %d, want %d", len(limiter.buckets), helloLimiterSlots)
	}
}
