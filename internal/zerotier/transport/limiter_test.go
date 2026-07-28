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
