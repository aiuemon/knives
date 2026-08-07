package main

import (
	"context"
	"testing"
	"time"
)

func TestIPRateLimiter_AllowsUpToBurstThenBlocks(t *testing.T) {
	limiter := newIPRateLimiter(1, 3) // 低いrpsでburstだけを使い切らせる

	for i := 0; i < 3; i++ {
		if !limiter.allow("1.2.3.4") {
			t.Fatalf("request %d within burst should be allowed", i)
		}
	}
	if limiter.allow("1.2.3.4") {
		t.Fatalf("request beyond burst should be blocked")
	}
}

func TestIPRateLimiter_TracksEachIPIndependently(t *testing.T) {
	limiter := newIPRateLimiter(1, 1)

	if !limiter.allow("1.1.1.1") {
		t.Fatalf("first IP's first request should be allowed")
	}
	if !limiter.allow("2.2.2.2") {
		t.Fatalf("a different IP must not share the first IP's bucket")
	}
	if limiter.allow("1.1.1.1") {
		t.Fatalf("first IP should now be rate-limited")
	}
}

func TestIPRateLimiter_CleanupLoopEvictsIdleEntries(t *testing.T) {
	limiter := newIPRateLimiter(1, 1)
	limiter.allow("3.3.3.3")

	ctx, cancel := context.WithCancel(context.Background())
	go limiter.cleanupLoop(ctx, 10*time.Millisecond, 20*time.Millisecond)
	defer cancel()

	deadline := time.Now().Add(2 * time.Second)
	for {
		limiter.mu.Lock()
		_, exists := limiter.limiters["3.3.3.3"]
		limiter.mu.Unlock()
		if !exists {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("idle limiter entry was never evicted by cleanupLoop")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
