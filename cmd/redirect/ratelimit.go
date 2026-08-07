package main

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ipRateLimiter is a process-local, per-IP token bucket (6節-0): no Redis
// round trip guards the cache lookup, at the cost of the effective limit
// being "configured value × instance count" in a multi-instance deployment.
type ipRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rateLimiterEntry
	rps      rate.Limit
	burst    int
}

type rateLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newIPRateLimiter(rps float64, burst int) *ipRateLimiter {
	return &ipRateLimiter{
		limiters: make(map[string]*rateLimiterEntry),
		rps:      rate.Limit(rps),
		burst:    burst,
	}
}

func (r *ipRateLimiter) allow(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.limiters[ip]
	if !ok {
		entry = &rateLimiterEntry{limiter: rate.NewLimiter(r.rps, r.burst)}
		r.limiters[ip] = entry
	}
	entry.lastSeen = time.Now()
	return entry.limiter.Allow()
}

// cleanupLoop evicts limiters idle longer than idleTimeout, so the map
// doesn't grow without bound as distinct client IPs accumulate over the
// process lifetime. It blocks until ctx is cancelled.
func (r *ipRateLimiter) cleanupLoop(ctx context.Context, interval, idleTimeout time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-idleTimeout)
			r.mu.Lock()
			for ip, entry := range r.limiters {
				if entry.lastSeen.Before(cutoff) {
					delete(r.limiters, ip)
				}
			}
			r.mu.Unlock()
		}
	}
}
