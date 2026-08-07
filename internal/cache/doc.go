// Package cache abstracts the two-tier cache (Redis cache-aside + in-process
// ristretto LRU) used by cmd/redirect for the hot short_code -> long_url
// lookup path (see docs/architecture.md, 6節).
package cache
