package cache

import (
	"context"
	"errors"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/redis/go-redis/v9"
)

// localTTL bounds how stale an in-process hit can be, independent of the
// Redis-side TTL, so a missed or delayed Invalidate() (6節-2の
// Pub/Sub伝播) can't leave a redirect instance serving a purged mapping
// indefinitely.
const localTTL = 30 * time.Second

// Cache is the two-tier cache-aside abstraction used by cmd/redirect for
// the short_code -> long_url hot path (6節): an in-process ristretto LRU
// in front of Redis, with PostgreSQL as the caller's own fallback on a
// full miss.
type Cache struct {
	local   *ristretto.Cache
	redis   *redis.Client
	channel string
}

type Config struct {
	Redis *redis.Client
	// InvalidationChannel is the Redis Pub/Sub channel Invalidate publishes
	// to, and Subscribe listens on, so every redirect instance's in-process
	// tier is evicted together (6節-2).
	InvalidationChannel string
}

func New(cfg Config) (*Cache, error) {
	local, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1e7,
		MaxCost:     1 << 28, // 256MiB of cached values, keyed by byte length
		BufferItems: 64,
	})
	if err != nil {
		return nil, err
	}
	return &Cache{local: local, redis: cfg.Redis, channel: cfg.InvalidationChannel}, nil
}

// Get resolves key from the in-process tier first, then Redis, populating
// the in-process tier on a Redis hit. It never touches PostgreSQL; callers
// own the DB fallback and should call Set to populate both tiers on it.
func (c *Cache) Get(ctx context.Context, key string) (value string, ok bool, err error) {
	if v, hit := c.local.Get(key); hit {
		return v.(string), true, nil
	}
	val, err := c.redis.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	c.local.SetWithTTL(key, val, int64(len(val)), localTTL)
	return val, true, nil
}

// Set writes through to both tiers. redisTTL of zero means no expiration in
// Redis: entries live until an explicit Invalidate (the purge-on-write
// model of 6節-2), not a timer.
func (c *Cache) Set(ctx context.Context, key, value string, redisTTL time.Duration) error {
	if err := c.redis.Set(ctx, key, value, redisTTL).Err(); err != nil {
		return err
	}
	c.local.SetWithTTL(key, value, int64(len(value)), localTTL)
	return nil
}

// Invalidate removes key from this instance's own tiers and publishes to
// InvalidationChannel so every other redirect instance evicts it from
// their in-process tier too (6節-2: 更新・削除時にAPIサービスがpurgeし、
// Pub/Subで伝播する).
func (c *Cache) Invalidate(ctx context.Context, key string) error {
	c.local.Del(key)
	if err := c.redis.Del(ctx, key).Err(); err != nil {
		return err
	}
	return c.redis.Publish(ctx, c.channel, key).Err()
}

// Subscribe listens for invalidation messages published by Invalidate
// (typically called from another instance, e.g. the api service after an
// edit) and evicts the corresponding key from this instance's in-process
// tier. It blocks until ctx is cancelled.
func (c *Cache) Subscribe(ctx context.Context) error {
	sub := c.redis.Subscribe(ctx, c.channel)
	defer sub.Close()

	ch := sub.Channel()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg, open := <-ch:
			if !open {
				return nil
			}
			c.local.Del(msg.Payload)
		}
	}
}
