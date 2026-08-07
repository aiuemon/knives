package cache_test

import (
	"context"
	"testing"
	"time"

	"github.com/aiuemon/knives/internal/cache"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

// setupRedis starts a real Redis container so these tests exercise the
// actual cache-aside and Pub/Sub behavior, not a fake. It skips (not
// fails) when no container runtime is reachable.
func setupRedis(t *testing.T) *redis.Client {
	t.Helper()
	ctx := context.Background()

	container, err := tcredis.Run(ctx, "redis:7-alpine")
	if err != nil {
		t.Skipf("redis testcontainer unavailable in this environment: %v", err)
	}
	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(container); err != nil {
			t.Logf("failed to terminate redis container: %v", err)
		}
	})

	connStr, err := container.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	opts, err := redis.ParseURL(connStr)
	if err != nil {
		t.Fatalf("parse redis url: %v", err)
	}
	return redis.NewClient(opts)
}

func TestCache_LocalTierServesAfterRedisKeyRemoved(t *testing.T) {
	client := setupRedis(t)
	c, err := cache.New(cache.Config{Redis: client, InvalidationChannel: "test:invalidate"})
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	ctx := context.Background()

	if err := c.Set(ctx, "abc123", "https://example.com", 0); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Redisから直接削除しても、ローカル層がまだ生きていればGetは応答できる
	// (cache-asideのローカルヒット優先を検証する)。
	if err := client.Del(ctx, "abc123").Err(); err != nil {
		t.Fatalf("redis Del: %v", err)
	}

	val, ok, err := c.Get(ctx, "abc123")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok || val != "https://example.com" {
		t.Fatalf("expected a local-tier hit despite the Redis eviction, got ok=%v val=%q", ok, val)
	}
}

func TestCache_Invalidate_ClearsRedisAndLocal(t *testing.T) {
	client := setupRedis(t)
	c, err := cache.New(cache.Config{Redis: client, InvalidationChannel: "test:invalidate"})
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	ctx := context.Background()

	if err := c.Set(ctx, "xyz789", "https://example.com/xyz", 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := c.Invalidate(ctx, "xyz789"); err != nil {
		t.Fatalf("Invalidate: %v", err)
	}

	if _, ok, err := c.Get(ctx, "xyz789"); err != nil || ok {
		t.Fatalf("expected a miss after Invalidate, got ok=%v err=%v", ok, err)
	}
}

func TestCache_Subscribe_EvictsOtherInstancesLocalTier(t *testing.T) {
	client := setupRedis(t)
	channel := "test:invalidate:cross-instance"

	writer, err := cache.New(cache.Config{Redis: client, InvalidationChannel: channel})
	if err != nil {
		t.Fatalf("cache.New writer: %v", err)
	}
	reader, err := cache.New(cache.Config{Redis: client, InvalidationChannel: channel})
	if err != nil {
		t.Fatalf("cache.New reader: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = reader.Subscribe(ctx) }()

	// writer.Setはredisにしか反映されないので、readerのローカル層には
	// readerが自分でSetして仕込む。
	if err := reader.Set(ctx, "shared-key", "https://example.com/shared", 0); err != nil {
		t.Fatalf("reader Set: %v", err)
	}

	// Subscribeのgoroutineが購読を確立するタイミングは観測できないため、
	// 「evictされるまでInvalidateを再送する」リトライで待つ(固定sleep一発
	// より、遅いCI環境でも決め打ちのタイムアウト値に依存しにくい)。
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := writer.Invalidate(ctx, "shared-key"); err != nil {
			t.Fatalf("writer Invalidate: %v", err)
		}
		if _, ok, err := reader.Get(ctx, "shared-key"); err != nil {
			t.Fatalf("reader Get: %v", err)
		} else if !ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("reader's local tier was never evicted via Subscribe within the timeout")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
