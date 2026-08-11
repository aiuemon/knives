package main

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"

	"github.com/aiuemon/knives/internal/stats"
)

// setupRedis starts a real Redis container, mirroring
// internal/auth/session_integration_test.go's helper. Skips (not fails)
// when no container runtime is reachable.
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

type fakeStatsStore struct {
	inserted map[string]stats.ClickEvent
}

func newFakeStatsStore() *fakeStatsStore {
	return &fakeStatsStore{inserted: map[string]stats.ClickEvent{}}
}

func (s *fakeStatsStore) InsertClickEvent(_ context.Context, ev stats.ClickEvent) (bool, error) {
	if _, exists := s.inserted[ev.StreamID]; exists {
		return false, nil
	}
	s.inserted[ev.StreamID] = ev
	return true, nil
}

func (s *fakeStatsStore) UpsertDailyCount(context.Context, uuid.UUID, time.Time, int) error {
	return nil
}

func pushRawClickEvent(t *testing.T, client *redis.Client, shortURLID uuid.UUID) string {
	t.Helper()
	id, err := client.XAdd(context.Background(), &redis.XAddArgs{
		Stream: clickStreamName,
		Values: map[string]any{
			"short_url_id":  shortURLID.String(),
			"clicked_at":    time.Now().UTC().Format(time.RFC3339Nano),
			"referrer_host": "example.com",
			"user_agent":    "test-agent",
			"ip_hash":       "hash-1",
		},
	}).Result()
	if err != nil {
		t.Fatalf("XAdd: %v", err)
	}
	return id
}

func TestClickConsumer_ProcessesAndAcksNewEntries(t *testing.T) {
	client := setupRedis(t)
	ctx := context.Background()
	shortURLID := uuid.New()

	entryID := pushRawClickEvent(t, client, shortURLID)

	store := newFakeStatsStore()
	c := &clickConsumer{
		redis: client, recorder: &stats.Recorder{Store: store},
		consumerName: "test-consumer", batchSize: 10,
		blockTimeout: 200 * time.Millisecond, staleThreshold: time.Minute,
	}
	if err := c.ensureGroup(ctx); err != nil {
		t.Fatalf("ensureGroup: %v", err)
	}

	streams, err := client.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group: clickConsumerGroup, Consumer: c.consumerName,
		Streams: []string{clickStreamName, ">"}, Count: 10, Block: time.Second,
	}).Result()
	if err != nil {
		t.Fatalf("XReadGroup: %v", err)
	}
	if len(streams) != 1 || len(streams[0].Messages) != 1 {
		t.Fatalf("expected exactly one message, got %+v", streams)
	}
	c.processBatch(ctx, streams[0].Messages)

	if _, ok := store.inserted[entryID]; !ok {
		t.Fatalf("expected the entry to be recorded, got %+v", store.inserted)
	}

	pending, err := client.XPending(ctx, clickStreamName, clickConsumerGroup).Result()
	if err != nil {
		t.Fatalf("XPending: %v", err)
	}
	if pending.Count != 0 {
		t.Fatalf("expected the processed entry to be acked (0 pending), got %d", pending.Count)
	}
}

func TestClickConsumer_ReclaimsStaleEntriesFromADeadConsumer(t *testing.T) {
	client := setupRedis(t)
	ctx := context.Background()
	shortURLID := uuid.New()

	entryID := pushRawClickEvent(t, client, shortURLID)

	deadConsumer := &clickConsumer{
		redis: client, consumerName: "dead-consumer",
		batchSize: 10, blockTimeout: time.Second, staleThreshold: time.Millisecond,
	}
	if err := deadConsumer.ensureGroup(ctx); err != nil {
		t.Fatalf("ensureGroup: %v", err)
	}
	// このconsumerが読み取ったままACKせずに落ちた状況を再現する。
	if _, err := client.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group: clickConsumerGroup, Consumer: "dead-consumer",
		Streams: []string{clickStreamName, ">"}, Count: 10, Block: time.Second,
	}).Result(); err != nil {
		t.Fatalf("XReadGroup (dead consumer): %v", err)
	}

	time.Sleep(10 * time.Millisecond) // staleThresholdを確実に超えさせる

	store := newFakeStatsStore()
	rescuer := &clickConsumer{
		redis: client, recorder: &stats.Recorder{Store: store},
		consumerName: "rescuer", batchSize: 10,
		blockTimeout: time.Second, staleThreshold: time.Millisecond,
	}
	rescuer.reclaimStaleEntries(ctx)

	if _, ok := store.inserted[entryID]; !ok {
		t.Fatalf("expected the stale entry to be reclaimed and recorded, got %+v", store.inserted)
	}

	pending, err := client.XPending(ctx, clickStreamName, clickConsumerGroup).Result()
	if err != nil {
		t.Fatalf("XPending: %v", err)
	}
	if pending.Count != 0 {
		t.Fatalf("expected the reclaimed entry to be acked, got %d pending", pending.Count)
	}
}

func TestClickConsumer_Run_StopsOnContextCancellation(t *testing.T) {
	client := setupRedis(t)
	ctx, cancel := context.WithCancel(context.Background())

	c := &clickConsumer{
		redis: client, recorder: &stats.Recorder{Store: newFakeStatsStore()},
		consumerName: "test-consumer", batchSize: 10,
		blockTimeout: 100 * time.Millisecond, staleThreshold: time.Minute,
	}

	done := make(chan error, 1)
	go func() { done <- c.run(ctx) }()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected run to return nil on cancellation, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("expected run to stop shortly after context cancellation")
	}
}
