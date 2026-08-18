package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/aiuemon/knives/internal/stats"
	"github.com/aiuemon/knives/internal/useragent"
)

const (
	clickStreamName    = "clicks"
	clickConsumerGroup = "worker"
)

// clickConsumer reads the "clicks" Redis Stream via a consumer group and
// turns each batch into durable click_events rows plus an incremental
// click_stats_daily rollup (6節-4,5). at-least-once delivery is handled
// two ways: RecordBatch is itself idempotent per StreamID (see
// internal/stats), and any batch that fails to record is left unacked so
// reclaimStaleEntries retries it later rather than silently dropping it.
type clickConsumer struct {
	redis        *redis.Client
	recorder     *stats.Recorder
	consumerName string
	batchSize    int64
	blockTimeout time.Duration
	// staleThreshold is both how long a pending (unacked) entry must sit
	// idle before it's reclaimed for retry, and how often that sweep
	// runs — a worker that crashed mid-batch (or another instance that
	// died) leaves its in-flight entries pending under its own consumer
	// name until this claims them back.
	staleThreshold time.Duration
}

// run reads new entries and periodically reclaims stale pending ones.
// Returns nil when ctx is cancelled (graceful shutdown), not an error.
func (c *clickConsumer) run(ctx context.Context) error {
	if err := c.ensureGroup(ctx); err != nil {
		return fmt.Errorf("ensure consumer group: %w", err)
	}

	claimTicker := time.NewTicker(c.staleThreshold)
	defer claimTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-claimTicker.C:
			c.reclaimStaleEntries(ctx)
		default:
		}

		streams, err := c.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group:    clickConsumerGroup,
			Consumer: c.consumerName,
			Streams:  []string{clickStreamName, ">"},
			Count:    c.batchSize,
			Block:    c.blockTimeout,
		}).Result()
		switch {
		case errors.Is(err, context.Canceled):
			return nil
		case errors.Is(err, redis.Nil):
			continue // Block timed out with nothing new; loop and check ctx/ticker again.
		case err != nil:
			slog.Error("xreadgroup failed", "error", err)
			continue
		}

		for _, stream := range streams {
			c.processBatch(ctx, stream.Messages)
		}
	}
}

func (c *clickConsumer) ensureGroup(ctx context.Context) error {
	// "0" (not "$"): a first-ever run must process any backlog already on
	// the stream, not just entries that arrive after group creation.
	err := c.redis.XGroupCreateMkStream(ctx, clickStreamName, clickConsumerGroup, "0").Err()
	if err != nil && !strings.HasPrefix(err.Error(), "BUSYGROUP") {
		return err
	}
	return nil
}

// reclaimStaleEntries reassigns any pending entry idle for at least
// staleThreshold to this consumer and reprocesses it — crash recovery for
// a worker (this one or another instance) that read a batch but died
// before acking it.
func (c *clickConsumer) reclaimStaleEntries(ctx context.Context) {
	start := "0-0"
	for {
		messages, next, err := c.redis.XAutoClaim(ctx, &redis.XAutoClaimArgs{
			Stream:   clickStreamName,
			Group:    clickConsumerGroup,
			Consumer: c.consumerName,
			MinIdle:  c.staleThreshold,
			Start:    start,
			Count:    c.batchSize,
		}).Result()
		if err != nil {
			slog.Error("xautoclaim failed", "error", err)
			return
		}
		if len(messages) > 0 {
			slog.Warn("reclaiming stale pending click events", "count", len(messages))
			c.processBatch(ctx, messages)
		}
		if next == "0-0" || len(messages) == 0 {
			return
		}
		start = next
	}
}

func (c *clickConsumer) processBatch(ctx context.Context, messages []redis.XMessage) {
	if len(messages) == 0 {
		return
	}

	events := make([]stats.ClickEvent, 0, len(messages))
	// Every message ID is ACKed, even ones dropped as malformed: a
	// message that can never parse would otherwise poison the stream,
	// getting reclaimed and retried forever.
	ids := make([]string, 0, len(messages))
	for _, msg := range messages {
		ids = append(ids, msg.ID)
		ev, err := parseClickEvent(msg)
		if err != nil {
			slog.Error("dropping malformed click event", "id", msg.ID, "error", err)
			continue
		}
		events = append(events, ev)
	}

	if len(events) > 0 {
		if err := c.recorder.RecordBatch(ctx, events); err != nil {
			slog.Error("record batch failed; leaving unacked for retry", "error", err)
			return
		}
	}

	if err := c.redis.XAck(ctx, clickStreamName, clickConsumerGroup, ids...).Err(); err != nil {
		slog.Error("xack failed", "error", err)
	}
}

// parseClickEvent decodes one Stream entry into a stats.ClickEvent. Field
// names must match cmd/redirect's recordClickAsync exactly (6節-4).
func parseClickEvent(msg redis.XMessage) (stats.ClickEvent, error) {
	shortURLIDStr, _ := msg.Values["short_url_id"].(string)
	shortURLID, err := uuid.Parse(shortURLIDStr)
	if err != nil {
		return stats.ClickEvent{}, fmt.Errorf("invalid short_url_id: %w", err)
	}

	clickedAtStr, _ := msg.Values["clicked_at"].(string)
	clickedAt, err := time.Parse(time.RFC3339Nano, clickedAtStr)
	if err != nil {
		return stats.ClickEvent{}, fmt.Errorf("invalid clicked_at: %w", err)
	}

	referrerHost, _ := msg.Values["referrer_host"].(string)
	userAgentRaw, _ := msg.Values["user_agent"].(string)
	ipHash, _ := msg.Values["ip_hash"].(string)
	countryCode, _ := msg.Values["country_code"].(string)

	// UAの解析はここ(cmd/redirectのホットパスの外)で一度だけ行う(4節)。
	os, browser := useragent.Categorize(userAgentRaw)

	return stats.ClickEvent{
		StreamID:     msg.ID,
		ShortURLID:   shortURLID,
		ClickedAt:    clickedAt,
		ReferrerHost: referrerHost,
		UserAgentRaw: userAgentRaw,
		IPHash:       ipHash,
		CountryCode:  countryCode,
		OS:           os,
		Browser:      browser,
	}, nil
}
