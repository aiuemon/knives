// Package stats implements click-event ingestion and daily rollup
// aggregation (docs/architecture.md 6節-4,5): cmd/worker reads raw click
// events off the Redis Stream cmd/redirect pushes to, and this package
// turns them into durable click_events rows plus an incremental
// click_stats_daily count — the write side of statistics. Permission-gated
// reading of those tables for the admin UI is a separate, not-yet-built
// concern (4節).
package stats

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// ClickEvent is one parsed entry from the Redis Stream "clicks" (6節-4),
// pushed asynchronously by cmd/redirect after each redirect response.
type ClickEvent struct {
	// StreamID is the Redis Stream entry ID (e.g. "1691568000000-0"),
	// unique within the stream. It doubles as this event's idempotency
	// key (6節-5): at-least-once delivery means the same entry can be
	// read more than once, and Store.InsertClickEvent must silently
	// no-op on a StreamID it has already recorded.
	StreamID     string
	ShortURLID   uuid.UUID
	ClickedAt    time.Time
	ReferrerHost string
	UserAgentRaw string
	IPHash       string
}

// Store is the persistence port RecordBatch depends on.
type Store interface {
	// InsertClickEvent inserts one click_events row. inserted is false
	// (with a nil error) when ev.StreamID was already recorded — the
	// at-least-once redelivery case (6節-5) — so callers can avoid
	// double-counting it in the daily rollup.
	InsertClickEvent(ctx context.Context, ev ClickEvent) (inserted bool, err error)
	// UpsertDailyCount adds delta to click_stats_daily's running total
	// for (shortURLID, date), creating the row if it doesn't exist yet.
	// date must already be truncated to a calendar day.
	UpsertDailyCount(ctx context.Context, shortURLID uuid.UUID, date time.Time, delta int) error
}

// Recorder turns a batch of raw click events into durable click_events
// rows plus an incremental click_stats_daily rollup (6節-5).
//
// RecordBatch deliberately doesn't wrap the whole batch in one
// transaction: idempotency is enforced per-event via StreamID, and the
// daily delta is computed only from events this call actually inserted,
// so a crash partway through a batch just defers the remainder to the
// next redelivery rather than corrupting or double-counting anything.
type Recorder struct {
	Store Store
}

// RecordBatch persists events, then upserts click_stats_daily once per
// (short_url_id, date) pair actually touched by this batch.
func (r *Recorder) RecordBatch(ctx context.Context, events []ClickEvent) error {
	type dailyKey struct {
		ShortURLID uuid.UUID
		Date       time.Time
	}
	deltas := make(map[dailyKey]int)

	for _, ev := range events {
		inserted, err := r.Store.InsertClickEvent(ctx, ev)
		if err != nil {
			return err
		}
		if !inserted {
			continue
		}
		key := dailyKey{ShortURLID: ev.ShortURLID, Date: ev.ClickedAt.UTC().Truncate(24 * time.Hour)}
		deltas[key]++
	}

	for key, delta := range deltas {
		if err := r.Store.UpsertDailyCount(ctx, key.ShortURLID, key.Date, delta); err != nil {
			return err
		}
	}
	return nil
}
