package stats

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// maxRangeDays bounds how wide a from/to window callers may query.
// click_events has no retention limit (2.2節: 無期限保存), so an unbounded
// range would let a single request scan an unbounded number of monthly
// partitions; API handlers should reject anything wider than this before
// it ever reaches the Reader.
const maxRangeDays = 366

var (
	// ErrInvalidRange is returned by GetStats when to is before from, or
	// the range exceeds maxRangeDays.
	ErrInvalidRange = errors.New("stats: invalid from/to range")
)

// DailyCount is one row of click_stats_daily (2.2節) for a short URL.
type DailyCount struct {
	Date       time.Time
	ClickCount int64
}

// ReferrerCount is the click total for one referrer host over a queried
// range, aggregated live from click_events.referrer_host (2.2節) since
// there is no referrer-level rollup table. ReferrerHost is "" for clicks
// with no referrer (direct access).
type ReferrerCount struct {
	ReferrerHost string
	ClickCount   int64
}

// Summary is what GetStats returns: a short URL's click activity over one
// [From, To] range, broken down by day and by referrer.
type Summary struct {
	From       time.Time
	To         time.Time
	Daily      []DailyCount
	ByReferrer []ReferrerCount
}

// Reader is the persistence port GetStats depends on. Permission-gating
// (4.2節: owner/editor/viewerまたはsystem_adminのみ) is the caller's
// responsibility (cmd/api's resolveAccess) — Reader itself trusts
// shortURLID unconditionally, same division of responsibility as
// shorturl.Store.
type Reader interface {
	// DailyCounts returns click_stats_daily rows for shortURLID with date
	// in the half-open range [from, to), ordered by date ascending.
	DailyCounts(ctx context.Context, shortURLID uuid.UUID, from, to time.Time) ([]DailyCount, error)
	// ReferrerCounts returns click_events aggregated by referrer_host for
	// shortURLID with clicked_at in the half-open range [from, to),
	// ordered by click count descending.
	ReferrerCounts(ctx context.Context, shortURLID uuid.UUID, from, to time.Time) ([]ReferrerCount, error)
}

type Service struct {
	Reader Reader
}

// GetStats validates the requested range and returns shortURLID's daily
// and per-referrer click activity within it.
func (s *Service) GetStats(ctx context.Context, shortURLID uuid.UUID, from, to time.Time) (*Summary, error) {
	if to.Before(from) || to.Sub(from) > maxRangeDays*24*time.Hour {
		return nil, ErrInvalidRange
	}

	daily, err := s.Reader.DailyCounts(ctx, shortURLID, from, to)
	if err != nil {
		return nil, err
	}
	referrers, err := s.Reader.ReferrerCounts(ctx, shortURLID, from, to)
	if err != nil {
		return nil, err
	}

	return &Summary{From: from, To: to, Daily: daily, ByReferrer: referrers}, nil
}
