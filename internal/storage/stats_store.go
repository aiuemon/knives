package storage

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/aiuemon/knives/internal/stats"
)

// StatsStore adapts the sqlc-generated stats queries to the stats.Reader
// port — the read side of statistics (4節), mirroring ClickEventStore's
// role as the write side.
type StatsStore struct {
	Q Querier
}

var _ stats.Reader = (*StatsStore)(nil)

func NewStatsStore(db DBTX) *StatsStore {
	return &StatsStore{Q: New(db)}
}

func (s *StatsStore) DailyCounts(ctx context.Context, shortURLID uuid.UUID, from, to time.Time) ([]stats.DailyCount, error) {
	rows, err := s.Q.FindDailyClickCounts(ctx, FindDailyClickCountsParams{
		ShortUrlID: shortURLID,
		Date:       pgtype.Date{Time: from, Valid: true},
		Date_2:     pgtype.Date{Time: to, Valid: true},
	})
	if err != nil {
		return nil, err
	}
	result := make([]stats.DailyCount, 0, len(rows))
	for _, row := range rows {
		result = append(result, stats.DailyCount{Date: row.Date.Time, ClickCount: row.ClickCount})
	}
	return result, nil
}

func (s *StatsStore) ReferrerCounts(ctx context.Context, shortURLID uuid.UUID, from, to time.Time) ([]stats.ReferrerCount, error) {
	rows, err := s.Q.FindReferrerClickCounts(ctx, FindReferrerClickCountsParams{
		ShortUrlID:  shortURLID,
		ClickedAt:   pgtype.Timestamptz{Time: from, Valid: true},
		ClickedAt_2: pgtype.Timestamptz{Time: to, Valid: true},
	})
	if err != nil {
		return nil, err
	}
	result := make([]stats.ReferrerCount, 0, len(rows))
	for _, row := range rows {
		result = append(result, stats.ReferrerCount{ReferrerHost: row.ReferrerHost, ClickCount: row.ClickCount})
	}
	return result, nil
}
