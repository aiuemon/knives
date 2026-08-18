package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aiuemon/knives/internal/stats"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// ClickEventStore adapts the sqlc-generated Queries to the stats.Store
// port, and additionally manages click_events' monthly partitions —
// DDL sqlc can't express, since partition table names are generated, not
// static (0001_init.up.sql's comment: 運用開始後はworkerが月次パーティション
// を先行作成する).
type ClickEventStore struct {
	Q    Querier
	pool DBTX
}

var _ stats.Store = (*ClickEventStore)(nil)

func NewClickEventStore(db DBTX) *ClickEventStore {
	return &ClickEventStore{Q: New(db), pool: db}
}

func (s *ClickEventStore) InsertClickEvent(ctx context.Context, ev stats.ClickEvent) (bool, error) {
	_, err := s.Q.InsertClickEvent(ctx, InsertClickEventParams{
		ShortUrlID:   ev.ShortURLID,
		ClickedAt:    toTimestamptz(ev.ClickedAt),
		ReferrerHost: textOrNull(ev.ReferrerHost),
		UserAgentRaw: textOrNull(ev.UserAgentRaw),
		IpHash:       textOrNull(ev.IPHash),
		CountryCode:  textOrNull(ev.CountryCode),
		Os:           textOrNull(ev.OS),
		Browser:      textOrNull(ev.Browser),
		StreamID:     ev.StreamID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// ON CONFLICT DO NOTHING対象(6節-5: 同一StreamIDの再配送)。
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *ClickEventStore) UpsertDailyCount(ctx context.Context, shortURLID uuid.UUID, date time.Time, delta int) error {
	return s.Q.UpsertClickStatsDaily(ctx, UpsertClickStatsDailyParams{
		ShortUrlID: shortURLID,
		Date:       pgtype.Date{Time: date, Valid: true},
		ClickCount: int64(delta),
	})
}

// EnsurePartition creates click_events' partition covering forMonth if it
// doesn't already exist (idempotent — safe to call repeatedly). Table
// names and the FOR VALUES bounds can't be bind parameters in a CREATE
// TABLE statement (pgx returns "mismatched param and argument count" if
// attempted), so this bypasses sqlc entirely. forMonth is always
// caller-controlled (never user input) and only ever contributes plain
// integer year/month components to the SQL text, so string interpolation
// here carries no injection risk.
func (s *ClickEventStore) EnsurePartition(ctx context.Context, forMonth time.Time) error {
	monthStart := time.Date(forMonth.Year(), forMonth.Month(), 1, 0, 0, 0, 0, time.UTC)
	monthEnd := monthStart.AddDate(0, 1, 0)
	partitionName := fmt.Sprintf("click_events_%04d_%02d", monthStart.Year(), monthStart.Month())

	sql := fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS %s PARTITION OF click_events FOR VALUES FROM ('%s') TO ('%s')`,
		pgx.Identifier{partitionName}.Sanitize(),
		monthStart.Format("2006-01-02"),
		monthEnd.Format("2006-01-02"),
	)
	_, err := s.pool.Exec(ctx, sql)
	return err
}
