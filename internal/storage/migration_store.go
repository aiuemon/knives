package storage

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// ErrMigratedShortURLAlreadyExists is returned by
// MigrationStore.InsertMigratedShortURL when (domain_id, short_code)
// already exists — either a genuine keyword collision, or (more likely in
// practice) cmd/migrate-yourls being re-run over data it already migrated.
// Either way the caller should skip this row rather than fail the whole
// batch, which is what makes re-running the CLI safe (10節).
var ErrMigratedShortURLAlreadyExists = errors.New("storage: short_code already exists")

// MigratedShortURLInput is the caller-supplied part of one migrated row.
type MigratedShortURLInput struct {
	DomainID  uuid.UUID
	ShortCode string
	LongURL   string
	Title     string
	CreatedBy uuid.UUID
	// CreatedAt is carried over from YOURLS' own timestamp column, rather
	// than defaulting to the migration run's now() — cmd/migrate-yourls
	// treats it as historical data, not newly-created data.
	CreatedAt time.Time
}

// MigrationStore is the persistence port cmd/migrate-yourls depends on
// (10節). It's deliberately separate from ShortURLStore/PermissionStore:
// its queries encode migration-only assumptions (fixed status/source,
// caller-supplied created_at, overwrite-not-add stats) that the running
// services must never do.
type MigrationStore struct {
	Q Querier
}

func NewMigrationStore(db DBTX) *MigrationStore {
	return &MigrationStore{Q: New(db)}
}

// InsertMigratedShortURL inserts one short_urls row with
// source='yourls_import' and status='active'. Returns
// ErrMigratedShortURLAlreadyExists on a (domain_id, short_code) collision.
func (s *MigrationStore) InsertMigratedShortURL(ctx context.Context, in MigratedShortURLInput) (uuid.UUID, error) {
	id, err := s.Q.InsertMigratedShortURL(ctx, InsertMigratedShortURLParams{
		DomainID:  in.DomainID,
		ShortCode: in.ShortCode,
		LongUrl:   in.LongURL,
		Title:     textOrNull(in.Title),
		CreatedBy: in.CreatedBy,
		CreatedAt: pgtype.Timestamptz{Time: in.CreatedAt, Valid: true},
	})
	if isUniqueViolation(err) {
		return uuid.Nil, ErrMigratedShortURLAlreadyExists
	}
	return id, err
}

// GrantOwner grants userID the owner role on shortURLID, attributed to
// grantedBy (the migration system user) — mirrors ShortURLStore.
// CreateShortURL's owner grant, but as a standalone call since migration
// inserts the short_url and resolves its owner (possibly a different user
// than created_by) in separate steps.
func (s *MigrationStore) GrantOwner(ctx context.Context, shortURLID, userID, grantedBy uuid.UUID) error {
	return s.Q.InsertURLPermission(ctx, InsertURLPermissionParams{
		ShortUrlID: shortURLID,
		UserID:     userID,
		Role:       UrlPermissionRoleOwner,
		GrantedBy:  grantedBy,
	})
}

// SetClickStatsTotal records total as shortURLID's cumulative click count
// as of date, overwriting (not adding to) any existing value for that day
// — see SetMigratedClickStatsDaily's doc comment for why.
func (s *MigrationStore) SetClickStatsTotal(ctx context.Context, shortURLID uuid.UUID, date time.Time, total int64) error {
	return s.Q.SetMigratedClickStatsDaily(ctx, SetMigratedClickStatsDailyParams{
		ShortUrlID: shortURLID,
		Date:       pgtype.Date{Time: date, Valid: true},
		ClickCount: total,
	})
}
