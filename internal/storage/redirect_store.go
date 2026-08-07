package storage

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RedirectStore backs cmd/redirect's cache-miss fallback (6節): resolving
// the single default domain at startup, then short_code -> (id, long_url)
// lookups scoped to it.
type RedirectStore struct {
	Q Querier
}

func NewRedirectStore(db DBTX) *RedirectStore {
	return &RedirectStore{Q: New(db)}
}

func (s *RedirectStore) FindDefaultDomain(ctx context.Context) (uuid.UUID, error) {
	id, err := s.Q.FindDefaultDomain(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	return id, err
}

// FindRedirectTarget returns the short URL's id and long_url, but only if
// it is currently active and unexpired — an expired/disabled short_code
// must 404 like one that never existed.
func (s *RedirectStore) FindRedirectTarget(ctx context.Context, domainID uuid.UUID, shortCode string) (id uuid.UUID, longURL string, err error) {
	row, err := s.Q.FindRedirectTarget(ctx, FindRedirectTargetParams{DomainID: domainID, ShortCode: shortCode})
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", ErrNotFound
	}
	if err != nil {
		return uuid.Nil, "", err
	}
	return row.ID, row.LongUrl, nil
}
