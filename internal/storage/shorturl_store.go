package storage

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/aiuemon/knives/internal/shorturl"
)

const uniqueViolationCode = "23505"

// txBeginner is the subset of *pgxpool.Pool that ShortURLStore needs: it
// must run InsertShortURL and InsertURLPermission in one transaction, since
// a short URL must never exist without its owner grant (4.2節).
type txBeginner interface {
	DBTX
	Begin(ctx context.Context) (pgx.Tx, error)
}

type ShortURLStore struct {
	pool txBeginner
}

var _ shorturl.Store = (*ShortURLStore)(nil)

func NewShortURLStore(pool txBeginner) *ShortURLStore {
	return &ShortURLStore{pool: pool}
}

func (s *ShortURLStore) ShortCodeSettings(ctx context.Context) (charset string, length int, err error) {
	row, err := New(s.pool).FindShortCodeSettings(ctx)
	if err != nil {
		return "", 0, err
	}
	return row.Charset, int(row.Length), nil
}

func (s *ShortURLStore) CreateShortURL(ctx context.Context, in shorturl.ShortURL) (*shorturl.ShortURL, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once Commit has succeeded

	q := New(tx)

	id, err := q.InsertShortURL(ctx, InsertShortURLParams{
		DomainID:    in.DomainID,
		ShortCode:   in.ShortCode,
		LongUrl:     in.LongURL,
		Title:       textOrNull(in.Title),
		Description: textOrNull(in.Description),
		CreatedBy:   in.CreatedBy,
		Status:      ShortUrlStatus(in.Status),
		ExpiresAt:   timestamptzOrNull(in.ExpiresAt),
		Source:      ShortUrlSource(in.Source),
	})
	if err != nil {
		if isUniqueViolation(err) {
			return nil, shorturl.ErrCodeCollision
		}
		return nil, err
	}

	// 作成者を自動的にownerとする(4.2節)。
	if err := q.InsertURLPermission(ctx, InsertURLPermissionParams{
		ShortUrlID: id,
		UserID:     in.CreatedBy,
		Role:       UrlPermissionRoleOwner,
		GrantedBy:  in.CreatedBy,
	}); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	result := in
	result.ID = id
	return &result, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == uniqueViolationCode
}

func textOrNull(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

func timestamptzOrNull(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}
