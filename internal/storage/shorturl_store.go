package storage

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
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

func (s *ShortURLStore) FindByID(ctx context.Context, id uuid.UUID) (*shorturl.ShortURL, error) {
	row, err := New(s.pool).FindShortURLByID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, shorturl.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return toDomainShortURL(row), nil
}

func (s *ShortURLStore) ListForUser(ctx context.Context, userID uuid.UUID, page shorturl.ListPage) ([]*shorturl.ShortURL, error) {
	rows, err := New(s.pool).ListShortURLsForUser(ctx, ListShortURLsForUserParams{
		UserID: userID,
		Limit:  int32(page.Limit),
		Offset: int32(page.Offset),
	})
	if err != nil {
		return nil, err
	}
	return toDomainShortURLs(rows), nil
}

func (s *ShortURLStore) ListAll(ctx context.Context, page shorturl.ListPage) ([]*shorturl.ShortURL, error) {
	rows, err := New(s.pool).ListAllShortURLs(ctx, ListAllShortURLsParams{
		Limit:  int32(page.Limit),
		Offset: int32(page.Offset),
	})
	if err != nil {
		return nil, err
	}
	return toDomainShortURLs(rows), nil
}

func (s *ShortURLStore) UpdateFields(ctx context.Context, id uuid.UUID, in shorturl.UpdateInput) (*shorturl.ShortURL, error) {
	row, err := New(s.pool).UpdateShortURLFields(ctx, UpdateShortURLFieldsParams{
		ID:          id,
		LongUrl:     in.LongURL,
		Title:       textOrNull(in.Title),
		Description: textOrNull(in.Description),
		ExpiresAt:   timestamptzOrNull(in.ExpiresAt),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, shorturl.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return toDomainShortURL(row), nil
}

func (s *ShortURLStore) SetStatus(ctx context.Context, id uuid.UUID, status shorturl.Status) error {
	// generated SetShortURLStatus discards the command tag, but callers
	// need to know whether id actually existed, so issue it directly here.
	tag, err := s.pool.Exec(ctx, setShortURLStatus, id, ShortUrlStatus(status))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return shorturl.ErrNotFound
	}
	return nil
}

func toDomainShortURL(row *ShortUrl) *shorturl.ShortURL {
	var expiresAt *time.Time
	if row.ExpiresAt.Valid {
		t := row.ExpiresAt.Time
		expiresAt = &t
	}
	return &shorturl.ShortURL{
		ID:          row.ID,
		DomainID:    row.DomainID,
		ShortCode:   row.ShortCode,
		LongURL:     row.LongUrl,
		Title:       row.Title.String,
		Description: row.Description.String,
		CreatedBy:   row.CreatedBy,
		Status:      shorturl.Status(row.Status),
		ExpiresAt:   expiresAt,
		Source:      shorturl.Source(row.Source),
	}
}

func toDomainShortURLs(rows []*ShortUrl) []*shorturl.ShortURL {
	result := make([]*shorturl.ShortURL, 0, len(rows))
	for _, row := range rows {
		result = append(result, toDomainShortURL(row))
	}
	return result
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
