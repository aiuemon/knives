package storage

import (
	"context"
	"errors"
	"fmt"
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

	inserted, err := q.InsertShortURL(ctx, InsertShortURLParams{
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
		ShortUrlID: inserted.ID,
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
	result.ID = inserted.ID
	result.CreatedAt = inserted.CreatedAt.Time
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

func (s *ShortURLStore) ListForUser(ctx context.Context, userID uuid.UUID, page shorturl.ListPage) ([]*shorturl.ListItem, int, error) {
	return s.listShortURLs(ctx, &userID, page)
}

func (s *ShortURLStore) ListAll(ctx context.Context, page shorturl.ListPage) ([]*shorturl.ListItem, int, error) {
	return s.listShortURLs(ctx, nil, page)
}

// shortURLSortColumns whitelists ListPage.SortBy -> the SQL expression it
// maps to. listShortURLs interpolates the selected value directly into the
// query text (bind parameters can't parameterize identifiers) — safe only
// because every value here is a fixed literal from this map, never
// attacker- or even caller-influenced text. Callers MUST have already
// validated page.SortBy via ListPage.normalize before reaching here;
// listShortURLs falls back to created_at for anything not in this map as a
// last-resort safety net, not as a substitute for that validation.
var shortURLSortColumns = map[shorturl.SortField]string{
	shorturl.SortByShortCode:    "su.short_code",
	shorturl.SortByLongURL:      "su.long_url",
	shorturl.SortByTitle:        "su.title",
	shorturl.SortByCreatedAt:    "su.created_at",
	shorturl.SortByClickCount:   "click_count",
	shorturl.SortByCreatorEmail: "creator_email",
}

// listShortURLs backs both ListForUser (userID != nil) and ListAll
// (userID == nil). It's hand-written SQL rather than a sqlc query because
// the listing needs a caller-selected ORDER BY column (4.1節: 表示内容の
// どの項目でもソート可能) — column names can't be bind parameters, so this
// builds the query text from the whitelist above plus a fixed ASC/DESC
// literal, with every actual value (filter text, user id, limit, offset)
// still passed as a real parameter.
func (s *ShortURLStore) listShortURLs(ctx context.Context, userID *uuid.UUID, page shorturl.ListPage) ([]*shorturl.ListItem, int, error) {
	sortColumn, ok := shortURLSortColumns[page.SortBy]
	if !ok {
		sortColumn = "su.created_at"
	}
	direction := "DESC"
	if page.SortDir == shorturl.SortAsc {
		direction = "ASC"
	}

	var args []any
	bind := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}

	var joinClause, userFilterClause string
	if userID != nil {
		joinClause = "JOIN url_permissions up ON up.short_url_id = su.id"
		userFilterClause = "up.user_id = " + bind(*userID) + " AND "
	}

	filterParam := bind(page.Filter)
	limitParam := bind(page.Limit)
	offsetParam := bind(page.Offset)

	query := fmt.Sprintf(`
		SELECT su.id, su.domain_id, su.short_code, su.long_url, su.title, su.description,
		       su.created_by, su.status, su.expires_at, su.source, su.created_at,
		       u.email AS creator_email,
		       COALESCE(cs.total_clicks, 0) AS click_count,
		       COUNT(*) OVER() AS total_count
		FROM short_urls su
		%s
		JOIN users u ON u.id = su.created_by
		LEFT JOIN (
			SELECT short_url_id, SUM(click_count) AS total_clicks
			FROM click_stats_daily
			GROUP BY short_url_id
		) cs ON cs.short_url_id = su.id
		WHERE %s (%s = '' OR su.short_code ILIKE '%%' || %s || '%%' OR su.long_url ILIKE '%%' || %s || '%%' OR su.title ILIKE '%%' || %s || '%%' OR u.email ILIKE '%%' || %s || '%%')
		ORDER BY %s %s NULLS LAST
		LIMIT %s OFFSET %s
	`, joinClause, userFilterClause, filterParam, filterParam, filterParam, filterParam, filterParam, sortColumn, direction, limitParam, offsetParam)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var (
		items []*shorturl.ListItem
		total int
	)
	for rows.Next() {
		var (
			su           shorturl.ShortURL
			title        pgtype.Text
			description  pgtype.Text
			status       string
			expiresAt    pgtype.Timestamptz
			source       string
			createdAt    pgtype.Timestamptz
			creatorEmail string
			clickCount   int64
		)
		if err := rows.Scan(
			&su.ID, &su.DomainID, &su.ShortCode, &su.LongURL, &title, &description,
			&su.CreatedBy, &status, &expiresAt, &source, &createdAt,
			&creatorEmail, &clickCount, &total,
		); err != nil {
			return nil, 0, err
		}
		su.Title = title.String
		su.Description = description.String
		su.Status = shorturl.Status(status)
		su.Source = shorturl.Source(source)
		su.CreatedAt = createdAt.Time
		if expiresAt.Valid {
			t := expiresAt.Time
			su.ExpiresAt = &t
		}
		items = append(items, &shorturl.ListItem{ShortURL: su, CreatorEmail: creatorEmail, ClickCount: clickCount})
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
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
		CreatedAt:   row.CreatedAt.Time,
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
