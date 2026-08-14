package main

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/aiuemon/knives/internal/auth"
	"github.com/aiuemon/knives/internal/storage"
)

// migrationTarget is the subset of storage.MigrationStore's behavior
// runMigration depends on; declared here (rather than depending on the
// concrete type directly) so the core migration loop is unit-testable
// without a real Postgres.
type migrationTarget interface {
	InsertMigratedShortURL(ctx context.Context, in storage.MigratedShortURLInput) (uuid.UUID, error)
	GrantOwner(ctx context.Context, shortURLID, userID, grantedBy uuid.UUID) error
	SetClickStatsTotal(ctx context.Context, shortURLID uuid.UUID, date time.Time, total int64) error
}

// userResolver is the subset of auth.Store findOrCreateUser needs;
// declared here for the same testability reason as migrationTarget.
// *storage.AuthStore satisfies this automatically as part of implementing
// the wider auth.Store.
type userResolver interface {
	FindUserByEmail(ctx context.Context, email string) (*auth.User, error)
	CreateUser(ctx context.Context, email string, emailVerified bool) (*auth.User, error)
}

// summary tallies what happened across a migration run, for the final
// log line and exit code (main() exits non-zero if Failed > 0).
type summary struct {
	Migrated int
	Skipped  int
	Failed   int
}

// runMigration is the core of cmd/migrate-yourls (10節): for every YOURLS
// row, resolve its owner (from the owners map, falling back to
// systemUserEmail), insert the short_url (attributed to the system user
// as created_by — ownership is a separate url_permissions grant, never
// created_by), grant that owner, and carry over the cumulative click
// count. A row whose short_code already exists is skipped rather than
// treated as fatal, which is what makes re-running the CLI over
// already-migrated data safe.
func runMigration(
	ctx context.Context,
	users userResolver,
	target migrationTarget,
	domainID uuid.UUID,
	systemUserEmail string,
	rows []yourlsRow,
	owners map[string]string,
) (summary, error) {
	systemUser, err := findOrCreateUser(ctx, users, systemUserEmail)
	if err != nil {
		return summary{}, err
	}

	userCache := map[string]uuid.UUID{normalizeEmail(systemUserEmail): systemUser.ID}
	migratedAt := time.Now().UTC().Truncate(24 * time.Hour)

	var s summary
	for _, row := range rows {
		ownerEmail := systemUserEmail
		if email, ok := owners[row.Keyword]; ok && email != "" {
			ownerEmail = email
		}

		ownerID, ok := userCache[normalizeEmail(ownerEmail)]
		if !ok {
			owner, err := findOrCreateUser(ctx, users, ownerEmail)
			if err != nil {
				slog.Error("resolve owner failed", "keyword", row.Keyword, "email", ownerEmail, "error", err)
				s.Failed++
				continue
			}
			ownerID = owner.ID
			userCache[normalizeEmail(ownerEmail)] = ownerID
		}

		shortURLID, err := target.InsertMigratedShortURL(ctx, storage.MigratedShortURLInput{
			DomainID:  domainID,
			ShortCode: row.Keyword,
			LongURL:   row.URL,
			Title:     row.Title,
			CreatedBy: systemUser.ID,
			CreatedAt: row.CreatedAt,
		})
		if errors.Is(err, storage.ErrMigratedShortURLAlreadyExists) {
			slog.Warn("skipped: short_code already exists", "keyword", row.Keyword)
			s.Skipped++
			continue
		}
		if err != nil {
			slog.Error("insert short_url failed", "keyword", row.Keyword, "error", err)
			s.Failed++
			continue
		}

		if err := target.GrantOwner(ctx, shortURLID, ownerID, systemUser.ID); err != nil {
			slog.Error("grant owner failed", "keyword", row.Keyword, "error", err)
			s.Failed++
			continue
		}

		if row.Clicks > 0 {
			if err := target.SetClickStatsTotal(ctx, shortURLID, migratedAt, row.Clicks); err != nil {
				// クリック数の投入失敗はURL自体の移行(short_url+owner)を
				// 無効にしない — 統計は後から手動で補正可能。
				slog.Error("set click stats failed", "keyword", row.Keyword, "error", err)
			}
		}

		s.Migrated++
	}
	return s, nil
}

// findOrCreateUser looks up email, creating an unverified placeholder user
// if none exists yet — the "未ログイン状態のユーザレコード" from 10節,
// which becomes a real account the first time that person actually logs
// in (via internal/auth's normal identity-resolution-by-email).
func findOrCreateUser(ctx context.Context, users userResolver, email string) (*auth.User, error) {
	u, err := users.FindUserByEmail(ctx, email)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, auth.ErrNotFound) {
		return nil, err
	}
	return users.CreateUser(ctx, email, false)
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
