package storage_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/aiuemon/knives/internal/auth"
	"github.com/aiuemon/knives/internal/permission"
	"github.com/aiuemon/knives/internal/shorturl"
	"github.com/aiuemon/knives/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// setupPostgres starts a real PostgreSQL container and applies 0001_init.up.sql,
// so these tests catch what sqlc's static analysis cannot (enum/uuid wire
// encoding, constraint violations, etc). It skips (not fails) when no
// container runtime is reachable, since that's an environment limitation
// rather than a code defect.
func setupPostgres(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()

	container, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithInitScripts(filepath.Join("..", "..", "db", "migrations", "0001_init.up.sql")),
		postgres.WithDatabase("knives_test"),
		postgres.WithUsername("knives"),
		postgres.WithPassword("knives"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Skipf("postgres testcontainer unavailable in this environment: %v", err)
	}
	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(container); err != nil {
			t.Logf("failed to terminate postgres container: %v", err)
		}
	})

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}

	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)

	return pool
}

func TestAuthStore_FullLifecycle(t *testing.T) {
	pool := setupPostgres(t)
	store := storage.NewAuthStore(pool)
	ctx := context.Background()

	user, err := store.CreateUser(ctx, "person@example.com", true)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	cfgID := uuid.New()
	identity, err := store.CreateAuthIdentity(ctx, user.ID, auth.ProviderOIDC, &cfgID, "sub-1", "person@example.com", true)
	if err != nil {
		t.Fatalf("CreateAuthIdentity: %v", err)
	}

	found, err := store.FindAuthIdentity(ctx, auth.ProviderOIDC, &cfgID, "sub-1")
	if err != nil {
		t.Fatalf("FindAuthIdentity: %v", err)
	}
	if found.ID != identity.ID || found.UserID != user.ID {
		t.Fatalf("unexpected identity: %+v", found)
	}

	if err := store.TouchAuthIdentity(ctx, identity.ID, time.Now()); err != nil {
		t.Fatalf("TouchAuthIdentity: %v", err)
	}

	if byEmail, err := store.FindUserByEmail(ctx, "person@example.com"); err != nil || byEmail.ID != user.ID {
		t.Fatalf("FindUserByEmail: err=%v, user=%+v", err, byEmail)
	}

	if byID, err := store.FindUserByID(ctx, user.ID); err != nil || byID.ID != user.ID {
		t.Fatalf("FindUserByID: err=%v, user=%+v", err, byID)
	}

	if count, err := store.CountAuthIdentitiesForUser(ctx, user.ID); err != nil || count != 1 {
		t.Fatalf("CountAuthIdentitiesForUser: err=%v, count=%d", err, count)
	}

	if _, err := store.FindAuthIdentity(ctx, auth.ProviderLocal, nil, "no-such-subject"); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for a missing identity, got %v", err)
	}

	pendingID, err := store.CreatePendingLinkRequest(ctx, user.ID, auth.ProviderLocal, nil, "person@example.com", "tokenhash-1", time.Now().Add(30*time.Minute))
	if err != nil {
		t.Fatalf("CreatePendingLinkRequest: %v", err)
	}

	pending, err := store.FindPendingLinkRequestByTokenHash(ctx, "tokenhash-1")
	if err != nil || pending.ID != pendingID || pending.ConfirmedAt != nil {
		t.Fatalf("FindPendingLinkRequestByTokenHash before confirm: err=%v, pending=%+v", err, pending)
	}

	if err := store.ConfirmPendingLinkRequest(ctx, pendingID, time.Now()); err != nil {
		t.Fatalf("ConfirmPendingLinkRequest: %v", err)
	}

	confirmed, err := store.FindPendingLinkRequestByTokenHash(ctx, "tokenhash-1")
	if err != nil || confirmed.ConfirmedAt == nil {
		t.Fatalf("expected a confirmed pending request, got err=%v, pending=%+v", err, confirmed)
	}

	if err := store.RecordAuditLog(ctx, auth.AuditLogEntry{
		ActorUserID: &user.ID,
		Action:      "account.link",
		TargetType:  "auth_identity",
		TargetID:    identity.ID.String(),
		Metadata:    map[string]any{"provider_type": "oidc"},
	}); err != nil {
		t.Fatalf("RecordAuditLog: %v", err)
	}
}

func TestPermissionStore_FindGrant(t *testing.T) {
	pool := setupPostgres(t)
	authStore := storage.NewAuthStore(pool)
	permStore := storage.NewPermissionStore(pool)
	ctx := context.Background()

	owner, err := authStore.CreateUser(ctx, "owner@example.com", true)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	bystander, err := authStore.CreateUser(ctx, "bystander@example.com", true)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	domainID := insertDefaultDomain(t, pool, "go.example.com")
	creator := shorturl.Creator{Store: storage.NewShortURLStore(pool)}
	su, err := creator.Create(ctx, shorturl.CreateInput{
		DomainID:  domainID,
		LongURL:   "https://example.com",
		CreatedBy: owner.ID,
	})
	if err != nil {
		t.Fatalf("shorturl Create: %v", err)
	}

	grant, err := permStore.FindGrant(ctx, su.ID, owner.ID)
	if err != nil {
		t.Fatalf("FindGrant: %v", err)
	}
	if grant == nil || grant.Role != permission.RoleOwner {
		t.Fatalf("expected the creator to hold an owner grant, got %+v", grant)
	}

	noGrant, err := permStore.FindGrant(ctx, su.ID, bystander.ID)
	if err != nil {
		t.Fatalf("FindGrant for a non-permitted user must not error: %v", err)
	}
	if noGrant != nil {
		t.Fatalf("expected nil grant for a user with no permission, got %+v", noGrant)
	}
}

func TestShortURLStore_CreateShortURL(t *testing.T) {
	pool := setupPostgres(t)
	authStore := storage.NewAuthStore(pool)
	permStore := storage.NewPermissionStore(pool)
	ctx := context.Background()

	domainID := insertDefaultDomain(t, pool, "go.example.com")
	owner, err := authStore.CreateUser(ctx, "creator@example.com", true)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	creator := shorturl.Creator{Store: storage.NewShortURLStore(pool)}

	su, err := creator.Create(ctx, shorturl.CreateInput{
		DomainID:    domainID,
		CustomAlias: "campaign-2026",
		LongURL:     "https://example.com/landing",
		CreatedBy:   owner.ID,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if su.ShortCode != "campaign-2026" {
		t.Fatalf("expected the custom alias to be used, got %q", su.ShortCode)
	}

	grant, err := permStore.FindGrant(ctx, su.ID, owner.ID)
	if err != nil || grant == nil || grant.Role != permission.RoleOwner {
		t.Fatalf("expected the creator to be granted owner in the same transaction, got grant=%+v err=%v", grant, err)
	}

	// 同じdomain_id+short_codeでの再作成はDBのUNIQUE制約に当たり、
	// shorturl.ErrAliasTakenとして表面化するはず(実DBでのcollision検知を検証)。
	_, err = creator.Create(ctx, shorturl.CreateInput{
		DomainID:    domainID,
		CustomAlias: "campaign-2026",
		LongURL:     "https://example.com/another",
		CreatedBy:   owner.ID,
	})
	if !errors.Is(err, shorturl.ErrAliasTaken) {
		t.Fatalf("expected ErrAliasTaken for a duplicate alias, got %v", err)
	}

	// short_code_settingsの初期値(migrationのデフォルト行)を使ったランダム
	// 生成の経路も、実DB相手にend-to-endで確認する。
	random, err := creator.Create(ctx, shorturl.CreateInput{
		DomainID:  domainID,
		LongURL:   "https://example.com/random",
		CreatedBy: owner.ID,
	})
	if err != nil {
		t.Fatalf("Create with random code: %v", err)
	}
	if len(random.ShortCode) == 0 {
		t.Fatalf("expected a non-empty randomly generated short_code")
	}
}

func insertDefaultDomain(t *testing.T, pool *pgxpool.Pool, hostname string) uuid.UUID {
	t.Helper()
	var domainID uuid.UUID
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO domains (hostname, is_default) VALUES ($1, true) RETURNING id`, hostname,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	return domainID
}
