package storage_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/aiuemon/knives/internal/auth"
	"github.com/aiuemon/knives/internal/permission"
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

	// internal/shorturl doesn't exist yet, so seed short_urls directly.
	var domainID, shortURLID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO domains (hostname, is_default) VALUES ($1, true) RETURNING id`, "go.example.com").Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO short_urls (domain_id, short_code, long_url, created_by) VALUES ($1, $2, $3, $4) RETURNING id`,
		domainID, "abc1234", "https://example.com", owner.ID).Scan(&shortURLID); err != nil {
		t.Fatalf("insert short_url: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO url_permissions (short_url_id, user_id, role, granted_by) VALUES ($1, $2, 'owner', $2)`, shortURLID, owner.ID); err != nil {
		t.Fatalf("insert url_permission: %v", err)
	}

	grant, err := permStore.FindGrant(ctx, shortURLID, owner.ID)
	if err != nil {
		t.Fatalf("FindGrant: %v", err)
	}
	if grant == nil || grant.Role != permission.RoleOwner {
		t.Fatalf("expected owner grant, got %+v", grant)
	}

	noGrant, err := permStore.FindGrant(ctx, shortURLID, bystander.ID)
	if err != nil {
		t.Fatalf("FindGrant for a non-permitted user must not error: %v", err)
	}
	if noGrant != nil {
		t.Fatalf("expected nil grant for a user with no permission, got %+v", noGrant)
	}
}
