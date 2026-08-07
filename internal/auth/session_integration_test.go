package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aiuemon/knives/internal/auth"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

// setupRedis starts a real Redis container, since RedisSessionStore has no
// business logic worth testing separately from the Redis operations
// themselves. It skips (not fails) when no container runtime is reachable.
func setupRedis(t *testing.T) *redis.Client {
	t.Helper()
	ctx := context.Background()

	container, err := tcredis.Run(ctx, "redis:7-alpine")
	if err != nil {
		t.Skipf("redis testcontainer unavailable in this environment: %v", err)
	}
	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(container); err != nil {
			t.Logf("failed to terminate redis container: %v", err)
		}
	})

	connStr, err := container.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	opts, err := redis.ParseURL(connStr)
	if err != nil {
		t.Fatalf("parse redis url: %v", err)
	}
	return redis.NewClient(opts)
}

func TestRedisSessionStore_CreateAndFind(t *testing.T) {
	store := auth.NewRedisSessionStore(setupRedis(t))
	ctx := context.Background()
	userID := uuid.New()

	token, err := store.Create(ctx, userID, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if token == "" {
		t.Fatalf("expected a non-empty token")
	}

	session, err := store.Find(ctx, token)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if session.UserID != userID {
		t.Fatalf("expected UserID %s, got %s", userID, session.UserID)
	}
}

func TestRedisSessionStore_FindUnknownTokenReturnsErrSessionNotFound(t *testing.T) {
	store := auth.NewRedisSessionStore(setupRedis(t))

	if _, err := store.Find(context.Background(), "no-such-token"); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestRedisSessionStore_Touch_UpdatesLastSeenAndExtendsExpiry(t *testing.T) {
	store := auth.NewRedisSessionStore(setupRedis(t))
	ctx := context.Background()

	token, err := store.Create(ctx, uuid.New(), time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	before, err := store.Find(ctx, token)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}

	time.Sleep(10 * time.Millisecond)
	if err := store.Touch(ctx, token, 2*time.Hour); err != nil {
		t.Fatalf("Touch: %v", err)
	}

	after, err := store.Find(ctx, token)
	if err != nil {
		t.Fatalf("Find after Touch: %v", err)
	}
	if !after.LastSeenAt.After(before.LastSeenAt) {
		t.Fatalf("expected LastSeenAt to advance: before=%v after=%v", before.LastSeenAt, after.LastSeenAt)
	}
	if !after.ExpiresAt.After(before.ExpiresAt) {
		t.Fatalf("expected ExpiresAt to extend: before=%v after=%v", before.ExpiresAt, after.ExpiresAt)
	}
}

func TestRedisSessionStore_Delete_RevokesTheSessionAndIsIdempotent(t *testing.T) {
	store := auth.NewRedisSessionStore(setupRedis(t))
	ctx := context.Background()

	token, err := store.Create(ctx, uuid.New(), time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := store.Delete(ctx, token); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Find(ctx, token); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound after Delete, got %v", err)
	}

	// ログアウトの二重送信等を想定し、既に無いトークンの再Deleteはエラーに
	// ならないことを確認する。
	if err := store.Delete(ctx, token); err != nil {
		t.Fatalf("Delete on an already-deleted token must be a no-op, got %v", err)
	}
}

func TestRedisSessionStore_DeleteAllForUser_RevokesOnlyThatUsersSessions(t *testing.T) {
	store := auth.NewRedisSessionStore(setupRedis(t))
	ctx := context.Background()

	victim := uuid.New()
	bystander := uuid.New()

	victimTokenA, err := store.Create(ctx, victim, time.Hour)
	if err != nil {
		t.Fatalf("Create victim A: %v", err)
	}
	victimTokenB, err := store.Create(ctx, victim, time.Hour)
	if err != nil {
		t.Fatalf("Create victim B: %v", err)
	}
	bystanderToken, err := store.Create(ctx, bystander, time.Hour)
	if err != nil {
		t.Fatalf("Create bystander: %v", err)
	}

	// 退職者対応・なりすまし検知時の即時失効(5.2節)を検証する: 対象ユーザの
	// 全セッションが消え、無関係なユーザのセッションは残る。
	if err := store.DeleteAllForUser(ctx, victim); err != nil {
		t.Fatalf("DeleteAllForUser: %v", err)
	}

	if _, err := store.Find(ctx, victimTokenA); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("expected victim's session A to be revoked, got %v", err)
	}
	if _, err := store.Find(ctx, victimTokenB); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("expected victim's session B to be revoked, got %v", err)
	}
	if _, err := store.Find(ctx, bystanderToken); err != nil {
		t.Fatalf("expected the bystander's session to survive, got %v", err)
	}
}
