package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/aiuemon/knives/internal/auth"
	"github.com/google/uuid"
)

func TestRedisOIDCNonceStore_CreateAndConsumeState(t *testing.T) {
	store := auth.NewRedisOIDCNonceStore(setupRedis(t))
	ctx := context.Background()
	pending := auth.OIDCPendingLogin{ConfigID: uuid.New(), Nonce: "nonce-1", CodeVerifier: "verifier-1"}

	if err := store.CreateState(ctx, "state-1", pending, time.Minute); err != nil {
		t.Fatalf("CreateState: %v", err)
	}

	got, ok, err := store.ConsumeState(ctx, "state-1")
	if err != nil {
		t.Fatalf("ConsumeState: %v", err)
	}
	if !ok || got != pending {
		t.Fatalf("expected (%+v, true), got (%+v, %v)", pending, got, ok)
	}
}

func TestRedisOIDCNonceStore_ConsumeStateIsSingleUse(t *testing.T) {
	store := auth.NewRedisOIDCNonceStore(setupRedis(t))
	ctx := context.Background()
	pending := auth.OIDCPendingLogin{ConfigID: uuid.New(), Nonce: "nonce-1", CodeVerifier: "verifier-1"}

	if err := store.CreateState(ctx, "state-1", pending, time.Minute); err != nil {
		t.Fatalf("CreateState: %v", err)
	}
	if _, ok, err := store.ConsumeState(ctx, "state-1"); err != nil || !ok {
		t.Fatalf("first consume: ok=%v err=%v", ok, err)
	}

	// リプレイ・CSRF対策(3.3節): 同じstateは二度使えない。
	if _, ok, err := store.ConsumeState(ctx, "state-1"); err != nil || ok {
		t.Fatalf("expected second consume to fail (single-use), got ok=%v err=%v", ok, err)
	}
}

func TestRedisOIDCNonceStore_ConsumeUnknownStateReturnsNotOK(t *testing.T) {
	store := auth.NewRedisOIDCNonceStore(setupRedis(t))

	if _, ok, err := store.ConsumeState(context.Background(), "never-issued"); err != nil || ok {
		t.Fatalf("expected ok=false for an unknown state, got ok=%v err=%v", ok, err)
	}
}
