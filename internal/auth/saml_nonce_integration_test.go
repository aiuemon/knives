package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/aiuemon/knives/internal/auth"
	"github.com/google/uuid"
)

func TestRedisSAMLNonceStore_CreateAndConsumeRequest(t *testing.T) {
	store := auth.NewRedisSAMLNonceStore(setupRedis(t))
	ctx := context.Background()
	configID := uuid.New()

	if err := store.CreateRequest(ctx, "relay-1", configID, time.Minute); err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	got, ok, err := store.ConsumeRequest(ctx, "relay-1")
	if err != nil {
		t.Fatalf("ConsumeRequest: %v", err)
	}
	if !ok || got != configID {
		t.Fatalf("expected (%s, true), got (%s, %v)", configID, got, ok)
	}
}

func TestRedisSAMLNonceStore_ConsumeRequestIsSingleUse(t *testing.T) {
	store := auth.NewRedisSAMLNonceStore(setupRedis(t))
	ctx := context.Background()
	configID := uuid.New()

	if err := store.CreateRequest(ctx, "relay-1", configID, time.Minute); err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if _, ok, err := store.ConsumeRequest(ctx, "relay-1"); err != nil || !ok {
		t.Fatalf("first consume: ok=%v err=%v", ok, err)
	}

	// リプレイ攻撃対策(3.2節): 同じRelayStateは二度使えない。
	if _, ok, err := store.ConsumeRequest(ctx, "relay-1"); err != nil || ok {
		t.Fatalf("expected second consume to fail (single-use), got ok=%v err=%v", ok, err)
	}
}

func TestRedisSAMLNonceStore_ConsumeUnknownRequestReturnsNotOK(t *testing.T) {
	store := auth.NewRedisSAMLNonceStore(setupRedis(t))

	if _, ok, err := store.ConsumeRequest(context.Background(), "never-issued"); err != nil || ok {
		t.Fatalf("expected ok=false for an unknown relay state, got ok=%v err=%v", ok, err)
	}
}

func TestRedisSAMLNonceStore_MarkAssertionSeen(t *testing.T) {
	store := auth.NewRedisSAMLNonceStore(setupRedis(t))
	ctx := context.Background()

	seen, err := store.MarkAssertionSeen(ctx, "assertion-1", time.Minute)
	if err != nil {
		t.Fatalf("MarkAssertionSeen (first): %v", err)
	}
	if seen {
		t.Fatalf("expected the first mark to report alreadySeen=false")
	}

	// リプレイ対策(3.2節): 同じAssertion IDの二度目はseen=trueで検出される。
	seen, err = store.MarkAssertionSeen(ctx, "assertion-1", time.Minute)
	if err != nil {
		t.Fatalf("MarkAssertionSeen (second): %v", err)
	}
	if !seen {
		t.Fatalf("expected the second mark to report alreadySeen=true (replay)")
	}
}
