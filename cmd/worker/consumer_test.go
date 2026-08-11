package main

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func TestParseClickEvent_Success(t *testing.T) {
	shortURLID := uuid.New()
	clickedAt := time.Date(2026, 8, 10, 12, 30, 0, 0, time.UTC)

	msg := redis.XMessage{
		ID: "1691568000000-0",
		Values: map[string]interface{}{
			"short_url_id":  shortURLID.String(),
			"clicked_at":    clickedAt.Format(time.RFC3339Nano),
			"referrer_host": "example.com",
			"user_agent":    "Mozilla/5.0",
			"ip_hash":       "abc123",
		},
	}

	ev, err := parseClickEvent(msg)
	if err != nil {
		t.Fatalf("parseClickEvent: %v", err)
	}
	if ev.StreamID != msg.ID {
		t.Fatalf("expected StreamID %q, got %q", msg.ID, ev.StreamID)
	}
	if ev.ShortURLID != shortURLID {
		t.Fatalf("expected ShortURLID %s, got %s", shortURLID, ev.ShortURLID)
	}
	if !ev.ClickedAt.Equal(clickedAt) {
		t.Fatalf("expected ClickedAt %v, got %v", clickedAt, ev.ClickedAt)
	}
	if ev.ReferrerHost != "example.com" || ev.UserAgentRaw != "Mozilla/5.0" || ev.IPHash != "abc123" {
		t.Fatalf("unexpected event: %+v", ev)
	}
}

func TestParseClickEvent_MissingOptionalFieldsDefaultToEmpty(t *testing.T) {
	shortURLID := uuid.New()
	msg := redis.XMessage{
		ID: "1-0",
		Values: map[string]interface{}{
			"short_url_id": shortURLID.String(),
			"clicked_at":   time.Now().Format(time.RFC3339Nano),
		},
	}

	ev, err := parseClickEvent(msg)
	if err != nil {
		t.Fatalf("parseClickEvent: %v", err)
	}
	if ev.ReferrerHost != "" || ev.UserAgentRaw != "" || ev.IPHash != "" {
		t.Fatalf("expected missing optional fields to default to empty strings, got %+v", ev)
	}
}

func TestParseClickEvent_InvalidShortURLIDIsRejected(t *testing.T) {
	msg := redis.XMessage{
		ID: "1-0",
		Values: map[string]interface{}{
			"short_url_id": "not-a-uuid",
			"clicked_at":   time.Now().Format(time.RFC3339Nano),
		},
	}
	if _, err := parseClickEvent(msg); err == nil {
		t.Fatalf("expected an error for an invalid short_url_id")
	}
}

func TestParseClickEvent_MissingShortURLIDIsRejected(t *testing.T) {
	msg := redis.XMessage{
		ID:     "1-0",
		Values: map[string]interface{}{"clicked_at": time.Now().Format(time.RFC3339Nano)},
	}
	if _, err := parseClickEvent(msg); err == nil {
		t.Fatalf("expected an error for a missing short_url_id")
	}
}

func TestParseClickEvent_InvalidClickedAtIsRejected(t *testing.T) {
	msg := redis.XMessage{
		ID: "1-0",
		Values: map[string]interface{}{
			"short_url_id": uuid.New().String(),
			"clicked_at":   "not-a-timestamp",
		},
	}
	if _, err := parseClickEvent(msg); err == nil {
		t.Fatalf("expected an error for an invalid clicked_at")
	}
}
