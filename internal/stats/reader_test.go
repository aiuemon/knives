package stats

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fakeReader struct {
	daily      []DailyCount
	referrers  []ReferrerCount
	calledWith struct {
		shortURLID uuid.UUID
		from, to   time.Time
	}
}

func (r *fakeReader) DailyCounts(_ context.Context, shortURLID uuid.UUID, from, to time.Time) ([]DailyCount, error) {
	r.calledWith.shortURLID = shortURLID
	r.calledWith.from = from
	r.calledWith.to = to
	return r.daily, nil
}

func (r *fakeReader) ReferrerCounts(_ context.Context, _ uuid.UUID, _, _ time.Time) ([]ReferrerCount, error) {
	return r.referrers, nil
}

func TestService_GetStats_ReturnsDailyAndReferrerBreakdown(t *testing.T) {
	reader := &fakeReader{
		daily:     []DailyCount{{Date: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), ClickCount: 3}},
		referrers: []ReferrerCount{{ReferrerHost: "example.com", ClickCount: 3}},
	}
	svc := &Service{Reader: reader}
	shortURLID := uuid.New()
	from := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)

	summary, err := svc.GetStats(context.Background(), shortURLID, from, to)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if len(summary.Daily) != 1 || summary.Daily[0].ClickCount != 3 {
		t.Fatalf("expected daily counts to pass through, got %+v", summary.Daily)
	}
	if len(summary.ByReferrer) != 1 || summary.ByReferrer[0].ReferrerHost != "example.com" {
		t.Fatalf("expected referrer counts to pass through, got %+v", summary.ByReferrer)
	}
	if reader.calledWith.shortURLID != shortURLID {
		t.Fatalf("expected shortURLID to be forwarded to the reader")
	}
}

func TestService_GetStats_RejectsToBeforeFrom(t *testing.T) {
	svc := &Service{Reader: &fakeReader{}}
	from := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

	_, err := svc.GetStats(context.Background(), uuid.New(), from, to)
	if !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("expected ErrInvalidRange, got %v", err)
	}
}

func TestService_GetStats_RejectsRangeExceedingMax(t *testing.T) {
	svc := &Service{Reader: &fakeReader{}}
	from := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.AddDate(0, 0, maxRangeDays+1)

	_, err := svc.GetStats(context.Background(), uuid.New(), from, to)
	if !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("expected ErrInvalidRange for an over-wide range, got %v", err)
	}
}
