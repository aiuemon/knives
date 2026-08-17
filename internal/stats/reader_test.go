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
	hourly     []HourlyCount
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

func (r *fakeReader) HourlyCounts(_ context.Context, shortURLID uuid.UUID, from, to time.Time) ([]HourlyCount, error) {
	r.calledWith.shortURLID = shortURLID
	r.calledWith.from = from
	r.calledWith.to = to
	return r.hourly, nil
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

	summary, err := svc.GetStats(context.Background(), shortURLID, from, to, GranularityDay)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if len(summary.Daily) != 1 || summary.Daily[0].ClickCount != 3 {
		t.Fatalf("expected daily counts to pass through, got %+v", summary.Daily)
	}
	if summary.Hourly != nil {
		t.Fatalf("expected Hourly to stay unset for GranularityDay, got %+v", summary.Hourly)
	}
	if len(summary.ByReferrer) != 1 || summary.ByReferrer[0].ReferrerHost != "example.com" {
		t.Fatalf("expected referrer counts to pass through, got %+v", summary.ByReferrer)
	}
	if reader.calledWith.shortURLID != shortURLID {
		t.Fatalf("expected shortURLID to be forwarded to the reader")
	}
}

func TestService_GetStats_ReturnsHourlyAndReferrerBreakdown(t *testing.T) {
	reader := &fakeReader{
		hourly:    []HourlyCount{{Hour: time.Date(2026, 8, 1, 14, 0, 0, 0, time.UTC), ClickCount: 2}},
		referrers: []ReferrerCount{{ReferrerHost: "example.com", ClickCount: 2}},
	}
	svc := &Service{Reader: reader}
	shortURLID := uuid.New()
	from := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)

	summary, err := svc.GetStats(context.Background(), shortURLID, from, to, GranularityHour)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if len(summary.Hourly) != 1 || summary.Hourly[0].ClickCount != 2 {
		t.Fatalf("expected hourly counts to pass through, got %+v", summary.Hourly)
	}
	if summary.Daily != nil {
		t.Fatalf("expected Daily to stay unset for GranularityHour, got %+v", summary.Daily)
	}
}

func TestService_GetStats_RejectsUnknownGranularity(t *testing.T) {
	svc := &Service{Reader: &fakeReader{}}
	from := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)

	_, err := svc.GetStats(context.Background(), uuid.New(), from, to, Granularity("minute"))
	if !errors.Is(err, ErrInvalidGranularity) {
		t.Fatalf("expected ErrInvalidGranularity, got %v", err)
	}
}

func TestService_GetStats_RejectsToBeforeFrom(t *testing.T) {
	svc := &Service{Reader: &fakeReader{}}
	from := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

	_, err := svc.GetStats(context.Background(), uuid.New(), from, to, GranularityDay)
	if !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("expected ErrInvalidRange, got %v", err)
	}
}

func TestService_GetStats_RejectsRangeExceedingMax(t *testing.T) {
	svc := &Service{Reader: &fakeReader{}}
	from := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.AddDate(0, 0, maxRangeDays+1)

	_, err := svc.GetStats(context.Background(), uuid.New(), from, to, GranularityDay)
	if !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("expected ErrInvalidRange for an over-wide range, got %v", err)
	}
}
