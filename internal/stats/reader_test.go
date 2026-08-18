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
	countries  []CountryCount
	oses       []OSCount
	browsers   []BrowserCount
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

func (r *fakeReader) CountryCounts(_ context.Context, _ uuid.UUID, _, _ time.Time) ([]CountryCount, error) {
	return r.countries, nil
}

func (r *fakeReader) OSCounts(_ context.Context, _ uuid.UUID, _, _ time.Time) ([]OSCount, error) {
	return r.oses, nil
}

func (r *fakeReader) BrowserCounts(_ context.Context, _ uuid.UUID, _, _ time.Time) ([]BrowserCount, error) {
	return r.browsers, nil
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

func TestService_GetStats_ReturnsCountryAndOSBreakdowns(t *testing.T) {
	reader := &fakeReader{
		countries: []CountryCount{{CountryCode: "JP", ClickCount: 5}, {CountryCode: "", ClickCount: 1}},
		oses:      []OSCount{{OS: "Windows", ClickCount: 4}, {OS: "iPadOS", ClickCount: 2}},
	}
	svc := &Service{Reader: reader}
	from := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)

	summary, err := svc.GetStats(context.Background(), uuid.New(), from, to, GranularityDay)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if len(summary.ByCountry) != 2 || summary.ByCountry[0].CountryCode != "JP" {
		t.Fatalf("expected country counts to pass through, got %+v", summary.ByCountry)
	}
	if len(summary.ByOS) != 2 || summary.ByOS[0].OS != "Windows" {
		t.Fatalf("expected OS counts to pass through, got %+v", summary.ByOS)
	}
}

func TestService_GetStats_FoldsBrowsersBeyondTop10IntoOther(t *testing.T) {
	// 11種類のブラウザを降順(Reader.BrowserCountsの契約通り)で用意し、
	// 上位10件はそのまま、11件目以降はBrowserOtherに合算されることを
	// 検証する(4節: シェアがトップ10までを分離、それ以外は「その他」)。
	browsers := make([]BrowserCount, 0, 11)
	for i := range 11 {
		browsers = append(browsers, BrowserCount{
			Browser:    string(rune('A' + i)),
			ClickCount: int64(11 - i), // 11,10,...,1 (降順)
		})
	}
	reader := &fakeReader{browsers: browsers}
	svc := &Service{Reader: reader}
	from := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)

	summary, err := svc.GetStats(context.Background(), uuid.New(), from, to, GranularityDay)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if len(summary.ByBrowser) != 11 {
		t.Fatalf("expected top 10 + 1 その他 bucket (11 entries), got %d: %+v", len(summary.ByBrowser), summary.ByBrowser)
	}
	for i := range 10 {
		if summary.ByBrowser[i].Browser != browsers[i].Browser {
			t.Fatalf("expected entry %d to be the untouched top-10 browser %q, got %+v", i, browsers[i].Browser, summary.ByBrowser[i])
		}
	}
	last := summary.ByBrowser[10]
	if last.Browser != BrowserOther || last.ClickCount != 1 {
		t.Fatalf("expected the 11th browser (count 1) to be folded into BrowserOther, got %+v", last)
	}
}

func TestService_GetStats_TopBrowsersUntouchedWhenAtOrBelowTen(t *testing.T) {
	browsers := []BrowserCount{{Browser: "Chrome", ClickCount: 5}, {Browser: "Firefox", ClickCount: 2}}
	reader := &fakeReader{browsers: browsers}
	svc := &Service{Reader: reader}
	from := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)

	summary, err := svc.GetStats(context.Background(), uuid.New(), from, to, GranularityDay)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if len(summary.ByBrowser) != 2 {
		t.Fatalf("expected no その他 bucket when there are only 2 browsers, got %+v", summary.ByBrowser)
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
