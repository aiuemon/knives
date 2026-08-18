package stats

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// maxRangeDays bounds how wide a from/to window callers may query.
// click_events has no retention limit (2.2節: 無期限保存), so an unbounded
// range would let a single request scan an unbounded number of monthly
// partitions; API handlers should reject anything wider than this before
// it ever reaches the Reader.
const maxRangeDays = 366

var (
	// ErrInvalidRange is returned by GetStats when to is before from, or
	// the range exceeds maxRangeDays.
	ErrInvalidRange = errors.New("stats: invalid from/to range")
	// ErrInvalidGranularity is returned by GetStats when granularity is
	// neither GranularityDay nor GranularityHour.
	ErrInvalidGranularity = errors.New("stats: invalid granularity")
)

// Granularity selects how GetStats buckets click activity over time.
type Granularity string

const (
	GranularityDay  Granularity = "day"
	GranularityHour Granularity = "hour"
)

// DailyCount is one row of click_stats_daily (2.2節) for a short URL.
type DailyCount struct {
	Date       time.Time
	ClickCount int64
}

// HourlyCount is one hour-truncated bucket of click_events for a short
// URL, aggregated live since there is no hourly rollup table (2.2節の
// click_stats_dailyは日単位のみ).
type HourlyCount struct {
	Hour       time.Time
	ClickCount int64
}

// ReferrerCount is the click total for one referrer host over a queried
// range, aggregated live from click_events.referrer_host (2.2節) since
// there is no referrer-level rollup table. ReferrerHost is "" for clicks
// with no referrer (direct access).
type ReferrerCount struct {
	ReferrerHost string
	ClickCount   int64
}

// CountryCount is the click total for one country over a queried range,
// aggregated live from click_events.country_code (internal/geoip).
// CountryCode is "" for clicks with no resolved country (no GeoIP
// database configured, private/unresolvable IP, or predating GeoIP
// support).
type CountryCount struct {
	CountryCode string
	ClickCount  int64
}

// OSCount is the click total for one OS category over a queried range,
// aggregated live from click_events.os (internal/useragent). OS is "" for
// clicks with no user_agent_raw or one that couldn't be classified.
type OSCount struct {
	OS         string
	ClickCount int64
}

// BrowserCount is the click total for one browser family over a queried
// range, aggregated live from click_events.browser (internal/useragent).
// Browser is "" for clicks with no user_agent_raw or one that couldn't be
// classified, or BrowserOther for the summed remainder beyond the top
// browserTopN families (4節: シェアがトップ10までを分離、それ以外は
// 「その他」)。
type BrowserCount struct {
	Browser    string
	ClickCount int64
}

// BrowserOther is the sentinel BrowserCount.Browser value for the bucket
// GetStats folds every browser family beyond the top browserTopN into.
// Distinct from "" (a genuinely unclassifiable User-Agent) so callers can
// tell the two apart if they ever need to.
const BrowserOther = "other"

// browserTopN bounds how many distinct browser families GetStats reports
// individually before folding the rest into BrowserOther (4節).
const browserTopN = 10

// Summary is what GetStats returns: a short URL's click activity over one
// [From, To] range, broken down by referrer/country/OS/browser and by
// either day or hour depending on Granularity. Only the field matching
// Granularity is populated (Daily for GranularityDay, Hourly for
// GranularityHour).
type Summary struct {
	From        time.Time
	To          time.Time
	Granularity Granularity
	Daily       []DailyCount
	Hourly      []HourlyCount
	ByReferrer  []ReferrerCount
	ByCountry   []CountryCount
	ByOS        []OSCount
	ByBrowser   []BrowserCount
}

// Reader is the persistence port GetStats depends on. Permission-gating
// (4.2節: owner/editor/viewerまたはsystem_adminのみ) is the caller's
// responsibility (cmd/api's resolveAccess) — Reader itself trusts
// shortURLID unconditionally, same division of responsibility as
// shorturl.Store.
type Reader interface {
	// DailyCounts returns click_stats_daily rows for shortURLID with date
	// in the half-open range [from, to), ordered by date ascending.
	DailyCounts(ctx context.Context, shortURLID uuid.UUID, from, to time.Time) ([]DailyCount, error)
	// HourlyCounts returns click_events aggregated into hour buckets for
	// shortURLID with clicked_at in the half-open range [from, to),
	// ordered by hour ascending.
	HourlyCounts(ctx context.Context, shortURLID uuid.UUID, from, to time.Time) ([]HourlyCount, error)
	// ReferrerCounts returns click_events aggregated by referrer_host for
	// shortURLID with clicked_at in the half-open range [from, to),
	// ordered by click count descending.
	ReferrerCounts(ctx context.Context, shortURLID uuid.UUID, from, to time.Time) ([]ReferrerCount, error)
	// CountryCounts returns click_events aggregated by country_code for
	// shortURLID with clicked_at in the half-open range [from, to),
	// ordered by click count descending.
	CountryCounts(ctx context.Context, shortURLID uuid.UUID, from, to time.Time) ([]CountryCount, error)
	// OSCounts returns click_events aggregated by os for shortURLID with
	// clicked_at in the half-open range [from, to), ordered by click
	// count descending.
	OSCounts(ctx context.Context, shortURLID uuid.UUID, from, to time.Time) ([]OSCount, error)
	// BrowserCounts returns click_events aggregated by browser for
	// shortURLID with clicked_at in the half-open range [from, to),
	// ordered by click count descending. GetStats — not Reader
	// implementations — is responsible for folding entries beyond
	// browserTopN into BrowserOther.
	BrowserCounts(ctx context.Context, shortURLID uuid.UUID, from, to time.Time) ([]BrowserCount, error)
}

type Service struct {
	Reader Reader
}

// GetStats validates the requested range and returns shortURLID's
// per-referrer click activity within it, bucketed by day or by hour
// according to granularity.
func (s *Service) GetStats(ctx context.Context, shortURLID uuid.UUID, from, to time.Time, granularity Granularity) (*Summary, error) {
	if to.Before(from) || to.Sub(from) > maxRangeDays*24*time.Hour {
		return nil, ErrInvalidRange
	}

	referrers, err := s.Reader.ReferrerCounts(ctx, shortURLID, from, to)
	if err != nil {
		return nil, err
	}
	countries, err := s.Reader.CountryCounts(ctx, shortURLID, from, to)
	if err != nil {
		return nil, err
	}
	oses, err := s.Reader.OSCounts(ctx, shortURLID, from, to)
	if err != nil {
		return nil, err
	}
	browsers, err := s.Reader.BrowserCounts(ctx, shortURLID, from, to)
	if err != nil {
		return nil, err
	}

	summary := &Summary{
		From:        from,
		To:          to,
		Granularity: granularity,
		ByReferrer:  referrers,
		ByCountry:   countries,
		ByOS:        oses,
		ByBrowser:   bucketTopBrowsers(browsers),
	}
	switch granularity {
	case GranularityDay:
		daily, err := s.Reader.DailyCounts(ctx, shortURLID, from, to)
		if err != nil {
			return nil, err
		}
		summary.Daily = daily
	case GranularityHour:
		hourly, err := s.Reader.HourlyCounts(ctx, shortURLID, from, to)
		if err != nil {
			return nil, err
		}
		summary.Hourly = hourly
	default:
		return nil, ErrInvalidGranularity
	}

	return summary, nil
}

// bucketTopBrowsers keeps the browserTopN highest-count entries of all
// (already ordered by click count descending — see Reader.BrowserCounts)
// and folds the remainder into a single BrowserOther entry.
func bucketTopBrowsers(all []BrowserCount) []BrowserCount {
	if len(all) <= browserTopN {
		return all
	}
	result := make([]BrowserCount, 0, browserTopN+1)
	var otherTotal int64
	for i, b := range all {
		if i < browserTopN {
			result = append(result, b)
			continue
		}
		otherTotal += b.ClickCount
	}
	if otherTotal > 0 {
		result = append(result, BrowserCount{Browser: BrowserOther, ClickCount: otherTotal})
	}
	return result
}
