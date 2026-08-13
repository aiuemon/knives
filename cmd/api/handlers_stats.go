package main

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/aiuemon/knives/internal/auth"
	"github.com/aiuemon/knives/internal/shorturl"
	"github.com/aiuemon/knives/internal/stats"
)

const statsDateLayout = "2006-01-02"

type statsDailyResponse struct {
	Date       string `json:"date"`
	ClickCount int64  `json:"click_count"`
}

type statsReferrerResponse struct {
	ReferrerHost string `json:"referrer_host"`
	ClickCount   int64  `json:"click_count"`
}

type shortURLStatsResponse struct {
	From       string                  `json:"from"`
	To         string                  `json:"to"`
	Daily      []statsDailyResponse    `json:"daily"`
	ByReferrer []statsReferrerResponse `json:"by_referrer"`
}

// toShortURLStatsResponse formats summary for the client. from/to are the
// caller-facing, inclusive calendar-day bounds the user actually asked
// for — distinct from summary.From/To, which is the half-open range
// actually queried (§Service.GetStats) and not meaningful to echo back.
func toShortURLStatsResponse(summary *stats.Summary, from, to time.Time) shortURLStatsResponse {
	daily := make([]statsDailyResponse, 0, len(summary.Daily))
	for _, d := range summary.Daily {
		daily = append(daily, statsDailyResponse{Date: d.Date.Format(statsDateLayout), ClickCount: d.ClickCount})
	}
	referrers := make([]statsReferrerResponse, 0, len(summary.ByReferrer))
	for _, r := range summary.ByReferrer {
		referrers = append(referrers, statsReferrerResponse{ReferrerHost: r.ReferrerHost, ClickCount: r.ClickCount})
	}
	return shortURLStatsResponse{
		From:       from.Format(statsDateLayout),
		To:         to.Format(statsDateLayout),
		Daily:      daily,
		ByReferrer: referrers,
	}
}

// parseStatsRange reads ?from=&to= (YYYY-MM-DD) from q, defaulting to the
// trailing 30 days (today inclusive) when omitted. Actual range validation
// (to before from, range too wide) is stats.Service's job — this only
// handles parsing and defaulting.
func parseStatsRange(q map[string][]string) (from, to time.Time, err error) {
	now := time.Now().UTC().Truncate(24 * time.Hour)
	from = now.AddDate(0, 0, -29)
	to = now

	if raw := firstOrEmpty(q["from"]); raw != "" {
		from, err = time.Parse(statsDateLayout, raw)
		if err != nil {
			return time.Time{}, time.Time{}, errors.New("invalid from (expected YYYY-MM-DD)")
		}
	}
	if raw := firstOrEmpty(q["to"]); raw != "" {
		to, err = time.Parse(statsDateLayout, raw)
		if err != nil {
			return time.Time{}, time.Time{}, errors.New("invalid to (expected YYYY-MM-DD)")
		}
	}
	return from, to, nil
}

func firstOrEmpty(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// handleGetShortURLStats returns a short URL's daily click counts and
// referrer breakdown (4節). Visibility follows the same owner/editor/
// viewer-or-system_admin rule as handleGetShortURL, via resolveAccess.
func (s *server) handleGetShortURLStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, access, _, subject, err := s.resolveAccess(ctx, r)
	if !s.writeAccessError(w, r, err) {
		return
	}

	// resolveAccess's Visible check only looks at the caller's own grant
	// (or AdminOverride), never at whether the short URL row itself
	// exists — a system_admin's AdminOverride is granted unconditionally,
	// so an admin querying a nonexistent id would otherwise sail through
	// to GetStats and get back an empty-but-200 result instead of 404.
	if _, err := s.shortURLGet.FindByID(ctx, id); errors.Is(err, shorturl.ErrNotFound) {
		http.NotFound(w, r)
		return
	} else if err != nil {
		slog.Error("find short url failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	from, to, err := parseStatsRange(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// from/to are inclusive calendar-day bounds from the client's
	// perspective ("through this day"), but Reader's range is half-open
	// ([from, to)) — extend to by one day so that day's clicks are
	// actually included.
	toExclusive := to.AddDate(0, 0, 1)

	summary, err := s.stats.GetStats(ctx, id, from, toExclusive)
	if errors.Is(err, stats.ErrInvalidRange) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		slog.Error("get short url stats failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if access.AdminOverride {
		if err := s.authStore.RecordAuditLog(ctx, auth.AuditLogEntry{
			ActorUserID: &subject.UserID,
			Action:      "stats.admin_view",
			TargetType:  "short_url",
			TargetID:    id.String(),
		}); err != nil {
			slog.Error("audit log write failed", "error", err)
		}
	}

	writeJSON(w, http.StatusOK, toShortURLStatsResponse(summary, from, to))
}
