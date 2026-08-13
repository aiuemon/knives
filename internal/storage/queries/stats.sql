-- name: FindDailyClickCounts :many
SELECT date, click_count
FROM click_stats_daily
WHERE short_url_id = $1
  AND date >= $2
  AND date < $3
ORDER BY date;

-- name: FindReferrerClickCounts :many
SELECT COALESCE(referrer_host, '') AS referrer_host, COUNT(*) AS click_count
FROM click_events
WHERE short_url_id = $1
  AND clicked_at >= $2
  AND clicked_at < $3
GROUP BY referrer_host
ORDER BY click_count DESC;
