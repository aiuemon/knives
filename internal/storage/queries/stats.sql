-- name: FindDailyClickCounts :many
SELECT date, click_count
FROM click_stats_daily
WHERE short_url_id = $1
  AND date >= $2
  AND date < $3
ORDER BY date;

-- name: FindHourlyClickCounts :many
-- click_stats_daily(UTC単位で丸めてロールアップ済み。stats.RecordBatch)と
-- 揃えるため、date_truncはセッションのTimeZone(運用環境ではAsia/Tokyo)
-- ではなく明示的にUTC境界で丸める。
SELECT (date_trunc('hour', clicked_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')::timestamptz AS hour, COUNT(*) AS click_count
FROM click_events
WHERE short_url_id = $1
  AND clicked_at >= $2
  AND clicked_at < $3
GROUP BY hour
ORDER BY hour;

-- name: FindReferrerClickCounts :many
SELECT COALESCE(referrer_host, '') AS referrer_host, COUNT(*) AS click_count
FROM click_events
WHERE short_url_id = $1
  AND clicked_at >= $2
  AND clicked_at < $3
GROUP BY referrer_host
ORDER BY click_count DESC;
