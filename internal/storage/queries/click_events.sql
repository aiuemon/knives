-- name: InsertClickEvent :one
INSERT INTO click_events (short_url_id, clicked_at, referrer_host, user_agent_raw, ip_hash, country_code, os, browser, stream_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (clicked_at, stream_id) DO NOTHING
RETURNING id;

-- name: UpsertClickStatsDaily :exec
INSERT INTO click_stats_daily (short_url_id, date, click_count)
VALUES ($1, $2, $3)
ON CONFLICT (short_url_id, date) DO UPDATE SET click_count = click_stats_daily.click_count + EXCLUDED.click_count;
