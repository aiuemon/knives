-- name: InsertMigratedShortURL :one
-- cmd/migrate-yourls専用(10節)。status/sourceは移行データに常に固定の値
-- ('active'/'yourls_import')のためリテラルで埋め込み、created_atは
-- YOURLS側のtimestampをそのまま引き継ぐ(通常のInsertShortURLはnow()任せ)。
INSERT INTO short_urls (domain_id, short_code, long_url, title, created_by, status, source, created_at)
VALUES ($1, $2, $3, $4, $5, 'active', 'yourls_import', $6)
RETURNING id;

-- name: SetMigratedClickStatsDaily :exec
-- 通常の運用中の集計(UpsertClickStatsDaily)は既存値に加算するが、移行は
-- 「移行時点までの累計値を1レコードとして投入する」(10節)ため、
-- 加算ではなく上書きする。再実行時に同じ日付・同じ値で入れ直しても
-- 安全(冪等)。
INSERT INTO click_stats_daily (short_url_id, date, click_count)
VALUES ($1, $2, $3)
ON CONFLICT (short_url_id, date) DO UPDATE SET click_count = EXCLUDED.click_count;
