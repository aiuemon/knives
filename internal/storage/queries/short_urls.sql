-- name: FindRedirectTarget :one
SELECT id, long_url
FROM short_urls
WHERE domain_id = $1
  AND short_code = $2
  AND status = 'active'
  AND (expires_at IS NULL OR expires_at > now());

-- name: InsertShortURL :one
INSERT INTO short_urls (domain_id, short_code, long_url, title, description, created_by, status, expires_at, source)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id, created_at;

-- name: FindShortURLByID :one
SELECT id, domain_id, short_code, long_url, title, description, created_by, status, expires_at, source, created_at, updated_at
FROM short_urls
WHERE id = $1;

-- ListShortURLsForUser/ListAllShortURLs (filter+sort+pagination+total count,
-- 4.1節) are hand-written in shorturl_store.go instead of here: sqlc can't
-- parameterize a dynamic ORDER BY column, which this listing needs to let
-- every displayed field be sortable.

-- name: UpdateShortURLFields :one
UPDATE short_urls
SET long_url = $2, title = $3, description = $4, expires_at = $5, updated_at = now()
WHERE id = $1
RETURNING id, domain_id, short_code, long_url, title, description, created_by, status, expires_at, source, created_at, updated_at;

-- name: SetShortURLStatus :exec
UPDATE short_urls
SET status = $2, updated_at = now()
WHERE id = $1;
