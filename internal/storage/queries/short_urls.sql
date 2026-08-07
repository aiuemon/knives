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
RETURNING id;

-- name: FindShortURLByID :one
SELECT id, domain_id, short_code, long_url, title, description, created_by, status, expires_at, source, created_at, updated_at
FROM short_urls
WHERE id = $1;
