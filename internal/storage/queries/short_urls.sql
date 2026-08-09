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

-- name: ListShortURLsForUser :many
SELECT su.id, su.domain_id, su.short_code, su.long_url, su.title, su.description, su.created_by, su.status, su.expires_at, su.source, su.created_at, su.updated_at
FROM short_urls su
JOIN url_permissions up ON up.short_url_id = su.id
WHERE up.user_id = $1
ORDER BY su.created_at DESC
LIMIT $2 OFFSET $3;

-- name: ListAllShortURLs :many
SELECT id, domain_id, short_code, long_url, title, description, created_by, status, expires_at, source, created_at, updated_at
FROM short_urls
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: UpdateShortURLFields :one
UPDATE short_urls
SET long_url = $2, title = $3, description = $4, expires_at = $5, updated_at = now()
WHERE id = $1
RETURNING id, domain_id, short_code, long_url, title, description, created_by, status, expires_at, source, created_at, updated_at;

-- name: SetShortURLStatus :exec
UPDATE short_urls
SET status = $2, updated_at = now()
WHERE id = $1;
