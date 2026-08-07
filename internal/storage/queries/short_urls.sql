-- name: FindRedirectTarget :one
SELECT id, long_url
FROM short_urls
WHERE domain_id = $1
  AND short_code = $2
  AND status = 'active'
  AND (expires_at IS NULL OR expires_at > now());
