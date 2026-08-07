-- name: FindURLPermission :one
SELECT role
FROM url_permissions
WHERE short_url_id = $1 AND user_id = $2;
