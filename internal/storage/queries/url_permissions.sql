-- name: FindURLPermission :one
SELECT role
FROM url_permissions
WHERE short_url_id = $1 AND user_id = $2;

-- name: InsertURLPermission :exec
INSERT INTO url_permissions (short_url_id, user_id, role, granted_by)
VALUES ($1, $2, $3, $4);
