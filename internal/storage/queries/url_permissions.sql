-- name: FindURLPermission :one
SELECT role
FROM url_permissions
WHERE short_url_id = $1 AND user_id = $2;

-- name: InsertURLPermission :exec
INSERT INTO url_permissions (short_url_id, user_id, role, granted_by)
VALUES ($1, $2, $3, $4);

-- name: ListURLPermissions :many
SELECT up.user_id, up.role, u.email, up.granted_at
FROM url_permissions up
JOIN users u ON u.id = up.user_id
WHERE up.short_url_id = $1
ORDER BY up.granted_at ASC;

-- name: CountURLOwners :one
SELECT count(*)
FROM url_permissions
WHERE short_url_id = $1 AND role = 'owner';

-- name: UpsertURLPermission :exec
INSERT INTO url_permissions (short_url_id, user_id, role, granted_by)
VALUES ($1, $2, $3, $4)
ON CONFLICT (short_url_id, user_id) DO UPDATE
SET role = EXCLUDED.role, granted_by = EXCLUDED.granted_by, granted_at = now();

-- name: DeleteURLPermission :exec
DELETE FROM url_permissions
WHERE short_url_id = $1 AND user_id = $2;
