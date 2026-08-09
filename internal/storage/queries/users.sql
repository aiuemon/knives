-- name: FindUserByEmail :one
SELECT id, email, email_verified
FROM users
WHERE email = $1;

-- name: FindUserByID :one
SELECT id, email, email_verified
FROM users
WHERE id = $1;

-- name: CreateUser :one
INSERT INTO users (email, email_verified)
VALUES ($1, $2)
RETURNING id, email, email_verified;

-- name: FindIsSystemAdmin :one
SELECT is_system_admin
FROM users
WHERE id = $1;

-- name: ListUsers :many
SELECT id, email, email_verified, is_system_admin, status, created_at
FROM users
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: FindAdminUserByID :one
SELECT id, email, email_verified, is_system_admin, status, created_at
FROM users
WHERE id = $1;

-- name: SetSystemAdmin :execrows
UPDATE users
SET is_system_admin = $2, updated_at = now()
WHERE id = $1;

-- name: SetUserStatus :execrows
UPDATE users
SET status = $2, updated_at = now()
WHERE id = $1;
