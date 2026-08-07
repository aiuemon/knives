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
