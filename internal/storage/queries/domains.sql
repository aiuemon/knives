-- name: FindDefaultDomain :one
SELECT id
FROM domains
WHERE is_default;
