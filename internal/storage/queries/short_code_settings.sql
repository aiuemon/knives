-- name: FindShortCodeSettings :one
SELECT charset, length
FROM short_code_settings
WHERE id;
