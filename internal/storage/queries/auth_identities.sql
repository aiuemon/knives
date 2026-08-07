-- name: FindAuthIdentity :one
SELECT id, user_id, email_at_link
FROM auth_identities
WHERE provider_type = $1
  AND provider_config_id IS NOT DISTINCT FROM $2
  AND subject = $3;

-- name: CountAuthIdentitiesForUser :one
SELECT count(*)
FROM auth_identities
WHERE user_id = $1;

-- name: CreateAuthIdentity :one
INSERT INTO auth_identities (user_id, provider_type, provider_config_id, subject, email_at_link, verified)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, user_id, email_at_link;

-- name: TouchAuthIdentity :exec
UPDATE auth_identities
SET last_used_at = $2
WHERE id = $1;
