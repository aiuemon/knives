-- name: CreatePendingLinkRequest :one
INSERT INTO pending_link_requests (
    existing_user_id, candidate_provider_type, candidate_provider_config_id, candidate_subject, token_hash, expires_at
)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id;

-- name: FindPendingLinkRequestByTokenHash :one
SELECT id, existing_user_id, candidate_provider_type, candidate_provider_config_id, candidate_subject, expires_at, confirmed_at
FROM pending_link_requests
WHERE token_hash = $1;

-- name: FindPendingLinkRequestByID :one
SELECT id, existing_user_id, candidate_provider_type, candidate_provider_config_id, candidate_subject, expires_at, confirmed_at
FROM pending_link_requests
WHERE id = $1;

-- name: FindPendingLinkRequestsForUser :many
SELECT id, existing_user_id, candidate_provider_type, candidate_provider_config_id, candidate_subject, expires_at, confirmed_at
FROM pending_link_requests
WHERE existing_user_id = $1
  AND confirmed_at IS NULL
  AND expires_at > now()
ORDER BY expires_at ASC;

-- name: ConfirmPendingLinkRequest :exec
UPDATE pending_link_requests
SET confirmed_at = $2
WHERE id = $1;
