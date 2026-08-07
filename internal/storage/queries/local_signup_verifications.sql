-- name: CreateLocalSignupVerification :one
INSERT INTO local_signup_verifications (email, password_hash, token_hash, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING id;

-- name: FindLocalSignupVerificationByTokenHash :one
SELECT id, email, password_hash, expires_at
FROM local_signup_verifications
WHERE token_hash = $1;

-- name: DeleteLocalSignupVerification :exec
DELETE FROM local_signup_verifications
WHERE id = $1;
