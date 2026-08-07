-- name: FindLocalCredential :one
SELECT user_id, password_hash, failed_attempts, locked_until
FROM local_credentials
WHERE user_id = $1;

-- name: UpsertLocalCredentialPassword :exec
INSERT INTO local_credentials (user_id, password_hash, failed_attempts, locked_until)
VALUES ($1, $2, 0, NULL)
ON CONFLICT (user_id) DO UPDATE
SET password_hash = EXCLUDED.password_hash, failed_attempts = 0, locked_until = NULL;

-- name: RecordFailedLoginAttempt :exec
UPDATE local_credentials
SET failed_attempts = $2, locked_until = $3
WHERE user_id = $1;

-- name: ResetFailedLoginAttempts :exec
UPDATE local_credentials
SET failed_attempts = 0, locked_until = NULL
WHERE user_id = $1;
