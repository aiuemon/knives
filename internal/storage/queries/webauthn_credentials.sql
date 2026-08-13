-- name: FindWebAuthnCredentialsByUserID :many
SELECT id, user_id, credential_id, public_key, sign_count, transports
FROM webauthn_credentials
WHERE user_id = $1
ORDER BY id;

-- name: InsertWebAuthnCredential :exec
INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, transports)
VALUES ($1, $2, $3, $4, $5);

-- name: UpdateWebAuthnCredentialSignCount :exec
UPDATE webauthn_credentials
SET sign_count = $2
WHERE credential_id = $1;

-- name: DeleteWebAuthnCredential :execrows
DELETE FROM webauthn_credentials
WHERE id = $1 AND user_id = $2;
