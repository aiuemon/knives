-- name: FindWebAuthnCredentialsByUserID :many
SELECT id, user_id, credential_id, public_key, sign_count, transports, name, created_at, last_used_at
FROM webauthn_credentials
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: InsertWebAuthnCredential :exec
INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, transports, name)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: UpdateWebAuthnCredentialSignCount :exec
-- ログイン成功のたびに呼ばれる(WebAuthnService.applyLoginResult)ため、
-- sign_countと合わせてlast_used_atも更新する。
UPDATE webauthn_credentials
SET sign_count = $2, last_used_at = now()
WHERE credential_id = $1;

-- name: UpdateWebAuthnCredentialName :one
UPDATE webauthn_credentials
SET name = $3
WHERE id = $1 AND user_id = $2
RETURNING id, user_id, credential_id, public_key, sign_count, transports, name, created_at, last_used_at;

-- name: DeleteWebAuthnCredential :execrows
DELETE FROM webauthn_credentials
WHERE id = $1 AND user_id = $2;
