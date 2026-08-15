-- name: FindWebAuthnCredentialsByUserID :many
SELECT id, user_id, credential_id, public_key, sign_count, transports, name, created_at, last_used_at,
       user_present, user_verified, backup_eligible, backup_state
FROM webauthn_credentials
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: InsertWebAuthnCredential :exec
INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, transports, name,
                                   user_present, user_verified, backup_eligible, backup_state)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: UpdateWebAuthnCredentialSignCount :exec
-- ログイン成功のたびに呼ばれる(WebAuthnService.applyLoginResult)。
-- go-webauthnのストレージ指針(webauthn/doc.go)により、sign_countと
-- last_used_atに加えbackup_state(変化しうる値)も毎回書き戻す。
-- backup_eligibleは登録時から変化しない値のためここでは更新しない。
UPDATE webauthn_credentials
SET sign_count = $2, backup_state = $3, last_used_at = now()
WHERE credential_id = $1;

-- name: UpdateWebAuthnCredentialName :one
UPDATE webauthn_credentials
SET name = $3
WHERE id = $1 AND user_id = $2
RETURNING id, user_id, credential_id, public_key, sign_count, transports, name, created_at, last_used_at,
          user_present, user_verified, backup_eligible, backup_state;

-- name: DeleteWebAuthnCredential :execrows
DELETE FROM webauthn_credentials
WHERE id = $1 AND user_id = $2;
