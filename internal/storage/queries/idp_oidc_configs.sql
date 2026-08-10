-- name: ListOIDCConfigs :many
SELECT id, name, issuer, client_id, client_secret_encrypted, scopes, require_email_verified_claim, enabled
FROM idp_oidc_configs
ORDER BY name;

-- name: FindOIDCConfigByID :one
SELECT id, name, issuer, client_id, client_secret_encrypted, scopes, require_email_verified_claim, enabled
FROM idp_oidc_configs
WHERE id = $1;

-- name: CreateOIDCConfig :one
INSERT INTO idp_oidc_configs (name, issuer, client_id, client_secret_encrypted, scopes, require_email_verified_claim, enabled)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, name, issuer, client_id, client_secret_encrypted, scopes, require_email_verified_claim, enabled;

-- name: UpdateOIDCConfig :one
UPDATE idp_oidc_configs
SET name = $2, issuer = $3, client_id = $4, scopes = $5, require_email_verified_claim = $6, enabled = $7
WHERE id = $1
RETURNING id, name, issuer, client_id, client_secret_encrypted, scopes, require_email_verified_claim, enabled;

-- name: UpdateOIDCConfigWithSecret :one
UPDATE idp_oidc_configs
SET name = $2, issuer = $3, client_id = $4, client_secret_encrypted = $5, scopes = $6, require_email_verified_claim = $7, enabled = $8
WHERE id = $1
RETURNING id, name, issuer, client_id, client_secret_encrypted, scopes, require_email_verified_claim, enabled;

-- name: DeleteOIDCConfig :execrows
DELETE FROM idp_oidc_configs
WHERE id = $1;

-- name: CountAuthIdentitiesForOIDCConfig :one
SELECT count(*)
FROM auth_identities
WHERE provider_type = 'oidc' AND provider_config_id = $1;
