-- name: ListSAMLConfigs :many
SELECT id, name, idp_entity_id, idp_sso_url, idp_certificate, email_attribute, trusted, enabled
FROM idp_saml_configs
ORDER BY name;

-- name: FindSAMLConfigByID :one
SELECT id, name, idp_entity_id, idp_sso_url, idp_certificate, email_attribute, trusted, enabled
FROM idp_saml_configs
WHERE id = $1;

-- name: CreateSAMLConfig :one
INSERT INTO idp_saml_configs (name, idp_entity_id, idp_sso_url, idp_certificate, email_attribute, trusted, enabled)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, name, idp_entity_id, idp_sso_url, idp_certificate, email_attribute, trusted, enabled;

-- name: UpdateSAMLConfig :one
UPDATE idp_saml_configs
SET name = $2, idp_entity_id = $3, idp_sso_url = $4, idp_certificate = $5, email_attribute = $6, trusted = $7, enabled = $8
WHERE id = $1
RETURNING id, name, idp_entity_id, idp_sso_url, idp_certificate, email_attribute, trusted, enabled;

-- name: DeleteSAMLConfig :execrows
DELETE FROM idp_saml_configs
WHERE id = $1;

-- name: CountAuthIdentitiesForSAMLConfig :one
SELECT count(*)
FROM auth_identities
WHERE provider_type = 'saml' AND provider_config_id = $1;
