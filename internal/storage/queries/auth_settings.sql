-- name: FindAuthSettings :one
SELECT local_auth_enabled, self_signup_enabled, require_email_confirmation_for_signup, require_reauth_for_account_link
FROM auth_settings
WHERE id;

-- name: UpdateAuthSettings :exec
UPDATE auth_settings
SET local_auth_enabled = $1,
    self_signup_enabled = $2,
    require_email_confirmation_for_signup = $3,
    require_reauth_for_account_link = $4
WHERE id;
