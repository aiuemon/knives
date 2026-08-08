-- name: FindAuthSettings :one
SELECT local_auth_enabled, self_signup_enabled, require_email_confirmation_for_signup, require_reauth_for_account_link
FROM auth_settings
WHERE id;
