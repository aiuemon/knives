-- name: FindAuthSettings :one
SELECT local_auth_enabled, self_signup_enabled, require_email_confirmation_for_signup
FROM auth_settings
WHERE id;
