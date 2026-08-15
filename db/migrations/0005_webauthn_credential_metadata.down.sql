ALTER TABLE webauthn_credentials DROP COLUMN IF EXISTS last_used_at;
ALTER TABLE webauthn_credentials DROP COLUMN IF EXISTS created_at;
ALTER TABLE webauthn_credentials DROP COLUMN IF EXISTS name;
