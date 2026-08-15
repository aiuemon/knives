ALTER TABLE webauthn_credentials DROP COLUMN IF EXISTS backup_state;
ALTER TABLE webauthn_credentials DROP COLUMN IF EXISTS backup_eligible;
ALTER TABLE webauthn_credentials DROP COLUMN IF EXISTS user_verified;
ALTER TABLE webauthn_credentials DROP COLUMN IF EXISTS user_present;
