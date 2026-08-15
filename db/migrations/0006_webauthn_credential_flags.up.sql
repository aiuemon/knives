-- go-webauthn(webauthn/doc.go, "Storage"節)は、認証器のフラグ
-- (UserPresent/UserVerified/BackupEligible/BackupState)をCredential
-- レコードの必須永続化項目としている。特にBackupEligibleは、保存されて
-- いる値が今回のログイン時のアサーションと一致しないと go-webauthn 側で
-- ログイン自体を拒否する(validateLogin)ため、これを永続化していないと
-- バックアップ対象(iCloud Keychain等で同期される)パスキーのログインが
-- 常に失敗する。
ALTER TABLE webauthn_credentials ADD COLUMN user_present boolean NOT NULL DEFAULT false;
ALTER TABLE webauthn_credentials ADD COLUMN user_verified boolean NOT NULL DEFAULT false;
ALTER TABLE webauthn_credentials ADD COLUMN backup_eligible boolean NOT NULL DEFAULT false;
ALTER TABLE webauthn_credentials ADD COLUMN backup_state boolean NOT NULL DEFAULT false;
