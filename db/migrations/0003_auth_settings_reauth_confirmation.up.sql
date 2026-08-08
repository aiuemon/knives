-- アカウント統合確認(3.4節-4)の承認方式を管理者が切り替えられるようにする。
-- true(既定): 統合の承認には、統合対象アカウントの既存のログイン方法で
--   再認証することを必須とする(安全側)。
-- false: 従来通り、メール内のリンクをクリックするだけで即時承認できる
--   (メール到達確認のみで足りるため、相対的に弱い)。
ALTER TABLE auth_settings
    ADD COLUMN require_reauth_for_account_link boolean NOT NULL DEFAULT true;
