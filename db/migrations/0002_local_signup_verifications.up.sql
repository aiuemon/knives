-- ローカル自己サインアップのメール到達確認(3.1節)。
-- users/local_credentialsは、このテーブルの検証トークンが確認されるまで
-- 一切作成しない。パスワードはこの時点でargon2idハッシュ化して保持し、
-- 平文は残さない。
CREATE TABLE local_signup_verifications (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email citext NOT NULL,
    password_hash text NOT NULL,
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_local_signup_verifications_email ON local_signup_verifications (email);
