-- 短縮URLシステム 初期スキーマ(docs/architecture.md 2節の実体化)

CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto; -- gen_random_uuid()

CREATE TYPE user_status AS ENUM ('active', 'suspended');
CREATE TYPE auth_provider_type AS ENUM ('local', 'saml', 'oidc');
CREATE TYPE short_url_status AS ENUM ('active', 'disabled', 'expired');
CREATE TYPE short_url_source AS ENUM ('native', 'yourls_import');
CREATE TYPE url_permission_role AS ENUM ('owner', 'editor', 'viewer');

-- users: 認証方式を問わず1レコード。email が統合キー。
CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email citext NOT NULL UNIQUE,
    email_verified boolean NOT NULL DEFAULT false,
    display_name text,
    is_system_admin boolean NOT NULL DEFAULT false,
    status user_status NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- idp_saml_configs / idp_oidc_configs は auth_identities より先に作る(FK先のため)
CREATE TABLE idp_saml_configs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    idp_entity_id text NOT NULL,
    idp_sso_url text NOT NULL,
    idp_certificate text NOT NULL,
    email_attribute text NOT NULL,
    trusted boolean NOT NULL DEFAULT false,
    enabled boolean NOT NULL DEFAULT false
);

CREATE TABLE idp_oidc_configs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    issuer text NOT NULL,
    client_id text NOT NULL,
    client_secret_encrypted text NOT NULL,
    scopes text[] NOT NULL DEFAULT ARRAY['openid', 'email', 'profile'],
    require_email_verified_claim boolean NOT NULL DEFAULT true,
    enabled boolean NOT NULL DEFAULT false
);

-- auth_identities: 外部/ローカル認証との紐付け(1ユーザに複数可)。
-- provider_config_id は provider_type に応じて idp_saml_configs/idp_oidc_configs
-- のいずれかを指す(local時はNULL)。参照先が可変のためDB外部キー制約は付けず、
-- internal/auth 側で整合性を保証する。
CREATE TABLE auth_identities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider_type auth_provider_type NOT NULL,
    provider_config_id uuid,
    subject text NOT NULL,
    email_at_link citext NOT NULL,
    verified boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    UNIQUE (provider_type, provider_config_id, subject)
);

CREATE INDEX idx_auth_identities_user_id ON auth_identities (user_id);

-- local_credentials
CREATE TABLE local_credentials (
    user_id uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    password_hash text,
    failed_attempts int NOT NULL DEFAULT 0,
    locked_until timestamptz
);

-- webauthn_credentials(パスキー)
CREATE TABLE webauthn_credentials (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id bytea NOT NULL UNIQUE,
    public_key bytea NOT NULL,
    sign_count bigint NOT NULL DEFAULT 0,
    transports text[]
);

CREATE INDEX idx_webauthn_credentials_user_id ON webauthn_credentials (user_id);

-- auth_settings(単一行のシステム設定)
CREATE TABLE auth_settings (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    local_auth_enabled boolean NOT NULL DEFAULT true,
    self_signup_enabled boolean NOT NULL DEFAULT false,
    require_email_confirmation_for_signup boolean NOT NULL DEFAULT true
);

INSERT INTO auth_settings (id) VALUES (true);

-- short_code_settings(単一行のシステム設定・短縮コード生成ポリシー)
CREATE TABLE short_code_settings (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    charset text NOT NULL DEFAULT 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
    length int NOT NULL DEFAULT 7,
    updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO short_code_settings (id) VALUES (true);

-- pending_link_requests(アカウント統合の確認フロー用)
CREATE TABLE pending_link_requests (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    existing_user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    candidate_provider_type auth_provider_type NOT NULL,
    candidate_provider_config_id uuid,
    candidate_subject text NOT NULL,
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    confirmed_at timestamptz
);

CREATE INDEX idx_pending_link_requests_existing_user_id ON pending_link_requests (existing_user_id);

-- domains(カスタムドメイン対応のため今から用意。初期は1レコードのみ運用)
CREATE TABLE domains (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname text NOT NULL UNIQUE,
    is_default boolean NOT NULL DEFAULT false
);

-- is_default=true のレコードは常に高々1件
CREATE UNIQUE INDEX idx_domains_single_default ON domains (is_default) WHERE is_default;

-- short_urls
CREATE TABLE short_urls (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id uuid NOT NULL REFERENCES domains (id),
    short_code text NOT NULL,
    long_url text NOT NULL,
    title text,
    description text,
    created_by uuid NOT NULL REFERENCES users (id),
    status short_url_status NOT NULL DEFAULT 'active',
    expires_at timestamptz,
    source short_url_source NOT NULL DEFAULT 'native',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (domain_id, short_code)
);

CREATE INDEX idx_short_urls_created_by ON short_urls (created_by);

-- url_permissions
CREATE TABLE url_permissions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    short_url_id uuid NOT NULL REFERENCES short_urls (id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role url_permission_role NOT NULL,
    granted_by uuid NOT NULL REFERENCES users (id),
    granted_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (short_url_id, user_id)
);

CREATE INDEX idx_url_permissions_user_id ON url_permissions (user_id);

-- click_events(生ログ、月次パーティション推奨)
-- 初期構築時点では単一の DEFAULT パーティションのみ用意する。運用開始後は
-- cmd/worker 等から月次パーティション(例: click_events_2026_08)を先行作成し、
-- DEFAULT パーティションにデータが溜まらないようにする。
-- PG16未満はパーティション親テーブルに GENERATED AS IDENTITY を付与できないため、
-- シーケンス+DEFAULTで代替する(全バージョン互換)。
CREATE SEQUENCE click_events_id_seq;

CREATE TABLE click_events (
    id bigint NOT NULL DEFAULT nextval('click_events_id_seq'),
    short_url_id uuid NOT NULL REFERENCES short_urls (id),
    clicked_at timestamptz NOT NULL DEFAULT now(),
    referrer_host text,
    user_agent_raw text,
    ip_hash text,
    country_code text,
    PRIMARY KEY (id, clicked_at)
) PARTITION BY RANGE (clicked_at);

ALTER SEQUENCE click_events_id_seq OWNED BY click_events.id;

CREATE TABLE click_events_default PARTITION OF click_events DEFAULT;

CREATE INDEX idx_click_events_short_url_id_clicked_at ON click_events (short_url_id, clicked_at);

-- click_stats_daily(集計ロールアップ)
CREATE TABLE click_stats_daily (
    short_url_id uuid NOT NULL REFERENCES short_urls (id) ON DELETE CASCADE,
    date date NOT NULL,
    click_count bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (short_url_id, date)
);

-- sessions(サーバサイドセッション、5.2節。運用上の実体はRedisだが、
-- スキーマとしても定義しておく)
CREATE TABLE sessions (
    id text PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_sessions_user_id ON sessions (user_id);

-- audit_log
CREATE TABLE audit_log (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_user_id uuid REFERENCES users (id) ON DELETE SET NULL,
    action text NOT NULL,
    target_type text,
    target_id text,
    metadata jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_log_actor_user_id ON audit_log (actor_user_id);
CREATE INDEX idx_audit_log_created_at ON audit_log (created_at);
