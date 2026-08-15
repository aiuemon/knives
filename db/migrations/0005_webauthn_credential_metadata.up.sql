-- パスキーをユーザ自身が識別しやすくするための表示用メタデータ(3.1節)。
-- nameは他の任意テキストラベル(short_urls.title等)と同じくnullable、
-- created_at/last_used_atで登録日時・最終利用日時を追跡する。
-- last_used_atは登録直後はNULL(まだログインに使われていないため)で、
-- ログイン成功のたびに更新される。
ALTER TABLE webauthn_credentials ADD COLUMN name text;
ALTER TABLE webauthn_credentials ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE webauthn_credentials ADD COLUMN last_used_at timestamptz;
