# knives

社内向け短縮URLシステム。既存の [YOURLS](https://github.com/YOURLS/YOURLS) を置き換える新規システムで、短縮URLの複数人共同管理(owner/editor/viewer)、アクセス統計の権限制御、ローカル(パスキー対応)/SAML/OIDC認証を提供する。

設計の詳細は [`docs/architecture.md`](docs/architecture.md) を参照。

## 構成

- `cmd/api` — 管理系API・認証・統計API
- `cmd/redirect` — リダイレクト専用サーバ
- `cmd/worker` — 非同期クリックロギング・統計集計
- `cmd/migrate-yourls` — YOURLSデータ移行CLI
- `internal/` — ドメインロジック(認証・権限・統計・ストレージ・キャッシュ)
- `web/` — フロントエンド(React + TypeScript)
- `db/migrations/` — DBスキーマ

## セットアップ

```sh
go build ./...
go test ./...
```

```sh
cp .env.example .env
docker compose up --build   # http://knives.localhost:8000/app/
```

`docker-compose.yaml` は PostgreSQL / Redis に加え、`api`・`redirect`・`worker`・`web` とリバースプロキシ(nginx)を1つのFQDN配下でまとめて起動する(1.4節)。環境変数は `.env.example` を参照。

## 開発フロー

Issue → ブランチ(`issue-<番号>/<説明>`) → PR → レビュー → squash merge。詳細は [`CLAUDE.md`](CLAUDE.md) を参照。

## License

[MIT](LICENSE)
