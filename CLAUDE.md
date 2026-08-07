# knives

社内向け短縮URLシステム。既存の YOURLS を置き換える新規システムで、複数人での共同管理(owner/editor/viewer)とアクセス統計の権限制御、ローカル/SAML/OIDC/パスキー認証を提供する。設計の詳細は [`docs/architecture.md`](docs/architecture.md) を参照。

## プロジェクトフェーズ

現在: **PROTOTYPE**

| フェーズ | 意味 | 状態 |
|---|---|---|
| **PROTOTYPE** | 試作期 | 試作・検証中。コア機能の開発とプロトタイピング |
| **ALPHA / BETA** | 検証期 | 主要機能が揃い、フィードバック収集・改善中 |
| **PREVIEW** | 公開準備期 | 本番環境に近い状態で最終調整 |
| **STABLE** | 安定稼働期 | 正式リリース。安定稼働中 |

## 言語・ツール

- 言語: Go 1.22+ / TypeScript
- フレームワーク: chi(HTTP) / React 18 + Vite(フロントエンド、`web/`)
- DB: PostgreSQL(pgx + sqlc) / Redis(キャッシュ・セッション・Streams)
- ビルド: `go build ./...`
- テスト: `go test ./...`
- リント: `go vet ./...`
- フォーマット: `gofmt -l .`

## ディレクトリ構成

- `cmd/api` — 管理系API + 認証(SAML/OIDC/WebAuthn) + 統計API
- `cmd/redirect` — リダイレクト専用サーバ(高頻度アクセスのホットパス)
- `cmd/worker` — 非同期クリックロギング、統計集計バッチ
- `cmd/migrate-yourls` — YOURLSデータ移行用ワンショットCLI
- `internal/auth` — 認証コア(アカウント統合ロジックを一元化。api/workerで共有)
- `internal/shorturl` — 短縮URLドメインロジック
- `internal/permission` — URL単位権限判定
- `internal/stats` — 統計集計
- `internal/storage` — DBアクセス層(sqlc生成コード)
- `internal/cache` — Redis/in-memoryキャッシュ抽象化
- `db/migrations` — スキーマ定義(golang-migrate)
- `web` — フロントエンド(React + TypeScript)
- `docs/architecture.md` — アーキテクチャ設計書(一次情報)

詳細な設計判断(データモデル、認証フロー、権限モデル、キャッシュ戦略等)は `docs/architecture.md` を正とする。

## コーディング規約

- フォーマッタ / リンタ: `gofmt` / `go vet`(Go)、Biome または ESLint + Prettier(TypeScript, `web/`)
- 命名規則: 型=PascalCase / 関数・変数=camelCase(Go/TS共通) / 定数=SCREAMING_SNAKE_CASE / ファイル=snake_case(Go) or kebab-case(TS)

## テスト戦略

- Go: 標準 `testing` パッケージ。DBを伴うテストは `testcontainers-go` でPostgreSQL/Redisを起動して実施
- `internal/auth`(アカウント統合ロジック)は最もセキュリティ影響が大きいため、正常系に加えなりすまし・再割当てシナリオのテストを優先する
- フロントエンド: Vitest

## コミットメッセージ規約

[Conventional Commits](https://www.conventionalcommits.org/) に従う(`<type>: <description> (#<issue-number>)`)。
詳細は常時効く制約として `.claude/rules/commit-conventions.md` を正とする。description は日本語で記述する。

## 開発フロー

1. **Issue 作成** — コード/ドキュメント変更には必ず Issue を作る。判断の経緯を Issue に記録する。
2. **ブランチ作成** — `issue-<番号>/<簡単な説明>`(例: `issue-42/add-user-auth`)。
3. **実装** — 作業中は適宜 commit・push。**main への直接 push は禁止**(`.claude/rules/branching.md` ＋ `block-main-push.sh` フックで担保)。
4. **PR 作成** — Issue を参照(`Closes #42`)。
5. **コードレビュー** — マージ前にレビュー(セキュリティ観点を含む)。特に認証・権限・アカウント統合ロジックの変更は入念にレビューする。
6. **squash merge → ブランチ削除**。

## ライセンスルール

permissive ライセンス(MIT / Apache-2.0 / BSD / ISC 等)のみを使い、GPL 系の依存は避ける。
詳細は常時効く制約として `.claude/rules/license-policy.md` を正とする。

## 環境ルール

- sudo は使用しない。ランタイム/ツールのインストールには mise を使う。
- PostgreSQL / Redis は Docker(`docker-compose.yaml`)で管理する。

## 言語ルール

- Issue・PR・コミット等の自然言語はすべて日本語で記述する。
