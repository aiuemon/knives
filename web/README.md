# web

フロントエンド(React + TypeScript)。構成は `docs/architecture.md` 8節を参照。

## Stack

- フレームワーク: React 19 + TypeScript + Vite
- スタイル: Tailwind CSS v4
- ルーティング: react-router-dom
- データフェッチ: TanStack Query
- テスト: Vitest + Testing Library
- lint/format: Biome

## Quick start

```sh
pnpm install
pnpm dev       # http://localhost:5173
```

開発サーバーは `/api/*` へのリクエストを `http://localhost:8080`(cmd/api)にプロキシする(`vite.config.ts`)。cmd/api・cmd/redirect・PostgreSQL・Redisをローカルで起動しておくこと。

## Configuration

`.env.example` を `.env` にコピーして使う。

- `VITE_REDIRECT_BASE_URL` — cmd/redirectの公開URL(短縮リンクのプレビュー表示に使用)

サーバ側(`cmd/api`)の `WEB_PUBLIC_BASE_URL` は、このアプリの公開URLと一致させること(確認メール内のリンク生成に使われる)。

## Layout

- `src/api/` — バックエンドAPIクライアント(`fetch`ラッパー、型定義)
- `src/auth/` — ログイン状態(`GET /api/auth/me`)を保持するReact Context
- `src/pages/` — 画面(ログイン・サインアップ・メール確認・アカウント統合承認・ダッシュボード)
- `src/components/` — 共通コンポーネント(ヘッダー、認証ガード)

## Development

```sh
pnpm test:run   # テスト
pnpm check      # lint + format(自動修正)
pnpm exec tsc -b  # 型チェック
pnpm build      # 本番ビルド
```

## 未実装

- 短縮URLの一覧取得(バックエンドに `GET /api/short-urls` が無いため、作成したURLはセッション内の一覧のみ表示)
- SAML/OIDC/WebAuthnログイン
- 短縮URLの編集・削除・権限管理(招待)・統計表示
