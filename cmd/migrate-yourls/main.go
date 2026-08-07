// Command migrate-yourls is a one-shot CLI that migrates data from an
// existing YOURLS installation (yourls_url table) into short_urls, along
// with owner assignment from an organization-provided CSV mapping
// (keyword -> owner email). See docs/architecture.md, 10節.
package main

import (
	"flag"
	"log/slog"
	"os"
)

type config struct {
	yourlsDSN  string
	targetDSN  string
	ownersCSV  string
	systemUser string
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.yourlsDSN, "yourls-dsn", "", "移行元YOURLSデータベースのDSN")
	flag.StringVar(&cfg.targetDSN, "target-dsn", "", "移行先PostgreSQLのDSN")
	flag.StringVar(&cfg.ownersCSV, "owners-csv", "", "keyword,owner_email 形式のオーナー対応表CSVのパス")
	flag.StringVar(&cfg.systemUser, "fallback-owner-email", "migration-import@example.com", "CSVに対応の無いURLの仮オーナー(移行専用システムユーザ)のメールアドレス")
	flag.Parse()
	return cfg
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg := parseFlags()
	if cfg.yourlsDSN == "" || cfg.targetDSN == "" {
		slog.Error("yourls-dsn と target-dsn は必須です")
		flag.Usage()
		os.Exit(2)
	}

	slog.Info("migrate-yourls starting", "owners_csv", cfg.ownersCSV)

	// TODO:
	// 1. yourls_url(keyword, url, title, timestamp, clicks)を読み込む
	// 2. short_urls へ source=yourls_import として変換投入する
	// 3. owners-csv(keyword -> email)を読み込み、対応するユーザが未作成なら
	//    未ログイン状態のユーザレコードを先に作成した上で url_permissions(role=owner)へ投入する
	// 4. CSVに記載のないURLは fallback-owner-email を仮オーナーとする
	// 5. クリック統計は click_events へは移行せず、累計値を click_stats_daily へ1件投入する

	slog.Info("migrate-yourls not yet implemented")
}
