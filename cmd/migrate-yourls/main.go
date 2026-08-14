// Command migrate-yourls is a one-shot CLI that migrates data from an
// existing YOURLS installation into short_urls, along with owner
// assignment from an organization-provided CSV mapping (keyword -> owner
// email). See docs/architecture.md, 10節.
//
// The YOURLS source is read from a CSV export of its yourls_url table
// (e.g. via `mysqldump --tab` or phpMyAdmin's CSV export), not a live
// MySQL connection — this keeps the migration tool free of a MySQL
// driver dependency (Go's de facto standard one, go-sql-driver/mysql, is
// MPL-2.0, which .claude/rules/license-policy.md's permissive allowlist
// doesn't cover) and decouples the migration run from the legacy
// database's availability.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aiuemon/knives/internal/storage"
)

type config struct {
	yourlsCSV  string
	targetDSN  string
	ownersCSV  string
	systemUser string
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.yourlsCSV, "yourls-csv", "", "YOURLSのyourls_urlテーブルをエクスポートしたCSV(keyword,url,title,timestamp,clicksの列を含む)のパス")
	flag.StringVar(&cfg.targetDSN, "target-dsn", "", "移行先PostgreSQLのDSN")
	flag.StringVar(&cfg.ownersCSV, "owners-csv", "", "keyword,owner_email 形式のオーナー対応表CSVのパス(省略可。省略時は全URLがfallback-owner-emailの仮オーナーになる)")
	flag.StringVar(&cfg.systemUser, "fallback-owner-email", "migration-import@example.com", "全移行データのcreated_by、および対応表に無いURLの仮オーナーとなる移行専用システムユーザのメールアドレス")
	flag.Parse()
	return cfg
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg := parseFlags()
	if cfg.yourlsCSV == "" || cfg.targetDSN == "" {
		slog.Error("yourls-csv と target-dsn は必須です")
		flag.Usage()
		os.Exit(2)
	}

	rows, err := readYourlsCSV(cfg.yourlsCSV)
	if err != nil {
		slog.Error("yourls-csv の読み込みに失敗しました", "error", err)
		os.Exit(1)
	}
	owners, err := readOwnersCSV(cfg.ownersCSV)
	if err != nil {
		slog.Error("owners-csv の読み込みに失敗しました", "error", err)
		os.Exit(1)
	}
	slog.Info("migrate-yourls starting", "rows", len(rows), "owners_mapped", len(owners))

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.targetDSN)
	if err != nil {
		slog.Error("connect to postgres failed", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	domainID, err := storage.NewRedirectStore(pool).FindDefaultDomain(ctx)
	if err != nil {
		slog.Error("no default domain configured", "error", err)
		os.Exit(1)
	}

	s, err := runMigration(
		ctx,
		storage.NewAuthStore(pool),
		storage.NewMigrationStore(pool),
		domainID,
		cfg.systemUser,
		rows,
		owners,
	)
	if err != nil {
		slog.Error("migration failed", "error", err)
		os.Exit(1)
	}

	slog.Info("migrate-yourls finished", "migrated", s.Migrated, "skipped", s.Skipped, "failed", s.Failed, "total", len(rows))
	if s.Failed > 0 {
		os.Exit(1)
	}
}
