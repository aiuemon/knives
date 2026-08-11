// Command worker consumes click events asynchronously and performs
// statistics rollups. See docs/architecture.md, 6節-4,5.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/aiuemon/knives/internal/stats"
	"github.com/aiuemon/knives/internal/storage"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	redisAddr := getenv("REDIS_ADDR", "localhost:6379")
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		slog.Error("DATABASE_URL is required")
		os.Exit(1)
	}

	batchSize, err := strconv.ParseInt(getenv("WORKER_BATCH_SIZE", "100"), 10, 64)
	if err != nil {
		slog.Error("invalid WORKER_BATCH_SIZE", "error", err)
		os.Exit(1)
	}
	blockTimeout, err := time.ParseDuration(getenv("WORKER_BLOCK_TIMEOUT", "5s"))
	if err != nil {
		slog.Error("invalid WORKER_BLOCK_TIMEOUT", "error", err)
		os.Exit(1)
	}
	// at-least-once配送(6節-5)のクラッシュ復旧: このしきい値だけACKなしで
	// 滞留したエントリを、別のconsumerが引き取って再処理する。
	staleThreshold, err := time.ParseDuration(getenv("WORKER_STALE_THRESHOLD", "5m"))
	if err != nil {
		slog.Error("invalid WORKER_STALE_THRESHOLD", "error", err)
		os.Exit(1)
	}

	consumerName := getenv("WORKER_CONSUMER_NAME", "")
	if consumerName == "" {
		if hostname, err := os.Hostname(); err == nil && hostname != "" {
			consumerName = hostname
		} else {
			consumerName = uuid.NewString()
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		slog.Error("connect to postgres failed", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	redisClient := redis.NewClient(&redis.Options{Addr: redisAddr})
	defer redisClient.Close()

	clickStore := storage.NewClickEventStore(pool)
	recorder := &stats.Recorder{Store: clickStore}

	if err := ensurePartitions(ctx, clickStore, time.Now()); err != nil {
		slog.Error("ensure click_events partitions failed", "error", err)
		os.Exit(1)
	}
	go partitionMaintenanceLoop(ctx, clickStore)

	consumer := &clickConsumer{
		redis:          redisClient,
		recorder:       recorder,
		consumerName:   consumerName,
		batchSize:      batchSize,
		blockTimeout:   blockTimeout,
		staleThreshold: staleThreshold,
	}

	slog.Info("worker starting", "consumer", consumerName)
	if err := consumer.run(ctx); err != nil {
		slog.Error("click consumer stopped with error", "error", err)
		os.Exit(1)
	}

	slog.Info("worker shutting down")
}

// ensurePartitions creates click_events' partitions for the current and
// next calendar month, so writes never fall through to the DEFAULT
// partition once the worker is running (0001_init.up.sqlのコメント参照)。
func ensurePartitions(ctx context.Context, store *storage.ClickEventStore, now time.Time) error {
	if err := store.EnsurePartition(ctx, now); err != nil {
		return err
	}
	return store.EnsurePartition(ctx, now.AddDate(0, 1, 0))
}

// partitionMaintenanceLoop keeps re-ensuring the current/next month's
// partitions exist for as long as the worker runs, so a long-lived process
// doesn't fall behind a month boundary.
func partitionMaintenanceLoop(ctx context.Context, store *storage.ClickEventStore) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := ensurePartitions(ctx, store, time.Now()); err != nil {
				slog.Error("ensure click_events partitions failed", "error", err)
			}
		}
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
