// Command redirect is the hot-path redirect server: short_code -> long_url
// lookups served from cache, with PostgreSQL only as a cache-miss fallback.
// Stateless; scales horizontally. See docs/architecture.md, 6節.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/aiuemon/knives/internal/cache"
	"github.com/aiuemon/knives/internal/storage"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	addr := getenv("REDIRECT_LISTEN_ADDR", ":8081")
	redisAddr := getenv("REDIS_ADDR", "localhost:6379")
	databaseURL := os.Getenv("DATABASE_URL")
	ipHashSalt := os.Getenv("IP_HASH_SALT")
	if databaseURL == "" {
		slog.Error("DATABASE_URL is required")
		os.Exit(1)
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

	shortURLCache, err := cache.New(cache.Config{Redis: redisClient, InvalidationChannel: "shorturl:invalidate"})
	if err != nil {
		slog.Error("cache init failed", "error", err)
		os.Exit(1)
	}
	go func() {
		if err := shortURLCache.Subscribe(ctx); err != nil && !errors.Is(err, context.Canceled) {
			slog.Error("cache invalidation subscription stopped", "error", err)
		}
	}()

	store := storage.NewRedirectStore(pool)
	domainID, err := store.FindDefaultDomain(ctx)
	if err != nil {
		slog.Error("no default domain configured", "error", err)
		os.Exit(1)
	}

	limiter := newIPRateLimiter(20, 40) // 6節-0: プロセス内・IPごとのトークンバケット
	go limiter.cleanupLoop(ctx, 5*time.Minute, 10*time.Minute)

	srv := &server{
		cache:       shortURLCache,
		store:       store,
		redisClient: redisClient,
		domainID:    domainID,
		ipHashSalt:  ipHashSalt,
		limiter:     limiter,
	}

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		slog.Info("redirect server starting", "addr", addr, "domain_id", domainID)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("redirect server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("redirect server shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("redirect server shutdown failed", "error", err)
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
