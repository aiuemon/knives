// Command api serves the management API: short URL CRUD, permission
// management, statistics, and authentication (local/SAML/OIDC/WebAuthn).
// See docs/architecture.md, 1.1節 and 5節.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/aiuemon/knives/internal/auth"
	"github.com/aiuemon/knives/internal/shorturl"
	"github.com/aiuemon/knives/internal/storage"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	addr := getenv("API_LISTEN_ADDR", ":8080")
	redisAddr := getenv("REDIS_ADDR", "localhost:6379")
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		slog.Error("DATABASE_URL is required")
		os.Exit(1)
	}

	sessionCookieName := getenv("SESSION_COOKIE_NAME", "knives_session")
	sessionTTL, err := time.ParseDuration(getenv("SESSION_TTL", "24h"))
	if err != nil {
		slog.Error("invalid SESSION_TTL", "error", err)
		os.Exit(1)
	}
	secureCookies := true
	if v := os.Getenv("SESSION_COOKIE_SECURE"); v != "" {
		secureCookies, err = strconv.ParseBool(v)
		if err != nil {
			slog.Error("invalid SESSION_COOKIE_SECURE", "error", err)
			os.Exit(1)
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

	authStore := storage.NewAuthStore(pool)
	credentialStore := storage.NewLocalCredentialStore(pool)
	permissionStore := storage.NewPermissionStore(pool)
	shortURLStore := storage.NewShortURLStore(pool)

	domainStore := storage.NewRedirectStore(pool) // FindDefaultDomain is shared with cmd/redirect
	domainID, err := domainStore.FindDefaultDomain(ctx)
	if err != nil {
		slog.Error("no default domain configured", "error", err)
		os.Exit(1)
	}

	srv := &server{
		sessions:    auth.NewRedisSessionStore(redisClient),
		authStore:   authStore,
		localAuth:   &auth.LocalAuthenticator{Users: authStore, Credentials: credentialStore},
		permissions: permissionStore,
		shortURLs:   &shorturl.Creator{Store: shortURLStore},
		shortURLGet: shortURLStore,

		domainID: domainID,

		sessionCookieName: sessionCookieName,
		sessionTTL:        sessionTTL,
		secureCookies:     secureCookies,
	}

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		slog.Info("api server starting", "addr", addr, "domain_id", domainID)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("api server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("api server shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("api server shutdown failed", "error", err)
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
