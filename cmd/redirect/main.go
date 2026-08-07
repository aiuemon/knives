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

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	addr := os.Getenv("REDIRECT_LISTEN_ADDR")
	if addr == "" {
		addr = ":8081"
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// TODO: internal/cache(Redis cache-aside + ristretto)経由での
	// short_code -> long_url 解決、302リダイレクト、クリックイベントの
	// 非同期push(Redis Stream)、プロセス内レート制限(x/time/rate)を実装する。
	r.Get("/{code}", func(w http.ResponseWriter, r *http.Request) {
		_ = chi.URLParam(r, "code")
		http.NotFound(w, r)
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("redirect server starting", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("redirect server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("redirect server shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("redirect server shutdown failed", "error", err)
	}
}
