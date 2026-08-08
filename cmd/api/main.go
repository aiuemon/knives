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

	mailer, err := buildMailer()
	if err != nil {
		slog.Error("mailer init failed", "error", err)
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

	authStore := storage.NewAuthStore(pool)
	credentialStore := storage.NewLocalCredentialStore(pool)
	permissionStore := storage.NewPermissionStore(pool)
	shortURLStore := storage.NewShortURLStore(pool)
	authSettingsStore := storage.NewAuthSettingsStore(pool)
	signupVerificationStore := storage.NewLocalSignupVerificationStore(pool)

	domainStore := storage.NewRedirectStore(pool) // FindDefaultDomain is shared with cmd/redirect
	domainID, err := domainStore.FindDefaultDomain(ctx)
	if err != nil {
		slog.Error("no default domain configured", "error", err)
		os.Exit(1)
	}

	publicBaseURL := getenv("API_PUBLIC_BASE_URL", "http://localhost:8080")

	resolver := &auth.Resolver{
		Store:          authStore,
		Mailer:         mailer,
		AuthSettings:   authSettingsStore,
		ConfirmBaseURL: publicBaseURL + "/api/auth/confirm-link",
		// web/ のSPAはまだ存在しないため、暫定的にAPIのJSONエンドポイントへ
		// 直接誘導する。フロントエンド実装後は、ログイン→一覧表示→承認を
		// 行う専用ページのURLに差し替えること。
		PendingLinksURL: publicBaseURL + "/api/auth/pending-links",
	}

	srv := &server{
		sessions:  auth.NewRedisSessionStore(redisClient),
		authStore: authStore,
		localAuth: &auth.LocalAuthenticator{Users: authStore, Credentials: credentialStore},
		resolver:  resolver,
		localSignup: &auth.LocalSignup{
			Store:         signupVerificationStore,
			Mailer:        mailer,
			Resolver:      resolver,
			Credentials:   credentialStore,
			VerifyBaseURL: publicBaseURL + "/api/auth/local/verify-email",
		},
		authSettings: authSettingsStore,
		permissions:  permissionStore,
		shortURLs:    &shorturl.Creator{Store: shortURLStore},
		shortURLGet:  shortURLStore,

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

// mailer is the union of the two mail-sending roles auth needs: account-link
// confirmation (3.4節) and local-signup email verification (3.1節).
// SMTPMailer implements both; so does the logMailer fallback below.
type mailer interface {
	auth.ConfirmationMailer
	auth.SignupVerificationMailer
}

// buildMailer returns a real SMTPMailer when SMTP_HOST is configured, or a
// logMailer fallback for local development so the signup/confirm-link flow
// is exercisable without a real mail server. Production deployments must
// set SMTP_HOST.
func buildMailer() (mailer, error) {
	smtpHost := os.Getenv("SMTP_HOST")
	if smtpHost == "" {
		slog.Warn("SMTP_HOST not set; confirmation/verification emails will only be logged, not sent")
		return logMailer{}, nil
	}

	smtpPort, err := strconv.Atoi(getenv("SMTP_PORT", "587"))
	if err != nil {
		return nil, err
	}
	return auth.NewSMTPMailer(auth.SMTPMailerConfig{
		Host:     smtpHost,
		Port:     smtpPort,
		Username: os.Getenv("SMTP_USERNAME"),
		Password: os.Getenv("SMTP_PASSWORD"),
		From:     getenv("MAIL_FROM", "noreply@example.com"),
	})
}

type logMailer struct{}

func (logMailer) SendAccountLinkConfirmation(_ context.Context, toEmail, confirmURL string) error {
	slog.Warn("confirmation email not sent (no SMTP configured)", "to", toEmail, "confirm_url", confirmURL)
	return nil
}

func (logMailer) SendSignupVerification(_ context.Context, toEmail, verifyURL string) error {
	slog.Warn("verification email not sent (no SMTP configured)", "to", toEmail, "verify_url", verifyURL)
	return nil
}

func (logMailer) SendAccountLinkReviewNotice(_ context.Context, toEmail, reviewURL string) error {
	slog.Warn("review notice not sent (no SMTP configured)", "to", toEmail, "review_url", reviewURL)
	return nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
