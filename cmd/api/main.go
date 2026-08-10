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
	"github.com/aiuemon/knives/internal/cache"
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

	credentialCipher, err := storage.NewCredentialCipher(os.Getenv("CREDENTIAL_ENCRYPTION_KEY"))
	if err != nil {
		slog.Error("invalid CREDENTIAL_ENCRYPTION_KEY", "error", err)
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

	// cmd/redirect用ホットパスキャッシュを、編集/削除時に無効化するために
	// ここでも保持する(6節-2)。チャンネル名はcmd/redirectと一致させる必要
	// がある。
	shortURLCache, err := cache.New(cache.Config{Redis: redisClient, InvalidationChannel: "shorturl:invalidate"})
	if err != nil {
		slog.Error("cache init failed", "error", err)
		os.Exit(1)
	}

	authStore := storage.NewAuthStore(pool)
	credentialStore := storage.NewLocalCredentialStore(pool)
	permissionStore := storage.NewPermissionStore(pool)
	shortURLStore := storage.NewShortURLStore(pool)
	authSettingsStore := storage.NewAuthSettingsStore(pool)
	signupVerificationStore := storage.NewLocalSignupVerificationStore(pool)
	samlConfigStore := storage.NewSAMLConfigStore(pool)
	oidcConfigStore := storage.NewOIDCConfigStore(pool, credentialCipher)

	domainStore := storage.NewRedirectStore(pool) // FindDefaultDomain is shared with cmd/redirect
	domainID, err := domainStore.FindDefaultDomain(ctx)
	if err != nil {
		slog.Error("no default domain configured", "error", err)
		os.Exit(1)
	}

	// web/ のSPA(ログイン→一覧表示→承認、メール確認画面等)の公開URL。
	// メール内のリンクはここを指す。
	webPublicBaseURL := getenv("WEB_PUBLIC_BASE_URL", "http://localhost:5173")
	// このAPIサーバ自身の外部到達可能なURL。SAMLのSP EntityID/ACS URL等、
	// IdPがコールバックする先はSPAではなくこのAPIなので別に持つ(3.2節)。
	apiPublicBaseURL := getenv("API_PUBLIC_BASE_URL", "http://localhost:8080")

	resolver := &auth.Resolver{
		Store:           authStore,
		Mailer:          mailer,
		AuthSettings:    authSettingsStore,
		ConfirmBaseURL:  webPublicBaseURL + "/auth/confirm-link",
		PendingLinksURL: webPublicBaseURL + "/pending-links",
	}

	samlLogin := &auth.SAMLLoginService{
		Configs:       samlConfigStore,
		Nonces:        auth.NewRedisSAMLNonceStore(redisClient),
		Resolver:      resolver,
		PublicBaseURL: apiPublicBaseURL,
	}
	oidcLogin := &auth.OIDCLoginService{
		Configs:       oidcConfigStore,
		Nonces:        auth.NewRedisOIDCNonceStore(redisClient),
		Resolver:      resolver,
		PublicBaseURL: apiPublicBaseURL,
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
			VerifyBaseURL: webPublicBaseURL + "/auth/local/verify-email",
		},
		authSettings: authSettingsStore,
		permissions:  permissionStore,
		shortURLs:    &shorturl.Service{Store: shortURLStore},
		shortURLGet:  shortURLStore,
		cache:        shortURLCache,
		samlConfigs:  &auth.SAMLConfigService{Store: samlConfigStore},
		samlLogin:    samlLogin,
		oidcConfigs:  &auth.OIDCConfigService{Store: oidcConfigStore},
		oidcLogin:    oidcLogin,

		domainID: domainID,

		sessionCookieName: sessionCookieName,
		sessionTTL:        sessionTTL,
		secureCookies:     secureCookies,
		webPublicBaseURL:  webPublicBaseURL,
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
