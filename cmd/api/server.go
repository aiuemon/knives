package main

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/aiuemon/knives/internal/auth"
	"github.com/aiuemon/knives/internal/permission"
	"github.com/aiuemon/knives/internal/shorturl"
)

// permissionChecker is the subset of storage.PermissionStore the API
// handlers need; declared here (rather than depending on the concrete
// storage type directly) so handler tests can fake it without a database.
type permissionChecker interface {
	FindGrant(ctx context.Context, shortURLID, userID uuid.UUID) (*permission.Grant, error)
	IsSystemAdmin(ctx context.Context, userID uuid.UUID) (bool, error)
}

type server struct {
	sessions    auth.SessionStore
	authStore   auth.Store // also used for audit_log writes (stats.admin_view, 4.1節)
	localAuth   *auth.LocalAuthenticator
	permissions permissionChecker
	shortURLs   *shorturl.Creator
	shortURLGet shorturl.Store

	domainID uuid.UUID

	sessionCookieName string
	sessionTTL        time.Duration
	secureCookies     bool
}

func (s *server) routes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r.Route("/api", func(r chi.Router) {
		r.Post("/auth/local/login", s.handleLocalLogin)
		r.Post("/auth/logout", s.handleLogout)

		r.Group(func(r chi.Router) {
			r.Use(s.requireAuth)
			r.Post("/short-urls", s.handleCreateShortURL)
			r.Get("/short-urls/{id}", s.handleGetShortURL)
		})
	})

	// TODO: SAML/OIDC/WebAuthn, ローカルセルフサインアップ(要 3.4節の確認
	// メールフロー・Mailer実装)、短縮URLの一覧/更新/削除、権限管理、統計API。
	return r
}
