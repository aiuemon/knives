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
	"github.com/aiuemon/knives/internal/storage"
)

// samlLoginService is the subset of *auth.SAMLLoginService the login/ACS
// handlers need; declared here (rather than depending on the concrete type
// directly) so handler tests can fake it without driving a real crewjam/saml
// round trip — that's covered thoroughly in internal/auth's own tests.
type samlLoginService interface {
	BeginLogin(ctx context.Context, configID uuid.UUID) (string, error)
	HandleACS(ctx context.Context, configID uuid.UUID, r *http.Request) (*auth.Result, error)
}

// permissionChecker is the subset of storage.PermissionStore the API
// handlers need; declared here (rather than depending on the concrete
// storage type directly) so handler tests can fake it without a database.
type permissionChecker interface {
	FindGrant(ctx context.Context, shortURLID, userID uuid.UUID) (*permission.Grant, error)
	IsSystemAdmin(ctx context.Context, userID uuid.UUID) (bool, error)
	ListGrants(ctx context.Context, shortURLID uuid.UUID) ([]storage.GrantWithEmail, error)
	CountOwners(ctx context.Context, shortURLID uuid.UUID) (int, error)
	Grant(ctx context.Context, shortURLID, userID uuid.UUID, role permission.Role, grantedBy uuid.UUID) error
	Revoke(ctx context.Context, shortURLID, userID uuid.UUID) error
}

// authSettingsChecker is the subset of storage.AuthSettingsStore the signup
// and admin-settings handlers need.
type authSettingsChecker interface {
	FindAuthSettings(ctx context.Context) (localAuthEnabled, selfSignupEnabled, requireEmailConfirmation, requireReauthForAccountLink bool, err error)
	UpdateAuthSettings(ctx context.Context, localAuthEnabled, selfSignupEnabled, requireEmailConfirmation, requireReauthForAccountLink bool) error
}

// shortURLCacheInvalidator is the subset of *cache.Cache the API needs:
// purge the redirect hot-path cache after an edit/disable so a stale
// mapping doesn't outlive the edit (6節-2). *cache.Cache satisfies this.
type shortURLCacheInvalidator interface {
	Invalidate(ctx context.Context, key string) error
}

type server struct {
	sessions     auth.SessionStore
	authStore    auth.Store // also used for audit_log writes (stats.admin_view, 4.1節)
	localAuth    *auth.LocalAuthenticator
	resolver     *auth.Resolver // account-link confirmation (3.4節), used directly by handleConfirmLink
	localSignup  *auth.LocalSignup
	authSettings authSettingsChecker
	permissions  permissionChecker
	shortURLs    *shorturl.Service
	shortURLGet  shorturl.Store
	cache        shortURLCacheInvalidator
	samlConfigs  *auth.SAMLConfigService
	samlLogin    samlLoginService
	oidcConfigs  *auth.OIDCConfigService

	domainID uuid.UUID

	sessionCookieName string
	sessionTTL        time.Duration
	secureCookies     bool
	// webPublicBaseURL is where handleSAMLACS redirects the browser after
	// the IdP posts back (3.2節) — SAML's HTTP-POST binding means ACS must
	// respond with a full-page redirect, never JSON.
	webPublicBaseURL string
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
		r.Post("/auth/local/signup", s.handleLocalSignup)
		r.Get("/auth/local/verify-email", s.handleVerifyEmail)
		r.Get("/auth/confirm-link", s.handleConfirmLink)
		r.Post("/auth/logout", s.handleLogout)

		r.Get("/auth/saml/idps", s.handleListSAMLIdPs)
		r.Get("/auth/saml/{id}/login", s.handleSAMLLoginRedirect)
		r.Post("/auth/saml/{id}/acs", s.handleSAMLACS)

		r.Group(func(r chi.Router) {
			r.Use(s.requireAuth)
			r.Get("/auth/me", s.handleMe)
			r.Post("/auth/local/password", s.handleSetPassword)
			r.Get("/auth/pending-links", s.handleListPendingLinks)
			r.Post("/auth/pending-links/{id}/approve", s.handleApprovePendingLink)

			r.Get("/short-urls", s.handleListShortURLs)
			r.Post("/short-urls", s.handleCreateShortURL)
			r.Get("/short-urls/{id}", s.handleGetShortURL)
			r.Patch("/short-urls/{id}", s.handleUpdateShortURL)
			r.Delete("/short-urls/{id}", s.handleDeleteShortURL)

			r.Get("/short-urls/{id}/permissions", s.handleListURLPermissions)
			r.Post("/short-urls/{id}/permissions", s.handleGrantURLPermission)
			r.Delete("/short-urls/{id}/permissions/{userId}", s.handleRevokeURLPermission)

			r.Route("/admin", func(r chi.Router) {
				r.Use(s.requireSystemAdmin)
				r.Get("/auth-settings", s.handleGetAuthSettings)
				r.Patch("/auth-settings", s.handlePatchAuthSettings)
				r.Get("/users", s.handleListUsers)
				r.Patch("/users/{id}", s.handlePatchUser)

				r.Get("/saml-configs", s.handleListSAMLConfigs)
				r.Post("/saml-configs", s.handleCreateSAMLConfig)
				r.Patch("/saml-configs/{id}", s.handleUpdateSAMLConfig)
				r.Delete("/saml-configs/{id}", s.handleDeleteSAMLConfig)

				r.Get("/oidc-configs", s.handleListOIDCConfigs)
				r.Post("/oidc-configs", s.handleCreateOIDCConfig)
				r.Patch("/oidc-configs/{id}", s.handleUpdateOIDCConfig)
				r.Delete("/oidc-configs/{id}", s.handleDeleteOIDCConfig)
			})
		})
	})

	// TODO: OIDC、WebAuthn、統計API。
	return r
}
