package main

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/aiuemon/knives/internal/auth"
)

type publicOIDCIdPResponse struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

// handleListOIDCIdPs is public (unauthenticated): the login page needs to
// render a "Login with X" link per enabled IdP before anyone has a
// session. Only id/name are exposed here — everything else stays behind
// the system_admin-only /api/admin/oidc-configs.
func (s *server) handleListOIDCIdPs(w http.ResponseWriter, r *http.Request) {
	configs, err := s.oidcConfigs.List(r.Context())
	if err != nil {
		slog.Error("list oidc configs failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	resp := make([]publicOIDCIdPResponse, 0, len(configs))
	for _, c := range configs {
		if c.Enabled {
			resp = append(resp, publicOIDCIdPResponse{ID: c.ID, Name: c.Name})
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleOIDCLoginRedirect starts the Authorization Code + PKCE flow
// (3.3節): /auth/oidc/{id}/login sends the browser on to the IdP's
// authorization endpoint.
func (s *server) handleOIDCLoginRedirect(w http.ResponseWriter, r *http.Request) {
	configID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}

	redirectURL, err := s.oidcLogin.BeginLogin(r.Context(), configID)
	if errors.Is(err, auth.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		slog.Error("oidc begin login failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// handleOIDCCallback is the Authorization Code callback (3.3節): the IdP
// redirects the browser here as a GET with ?code=&state=, so — like SAML's
// ACS — the response must be a full-page redirect back into the SPA,
// carrying only a coarse-grained outcome so nothing about *why* a login
// failed leaks to the browser.
func (s *server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	configID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}

	result, err := s.oidcLogin.HandleCallback(r.Context(), configID, r)
	switch {
	case errors.Is(err, auth.ErrNotFound):
		http.NotFound(w, r)
		return
	case errors.Is(err, auth.ErrOIDCResponseInvalid):
		slog.Warn("oidc callback rejected", "error", err)
		http.Redirect(w, r, s.webPublicBaseURL+"/login?error=oidc_failed", http.StatusFound)
		return
	case err != nil:
		slog.Error("oidc callback failed", "error", err)
		http.Redirect(w, r, s.webPublicBaseURL+"/login?error=oidc_failed", http.StatusFound)
		return
	}

	switch result.Outcome {
	case auth.OutcomePendingConfirmation:
		http.Redirect(w, r, s.webPublicBaseURL+"/login?notice=oidc_pending_confirmation", http.StatusFound)
	default:
		sessionToken, err := s.sessions.Create(r.Context(), result.User.ID, s.sessionTTL)
		if err != nil {
			slog.Error("session create failed", "error", err)
			http.Redirect(w, r, s.webPublicBaseURL+"/login?error=oidc_failed", http.StatusFound)
			return
		}
		s.setSessionCookie(w, sessionToken)
		http.Redirect(w, r, s.webPublicBaseURL+"/", http.StatusFound)
	}
}
