package main

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/aiuemon/knives/internal/auth"
)

type publicSAMLIdPResponse struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

// handleListSAMLIdPs is public (unauthenticated): the login page needs to
// render a "Login with X" link per enabled IdP before anyone has a
// session. Only id/name are exposed here — the certificate/SSO URL/etc.
// stay behind the system_admin-only /api/admin/saml-configs.
func (s *server) handleListSAMLIdPs(w http.ResponseWriter, r *http.Request) {
	configs, err := s.samlConfigs.List(r.Context())
	if err != nil {
		slog.Error("list saml configs failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	resp := make([]publicSAMLIdPResponse, 0, len(configs))
	for _, c := range configs {
		if c.Enabled {
			resp = append(resp, publicSAMLIdPResponse{ID: c.ID, Name: c.Name})
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleSAMLLoginRedirect starts the SP-initiated flow (3.2節):
// /auth/saml/{id}/login sends the browser on to the IdP with a signed(-ish;
// see SAMLLoginService) AuthnRequest.
func (s *server) handleSAMLLoginRedirect(w http.ResponseWriter, r *http.Request) {
	configID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}

	redirectURL, err := s.samlLogin.BeginLogin(r.Context(), configID)
	if errors.Is(err, auth.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		slog.Error("saml begin login failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// handleSAMLACS is the Assertion Consumer Service (3.2節): the IdP's page
// auto-submits a POST form here, so the response must be a full-page
// redirect (never JSON — there is no script on the IdP's page to read it)
// back into the SPA, carrying only a coarse-grained outcome in the query
// string so nothing about *why* a login failed leaks to the browser.
func (s *server) handleSAMLACS(w http.ResponseWriter, r *http.Request) {
	configID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}

	result, err := s.samlLogin.HandleACS(r.Context(), configID, r)
	switch {
	case errors.Is(err, auth.ErrNotFound):
		http.NotFound(w, r)
		return
	case errors.Is(err, auth.ErrSAMLResponseInvalid), errors.Is(err, auth.ErrSAMLReplay):
		slog.Warn("saml acs rejected", "error", err)
		http.Redirect(w, r, s.webPublicBaseURL+webAppPathPrefix+"/login?error=saml_failed", http.StatusFound)
		return
	case err != nil:
		slog.Error("saml acs failed", "error", err)
		http.Redirect(w, r, s.webPublicBaseURL+webAppPathPrefix+"/login?error=saml_failed", http.StatusFound)
		return
	}

	switch result.Outcome {
	case auth.OutcomePendingConfirmation:
		http.Redirect(w, r, s.webPublicBaseURL+webAppPathPrefix+"/login?notice=saml_pending_confirmation", http.StatusFound)
	default:
		sessionToken, err := s.sessions.Create(r.Context(), result.User.ID, s.sessionTTL)
		if err != nil {
			slog.Error("session create failed", "error", err)
			http.Redirect(w, r, s.webPublicBaseURL+webAppPathPrefix+"/login?error=saml_failed", http.StatusFound)
			return
		}
		s.setSessionCookie(w, sessionToken)
		http.Redirect(w, r, s.webPublicBaseURL+webAppPathPrefix+"/", http.StatusFound)
	}
}
