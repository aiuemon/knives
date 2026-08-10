package main

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/aiuemon/knives/internal/auth"
)

// oidcConfigResponse deliberately has no ClientSecret field — the API
// never round-trips it back to the client once stored, even to a
// system_admin. See auth.OIDCConfigInput's doc comment for how edits
// without a new secret are handled.
type oidcConfigResponse struct {
	ID                        uuid.UUID `json:"id"`
	Name                      string    `json:"name"`
	Issuer                    string    `json:"issuer"`
	ClientID                  string    `json:"client_id"`
	Scopes                    []string  `json:"scopes"`
	RequireEmailVerifiedClaim bool      `json:"require_email_verified_claim"`
	Enabled                   bool      `json:"enabled"`
}

func toOIDCConfigResponse(c *auth.OIDCConfig) oidcConfigResponse {
	return oidcConfigResponse{
		ID:                        c.ID,
		Name:                      c.Name,
		Issuer:                    c.Issuer,
		ClientID:                  c.ClientID,
		Scopes:                    c.Scopes,
		RequireEmailVerifiedClaim: c.RequireEmailVerifiedClaim,
		Enabled:                   c.Enabled,
	}
}

type oidcConfigRequest struct {
	Name     string `json:"name"`
	Issuer   string `json:"issuer"`
	ClientID string `json:"client_id"`
	// ClientSecret is required on create; on update, leave it empty to
	// keep the existing secret (it's never sent back to the client to
	// resend).
	ClientSecret              string   `json:"client_secret,omitempty"`
	Scopes                    []string `json:"scopes"`
	RequireEmailVerifiedClaim bool     `json:"require_email_verified_claim"`
	Enabled                   bool     `json:"enabled"`
}

func (r oidcConfigRequest) toInput() auth.OIDCConfigInput {
	return auth.OIDCConfigInput{
		Name:                      r.Name,
		Issuer:                    r.Issuer,
		ClientID:                  r.ClientID,
		ClientSecret:              r.ClientSecret,
		Scopes:                    r.Scopes,
		RequireEmailVerifiedClaim: r.RequireEmailVerifiedClaim,
		Enabled:                   r.Enabled,
	}
}

func (s *server) handleListOIDCConfigs(w http.ResponseWriter, r *http.Request) {
	configs, err := s.oidcConfigs.List(r.Context())
	if err != nil {
		slog.Error("list oidc configs failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	resp := make([]oidcConfigResponse, 0, len(configs))
	for _, c := range configs {
		resp = append(resp, toOIDCConfigResponse(c))
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) handleCreateOIDCConfig(w http.ResponseWriter, r *http.Request) {
	subject, ok := subjectFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()

	var req oidcConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	cfg, err := s.oidcConfigs.Create(ctx, req.toInput())
	switch {
	case errors.Is(err, auth.ErrInvalidOIDCConfig):
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	case err != nil:
		slog.Error("create oidc config failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := s.authStore.RecordAuditLog(ctx, auth.AuditLogEntry{
		ActorUserID: &subject.UserID,
		Action:      "admin.oidc_config_created",
		TargetType:  "idp_oidc_config",
		TargetID:    cfg.ID.String(),
	}); err != nil {
		slog.Error("audit log write failed", "error", err)
	}

	writeJSON(w, http.StatusCreated, toOIDCConfigResponse(cfg))
}

func (s *server) handleUpdateOIDCConfig(w http.ResponseWriter, r *http.Request) {
	subject, ok := subjectFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}

	var req oidcConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	cfg, err := s.oidcConfigs.Update(ctx, id, req.toInput())
	switch {
	case errors.Is(err, auth.ErrInvalidOIDCConfig):
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	case errors.Is(err, auth.ErrNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		slog.Error("update oidc config failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := s.authStore.RecordAuditLog(ctx, auth.AuditLogEntry{
		ActorUserID: &subject.UserID,
		Action:      "admin.oidc_config_updated",
		TargetType:  "idp_oidc_config",
		TargetID:    id.String(),
	}); err != nil {
		slog.Error("audit log write failed", "error", err)
	}

	writeJSON(w, http.StatusOK, toOIDCConfigResponse(cfg))
}

// handleDeleteOIDCConfig refuses (409) to remove a config that still has
// linked auth_identities — see auth.OIDCConfigService.Delete. Admins
// should set enabled=false instead to stop new logins without breaking
// existing linked users.
func (s *server) handleDeleteOIDCConfig(w http.ResponseWriter, r *http.Request) {
	subject, ok := subjectFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}

	err = s.oidcConfigs.Delete(ctx, id)
	switch {
	case errors.Is(err, auth.ErrOIDCConfigInUse):
		http.Error(w, err.Error(), http.StatusConflict)
		return
	case errors.Is(err, auth.ErrNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		slog.Error("delete oidc config failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := s.authStore.RecordAuditLog(ctx, auth.AuditLogEntry{
		ActorUserID: &subject.UserID,
		Action:      "admin.oidc_config_deleted",
		TargetType:  "idp_oidc_config",
		TargetID:    id.String(),
	}); err != nil {
		slog.Error("audit log write failed", "error", err)
	}

	w.WriteHeader(http.StatusNoContent)
}
