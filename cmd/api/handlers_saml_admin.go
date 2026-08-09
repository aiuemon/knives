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

type samlConfigResponse struct {
	ID             uuid.UUID `json:"id"`
	Name           string    `json:"name"`
	IdPEntityID    string    `json:"idp_entity_id"`
	IdPSSOURL      string    `json:"idp_sso_url"`
	IdPCertificate string    `json:"idp_certificate"`
	EmailAttribute string    `json:"email_attribute"`
	Trusted        bool      `json:"trusted"`
	Enabled        bool      `json:"enabled"`
}

func toSAMLConfigResponse(c *auth.SAMLConfig) samlConfigResponse {
	return samlConfigResponse{
		ID:             c.ID,
		Name:           c.Name,
		IdPEntityID:    c.IdPEntityID,
		IdPSSOURL:      c.IdPSSOURL,
		IdPCertificate: c.IdPCertificate,
		EmailAttribute: c.EmailAttribute,
		Trusted:        c.Trusted,
		Enabled:        c.Enabled,
	}
}

type samlConfigRequest struct {
	Name           string `json:"name"`
	IdPEntityID    string `json:"idp_entity_id"`
	IdPSSOURL      string `json:"idp_sso_url"`
	IdPCertificate string `json:"idp_certificate"`
	EmailAttribute string `json:"email_attribute"`
	Trusted        bool   `json:"trusted"`
	Enabled        bool   `json:"enabled"`
}

func (r samlConfigRequest) toInput() auth.SAMLConfigInput {
	return auth.SAMLConfigInput{
		Name:           r.Name,
		IdPEntityID:    r.IdPEntityID,
		IdPSSOURL:      r.IdPSSOURL,
		IdPCertificate: r.IdPCertificate,
		EmailAttribute: r.EmailAttribute,
		Trusted:        r.Trusted,
		Enabled:        r.Enabled,
	}
}

func (s *server) handleListSAMLConfigs(w http.ResponseWriter, r *http.Request) {
	configs, err := s.samlConfigs.List(r.Context())
	if err != nil {
		slog.Error("list saml configs failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	resp := make([]samlConfigResponse, 0, len(configs))
	for _, c := range configs {
		resp = append(resp, toSAMLConfigResponse(c))
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleCreateSAMLConfig registers a new SAML IdP connection. 3.4節-2:
// trusted must be set deliberately by the admin (SAML has no standard
// verified-email claim like OIDC), so it's a plain required field here, not
// defaulted to true.
func (s *server) handleCreateSAMLConfig(w http.ResponseWriter, r *http.Request) {
	subject, ok := subjectFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()

	var req samlConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	cfg, err := s.samlConfigs.Create(ctx, req.toInput())
	switch {
	case errors.Is(err, auth.ErrInvalidSAMLConfig):
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	case err != nil:
		slog.Error("create saml config failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := s.authStore.RecordAuditLog(ctx, auth.AuditLogEntry{
		ActorUserID: &subject.UserID,
		Action:      "admin.saml_config_created",
		TargetType:  "idp_saml_config",
		TargetID:    cfg.ID.String(),
	}); err != nil {
		slog.Error("audit log write failed", "error", err)
	}

	writeJSON(w, http.StatusCreated, toSAMLConfigResponse(cfg))
}

func (s *server) handleUpdateSAMLConfig(w http.ResponseWriter, r *http.Request) {
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

	var req samlConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	cfg, err := s.samlConfigs.Update(ctx, id, req.toInput())
	switch {
	case errors.Is(err, auth.ErrInvalidSAMLConfig):
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	case errors.Is(err, auth.ErrNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		slog.Error("update saml config failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := s.authStore.RecordAuditLog(ctx, auth.AuditLogEntry{
		ActorUserID: &subject.UserID,
		Action:      "admin.saml_config_updated",
		TargetType:  "idp_saml_config",
		TargetID:    id.String(),
	}); err != nil {
		slog.Error("audit log write failed", "error", err)
	}

	writeJSON(w, http.StatusOK, toSAMLConfigResponse(cfg))
}

// handleDeleteSAMLConfig refuses (409) to remove a config that still has
// linked auth_identities — see auth.SAMLConfigService.Delete. Admins should
// set enabled=false instead to stop new logins without breaking existing
// linked users.
func (s *server) handleDeleteSAMLConfig(w http.ResponseWriter, r *http.Request) {
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

	err = s.samlConfigs.Delete(ctx, id)
	switch {
	case errors.Is(err, auth.ErrSAMLConfigInUse):
		http.Error(w, err.Error(), http.StatusConflict)
		return
	case errors.Is(err, auth.ErrNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		slog.Error("delete saml config failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := s.authStore.RecordAuditLog(ctx, auth.AuditLogEntry{
		ActorUserID: &subject.UserID,
		Action:      "admin.saml_config_deleted",
		TargetType:  "idp_saml_config",
		TargetID:    id.String(),
	}); err != nil {
		slog.Error("audit log write failed", "error", err)
	}

	w.WriteHeader(http.StatusNoContent)
}
