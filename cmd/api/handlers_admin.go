package main

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/aiuemon/knives/internal/auth"
)

type authSettingsResponse struct {
	LocalAuthEnabled            bool `json:"local_auth_enabled"`
	SelfSignupEnabled           bool `json:"self_signup_enabled"`
	RequireEmailConfirmation    bool `json:"require_email_confirmation_for_signup"`
	RequireReauthForAccountLink bool `json:"require_reauth_for_account_link"`
}

func (s *server) handleGetAuthSettings(w http.ResponseWriter, r *http.Request) {
	local, selfSignup, requireConfirm, requireReauth, err := s.authSettings.FindAuthSettings(r.Context())
	if err != nil {
		slog.Error("find auth settings failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, authSettingsResponse{
		LocalAuthEnabled:            local,
		SelfSignupEnabled:           selfSignup,
		RequireEmailConfirmation:    requireConfirm,
		RequireReauthForAccountLink: requireReauth,
	})
}

type patchAuthSettingsRequest struct {
	LocalAuthEnabled            *bool `json:"local_auth_enabled,omitempty"`
	SelfSignupEnabled           *bool `json:"self_signup_enabled,omitempty"`
	RequireEmailConfirmation    *bool `json:"require_email_confirmation_for_signup,omitempty"`
	RequireReauthForAccountLink *bool `json:"require_reauth_for_account_link,omitempty"`
}

// handlePatchAuthSettings merges the given fields onto the current
// single-row settings (unset fields are left unchanged) since this is a
// PATCH, not a PUT. 5節: 管理者の設定変更は監査ログに記録する。
func (s *server) handlePatchAuthSettings(w http.ResponseWriter, r *http.Request) {
	subject, ok := subjectFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()

	var req patchAuthSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	local, selfSignup, requireConfirm, requireReauth, err := s.authSettings.FindAuthSettings(ctx)
	if err != nil {
		slog.Error("find auth settings failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if req.LocalAuthEnabled != nil {
		local = *req.LocalAuthEnabled
	}
	if req.SelfSignupEnabled != nil {
		selfSignup = *req.SelfSignupEnabled
	}
	if req.RequireEmailConfirmation != nil {
		requireConfirm = *req.RequireEmailConfirmation
	}
	if req.RequireReauthForAccountLink != nil {
		requireReauth = *req.RequireReauthForAccountLink
	}

	if err := s.authSettings.UpdateAuthSettings(ctx, local, selfSignup, requireConfirm, requireReauth); err != nil {
		slog.Error("update auth settings failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := s.authStore.RecordAuditLog(ctx, auth.AuditLogEntry{
		ActorUserID: &subject.UserID,
		Action:      "admin.auth_settings_updated",
		TargetType:  "auth_settings",
	}); err != nil {
		slog.Error("audit log write failed", "error", err)
	}

	writeJSON(w, http.StatusOK, authSettingsResponse{
		LocalAuthEnabled:            local,
		SelfSignupEnabled:           selfSignup,
		RequireEmailConfirmation:    requireConfirm,
		RequireReauthForAccountLink: requireReauth,
	})
}

type adminUserResponse struct {
	ID            uuid.UUID `json:"id"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	IsSystemAdmin bool      `json:"is_system_admin"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
}

func toAdminUserResponse(u *auth.AdminUser) adminUserResponse {
	return adminUserResponse{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		IsSystemAdmin: u.IsSystemAdmin,
		Status:        string(u.Status),
		CreatedAt:     u.CreatedAt,
	}
}

func (s *server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	limit := atoiOrZero(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := atoiOrZero(r.URL.Query().Get("offset"))

	users, err := s.authStore.ListUsers(r.Context(), limit, offset)
	if err != nil {
		slog.Error("list users failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp := make([]adminUserResponse, 0, len(users))
	for _, u := range users {
		resp = append(resp, toAdminUserResponse(u))
	}
	writeJSON(w, http.StatusOK, resp)
}

type patchUserRequest struct {
	IsSystemAdmin *bool   `json:"is_system_admin,omitempty"`
	Status        *string `json:"status,omitempty"`
}

// handlePatchUser grants/revokes system_admin and/or changes a user's
// status. Both changes refuse to act on the caller's own account when the
// effect would be a self-lockout (losing admin rights or suspending
// themselves) — otherwise a lone admin could strand the system with no one
// able to administer it.
func (s *server) handlePatchUser(w http.ResponseWriter, r *http.Request) {
	subject, ok := subjectFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()

	targetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}

	var req patchUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	target, err := s.authStore.FindAdminUserByID(ctx, targetID)
	if errors.Is(err, auth.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		slog.Error("find admin user failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if req.IsSystemAdmin != nil {
		if targetID == subject.UserID && !*req.IsSystemAdmin {
			http.Error(w, "cannot revoke your own system_admin status", http.StatusConflict)
			return
		}
		if err := s.authStore.SetSystemAdmin(ctx, targetID, *req.IsSystemAdmin); err != nil {
			slog.Error("set system admin failed", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		target.IsSystemAdmin = *req.IsSystemAdmin

		action := "admin.system_admin_revoked"
		if *req.IsSystemAdmin {
			action = "admin.system_admin_granted"
		}
		if err := s.authStore.RecordAuditLog(ctx, auth.AuditLogEntry{
			ActorUserID: &subject.UserID,
			Action:      action,
			TargetType:  "user",
			TargetID:    targetID.String(),
		}); err != nil {
			slog.Error("audit log write failed", "error", err)
		}
	}

	if req.Status != nil {
		status := auth.UserStatus(*req.Status)
		if status != auth.UserStatusActive && status != auth.UserStatusSuspended {
			http.Error(w, `status must be "active" or "suspended"`, http.StatusBadRequest)
			return
		}
		if targetID == subject.UserID && status == auth.UserStatusSuspended {
			http.Error(w, "cannot suspend your own account", http.StatusConflict)
			return
		}
		if err := s.authStore.SetUserStatus(ctx, targetID, status); err != nil {
			slog.Error("set user status failed", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		target.Status = status

		if err := s.authStore.RecordAuditLog(ctx, auth.AuditLogEntry{
			ActorUserID: &subject.UserID,
			Action:      "admin.user_status_changed",
			TargetType:  "user",
			TargetID:    targetID.String(),
			Metadata:    map[string]any{"status": string(status)},
		}); err != nil {
			slog.Error("audit log write failed", "error", err)
		}
	}

	writeJSON(w, http.StatusOK, toAdminUserResponse(target))
}
