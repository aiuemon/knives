package main

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/aiuemon/knives/internal/auth"
	"github.com/aiuemon/knives/internal/permission"
)

type urlPermissionResponse struct {
	UserID    uuid.UUID `json:"user_id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	GrantedAt time.Time `json:"granted_at"`
}

// handleListURLPermissions is gated by CanManagePermissions (owner-only),
// not merely Visible: who else can see/edit a URL is itself sensitive, so
// viewers/editors don't get to enumerate it.
func (s *server) handleListURLPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, access, _, _, err := s.resolveAccess(ctx, r)
	if !s.writeAccessError(w, r, err) {
		return
	}
	if !access.CanManagePermissions {
		http.NotFound(w, r)
		return
	}

	grants, err := s.permissions.ListGrants(ctx, id)
	if err != nil {
		slog.Error("list url permissions failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp := make([]urlPermissionResponse, 0, len(grants))
	for _, g := range grants {
		resp = append(resp, urlPermissionResponse{UserID: g.UserID, Email: g.Email, Role: string(g.Role), GrantedAt: g.GrantedAt})
	}
	writeJSON(w, http.StatusOK, resp)
}

type grantURLPermissionRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

// handleGrantURLPermission invites a user as editor or viewer (4.2節:
// ownerが他ユーザをeditor/viewerとして招待可能; co-ownership isn't
// grantable through this endpoint). If the email has never signed up, a
// placeholder user is created — the same pattern 10節 uses for YOURLS
// migration — so the invite works before the invitee's first login.
func (s *server) handleGrantURLPermission(w http.ResponseWriter, r *http.Request) {
	subject, ok := subjectFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()
	id, access, _, _, err := s.resolveAccess(ctx, r)
	if !s.writeAccessError(w, r, err) {
		return
	}
	if !access.CanManagePermissions {
		http.NotFound(w, r)
		return
	}

	var req grantURLPermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	role := permission.Role(req.Role)
	if role != permission.RoleEditor && role != permission.RoleViewer {
		http.Error(w, "role must be \"editor\" or \"viewer\"", http.StatusBadRequest)
		return
	}

	addr, err := mail.ParseAddress(strings.TrimSpace(req.Email))
	if err != nil {
		http.Error(w, "invalid email", http.StatusBadRequest)
		return
	}

	invitee, err := s.authStore.FindUserByEmail(ctx, addr.Address)
	if errors.Is(err, auth.ErrNotFound) {
		invitee, err = s.authStore.CreateUser(ctx, addr.Address, false)
	}
	if err != nil {
		slog.Error("find/create invitee failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := s.permissions.Grant(ctx, id, invitee.ID, role, subject.UserID); err != nil {
		slog.Error("grant url permission failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, urlPermissionResponse{UserID: invitee.ID, Email: invitee.Email, Role: string(role)})
}

// handleRevokeURLPermission refuses to remove the last remaining owner
// (permission.WouldOrphanOwnership) so a URL can never end up with nobody
// able to manage it or delete it.
func (s *server) handleRevokeURLPermission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, access, _, _, err := s.resolveAccess(ctx, r)
	if !s.writeAccessError(w, r, err) {
		return
	}
	if !access.CanManagePermissions {
		http.NotFound(w, r)
		return
	}

	targetUserID, err := uuid.Parse(chi.URLParam(r, "userId"))
	if err != nil {
		http.NotFound(w, r)
		return
	}

	targetGrant, err := s.permissions.FindGrant(ctx, id, targetUserID)
	if err != nil {
		slog.Error("find target grant failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if targetGrant == nil {
		http.NotFound(w, r)
		return
	}

	ownerCount, err := s.permissions.CountOwners(ctx, id)
	if err != nil {
		slog.Error("count owners failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if permission.WouldOrphanOwnership(targetGrant.Role, ownerCount) {
		http.Error(w, "cannot remove the last remaining owner", http.StatusConflict)
		return
	}

	if err := s.permissions.Revoke(ctx, id, targetUserID); err != nil {
		slog.Error("revoke url permission failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
