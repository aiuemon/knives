package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/aiuemon/knives/internal/auth"
	"github.com/aiuemon/knives/internal/permission"
	"github.com/aiuemon/knives/internal/shorturl"
)

type createShortURLRequest struct {
	LongURL     string     `json:"long_url"`
	CustomAlias string     `json:"custom_alias,omitempty"`
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

type updateShortURLRequest struct {
	LongURL     string     `json:"long_url"`
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

type shortURLResponse struct {
	ID          uuid.UUID  `json:"id"`
	ShortCode   string     `json:"short_code"`
	LongURL     string     `json:"long_url"`
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Status      string     `json:"status"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	// YourRole is the caller's own url_permissions role ("owner",
	// "editor", "viewer"), or "" when their visibility comes purely from
	// AdminOverride (system_admin viewing a URL they hold no grant on,
	// 4.1節) — the frontend needs this (and the Can* flags below) to
	// decide which of edit/delete/manage-permissions buttons to show,
	// since a system_admin's unlimited view is otherwise view-only.
	YourRole             string `json:"your_role,omitempty"`
	CanEdit              bool   `json:"can_edit"`
	CanDelete            bool   `json:"can_delete"`
	CanManagePermissions bool   `json:"can_manage_permissions"`
}

func toShortURLResponse(su *shorturl.ShortURL, access permission.Access, grant *permission.Grant) shortURLResponse {
	resp := shortURLResponse{
		ID:                   su.ID,
		ShortCode:            su.ShortCode,
		LongURL:              su.LongURL,
		Title:                su.Title,
		Description:          su.Description,
		Status:               string(su.Status),
		ExpiresAt:            su.ExpiresAt,
		CanEdit:              access.CanEdit,
		CanDelete:            access.CanDelete,
		CanManagePermissions: access.CanManagePermissions,
	}
	if grant != nil {
		resp.YourRole = string(grant.Role)
	}
	return resp
}

func (s *server) handleCreateShortURL(w http.ResponseWriter, r *http.Request) {
	subject, ok := subjectFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req createShortURLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	su, err := s.shortURLs.Create(r.Context(), shorturl.CreateInput{
		DomainID:    s.domainID,
		CustomAlias: req.CustomAlias,
		LongURL:     req.LongURL,
		Title:       req.Title,
		Description: req.Description,
		CreatedBy:   subject.UserID,
		ExpiresAt:   req.ExpiresAt,
	})
	switch {
	case errors.Is(err, shorturl.ErrInvalidLongURL), errors.Is(err, shorturl.ErrInvalidAlias):
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	case errors.Is(err, shorturl.ErrAliasTaken):
		http.Error(w, err.Error(), http.StatusConflict)
		return
	case err != nil:
		slog.Error("create short url failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 作成者は同一トランザクション内で自動的にownerになる
	// (shorturl.Store.CreateShortURLのドキュメント参照、4.2節)。
	ownerGrant := &permission.Grant{UserID: subject.UserID, Role: permission.RoleOwner}
	ownerAccess := permission.Resolve(subject, ownerGrant)
	writeJSON(w, http.StatusCreated, toShortURLResponse(su, ownerAccess, ownerGrant))
}

// handleListShortURLs returns the caller's own short URLs (自身が作成/招待
// された短縮URLの管理のみ、4.1節). A system_admin instead sees every short
// URL by default (4.1節: 全短縮URLの閲覧は無制限) unless ?scope=mine is
// given to see just their own.
func (s *server) handleListShortURLs(w http.ResponseWriter, r *http.Request) {
	subject, ok := subjectFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	page := shorturl.ListPage{
		Limit:  atoiOrZero(r.URL.Query().Get("limit")),
		Offset: atoiOrZero(r.URL.Query().Get("offset")),
	}

	var (
		items []*shorturl.ShortURL
		err   error
	)
	if subject.IsSystemAdmin && r.URL.Query().Get("scope") != "mine" {
		items, err = s.shortURLs.ListAll(ctx, page)
	} else {
		items, err = s.shortURLs.ListForUser(ctx, subject.UserID, page)
	}
	if err != nil {
		slog.Error("list short urls failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp := make([]shortURLResponse, 0, len(items))
	for _, su := range items {
		grant, err := s.permissions.FindGrant(ctx, su.ID, subject.UserID)
		if err != nil {
			slog.Error("find grant failed while building short url list", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		access := permission.Resolve(subject, grant)
		resp = append(resp, toShortURLResponse(su, access, grant))
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) handleGetShortURL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, access, grant, subject, err := s.resolveAccess(ctx, r)
	if !s.writeAccessError(w, r, err) {
		return
	}

	su, err := s.shortURLGet.FindByID(ctx, id)
	if errors.Is(err, shorturl.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		slog.Error("find short url failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if access.AdminOverride {
		if err := s.authStore.RecordAuditLog(ctx, auth.AuditLogEntry{
			ActorUserID: &subject.UserID,
			Action:      "stats.admin_view",
			TargetType:  "short_url",
			TargetID:    id.String(),
		}); err != nil {
			// 監査ログの書き込み失敗はレスポンス自体をブロックしない
			// (4.1節: 閲覧のブロックはしないが証跡は残す、が原則ではあるが
			// 一時的なログ書き込み障害でユーザ操作を止める設計にはしない)。
			slog.Error("audit log write failed", "error", err)
		}
	}

	writeJSON(w, http.StatusOK, toShortURLResponse(su, access, grant))
}

func (s *server) handleUpdateShortURL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, access, grant, _, err := s.resolveAccess(ctx, r)
	if !s.writeAccessError(w, r, err) {
		return
	}
	if !access.CanEdit {
		http.NotFound(w, r) // 4.2節: 権限不足は403ではなく404で秘匿する
		return
	}

	var req updateShortURLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	su, err := s.shortURLs.Update(ctx, id, shorturl.UpdateInput{
		LongURL:     req.LongURL,
		Title:       req.Title,
		Description: req.Description,
		ExpiresAt:   req.ExpiresAt,
	})
	switch {
	case errors.Is(err, shorturl.ErrInvalidLongURL):
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	case errors.Is(err, shorturl.ErrNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		slog.Error("update short url failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.invalidateShortURLCache(ctx, su)
	writeJSON(w, http.StatusOK, toShortURLResponse(su, access, grant))
}

// handleDeleteShortURL deactivates (status=disabled) rather than hard
// deletes — see shorturl.Service.Disable for why.
func (s *server) handleDeleteShortURL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, access, _, _, err := s.resolveAccess(ctx, r)
	if !s.writeAccessError(w, r, err) {
		return
	}
	if !access.CanDelete {
		http.NotFound(w, r)
		return
	}

	su, err := s.shortURLGet.FindByID(ctx, id)
	if errors.Is(err, shorturl.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		slog.Error("find short url before disable failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := s.shortURLs.Disable(ctx, id); err != nil {
		slog.Error("disable short url failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.invalidateShortURLCache(ctx, su)
	w.WriteHeader(http.StatusNoContent)
}

// invalidateShortURLCache purges cmd/redirect's hot-path cache (6節-2) so
// an edit or disable takes effect immediately instead of waiting out the
// cache's TTL.
func (s *server) invalidateShortURLCache(ctx context.Context, su *shorturl.ShortURL) {
	key := su.DomainID.String() + ":" + su.ShortCode
	if err := s.cache.Invalidate(ctx, key); err != nil {
		slog.Error("cache invalidate failed", "error", err)
	}
}

func atoiOrZero(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("response encode failed", "error", err)
	}
}
