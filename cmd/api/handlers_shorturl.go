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

type shortURLResponse struct {
	ID          uuid.UUID  `json:"id"`
	ShortCode   string     `json:"short_code"`
	LongURL     string     `json:"long_url"`
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Status      string     `json:"status"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

func toShortURLResponse(su *shorturl.ShortURL) shortURLResponse {
	return shortURLResponse{
		ID:          su.ID,
		ShortCode:   su.ShortCode,
		LongURL:     su.LongURL,
		Title:       su.Title,
		Description: su.Description,
		Status:      string(su.Status),
		ExpiresAt:   su.ExpiresAt,
	}
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

	writeJSON(w, http.StatusCreated, toShortURLResponse(su))
}

func (s *server) handleGetShortURL(w http.ResponseWriter, r *http.Request) {
	subject, ok := subjectFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()
	grant, err := s.permissions.FindGrant(ctx, id, subject.UserID)
	if err != nil {
		slog.Error("permission lookup failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	access := permission.Resolve(subject, grant)
	if !access.Visible {
		// 4.2節: 権限が無いことを403で漏らさず、存在ごと404で秘匿する。
		http.NotFound(w, r)
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

	writeJSON(w, http.StatusOK, toShortURLResponse(su))
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("response encode failed", "error", err)
	}
}
