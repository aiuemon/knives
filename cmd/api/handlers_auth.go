package main

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"

	"github.com/aiuemon/knives/internal/auth"
)

type localLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *server) handleLocalLogin(w http.ResponseWriter, r *http.Request) {
	var req localLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	user, err := s.localAuth.Login(r.Context(), req.Email, req.Password)
	switch {
	case errors.Is(err, auth.ErrAccountLocked):
		http.Error(w, "account temporarily locked", http.StatusTooManyRequests)
		return
	case errors.Is(err, auth.ErrInvalidCredentials):
		http.Error(w, "invalid email or password", http.StatusUnauthorized)
		return
	case err != nil:
		slog.Error("local login failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	token, err := s.sessions.Create(r.Context(), user.ID, s.sessionTTL)
	if err != nil {
		slog.Error("session create failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.setSessionCookie(w, token)
	w.WriteHeader(http.StatusNoContent)
}

// handleLogout is intentionally unauthenticated (no requireAuth): a
// missing/invalid cookie should still succeed in clearing client state
// rather than 401ing a client that's already logged out.
func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(s.sessionCookieName); err == nil {
		if err := s.sessions.Delete(r.Context(), cookie.Value); err != nil {
			slog.Error("session delete failed", "error", err)
		}
	}
	s.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

type localSignupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type localSignupResponse struct {
	// Status is "logged_in" when signup completed immediately, or
	// "confirmation_required" when this email already belongs to a
	// claimed account and a confirmation email was sent to its owner
	// instead (3.4節: なりすまし対策のため、リクエスト元ではなく既存アカ
	// ウントの登録メール宛に送る)。
	Status string `json:"status"`
}

func (s *server) handleLocalSignup(w http.ResponseWriter, r *http.Request) {
	var req localSignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	localEnabled, selfSignupEnabled, requireConfirmation, err := s.authSettings.FindAuthSettings(ctx)
	if err != nil {
		slog.Error("auth settings lookup failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !localEnabled || !selfSignupEnabled {
		http.Error(w, "self-signup is disabled", http.StatusForbidden)
		return
	}

	addr, err := mail.ParseAddress(strings.TrimSpace(req.Email))
	if err != nil {
		http.Error(w, "invalid email", http.StatusBadRequest)
		return
	}
	email := addr.Address

	// パスワードはResolveより先に検証する: 弱いパスワードで弾く前に
	// ユーザ作成や確認メール送信が起きてしまうのを避けるため。
	if err := auth.ValidatePasswordStrength(req.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result, err := s.resolver.Resolve(ctx, auth.LoginAttempt{
		ProviderType:  auth.ProviderLocal,
		Subject:       email, // localはIdP側IDを持たないため、emailをsubjectとして扱う
		Email:         email,
		EmailVerified: !requireConfirmation,
		Trusted:       false, // ローカルセルフサインアップは3.4節のIdP信頼バイパス対象外
	})
	if err != nil {
		slog.Error("resolve local signup failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if result.Outcome == auth.OutcomePendingConfirmation {
		writeJSON(w, http.StatusAccepted, localSignupResponse{Status: "confirmation_required"})
		return
	}

	// OutcomeLoggedIn: 新規ユーザ作成、またはYOURLS移行プレースホルダの
	// 初回有効化のいずれか。まだパスワードが保存されていないので設定する。
	if err := s.localAuth.SetPassword(ctx, result.User.ID, req.Password); err != nil {
		slog.Error("set password after signup failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	token, err := s.sessions.Create(ctx, result.User.ID, s.sessionTTL)
	if err != nil {
		slog.Error("session create failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.setSessionCookie(w, token)
	writeJSON(w, http.StatusCreated, localSignupResponse{Status: "logged_in"})
}

// handleConfirmLink completes the account-link confirmation flow
// (3.4節-4): the existing account's real owner opens the mailed link,
// which attaches the pending local identity to their own account and logs
// them in as themselves — never as whoever originally submitted the
// signup form.
func (s *server) handleConfirmLink(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}

	result, err := s.resolver.ConfirmPendingLink(r.Context(), token)
	switch {
	case errors.Is(err, auth.ErrTokenExpired):
		http.Error(w, "confirmation link has expired", http.StatusGone)
		return
	case errors.Is(err, auth.ErrTokenAlreadyUsed):
		http.Error(w, "confirmation link was already used", http.StatusConflict)
		return
	case err != nil:
		slog.Error("confirm link failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	sessionToken, err := s.sessions.Create(r.Context(), result.User.ID, s.sessionTTL)
	if err != nil {
		slog.Error("session create failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.setSessionCookie(w, sessionToken)
	writeJSON(w, http.StatusOK, map[string]string{"status": "confirmed"})
}

type setPasswordRequest struct {
	NewPassword string `json:"new_password"`
}

// handleSetPassword lets an already-authenticated user set/replace their
// local password — used both to finish local signup after email
// confirmation (the confirm-link flow attaches the identity but doesn't
// carry a password across the request boundary) and as an ordinary
// password change.
func (s *server) handleSetPassword(w http.ResponseWriter, r *http.Request) {
	subject, ok := subjectFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req setPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := s.localAuth.SetPassword(r.Context(), subject.UserID, req.NewPassword); err != nil {
		if errors.Is(err, auth.ErrPasswordTooShort) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		slog.Error("set password failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
