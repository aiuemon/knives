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
	// "verification_pending" when a link was mailed out and nothing has
	// been created yet — either because the submitted email itself still
	// needs to be proven reachable (local-auth専用の登録前ゲート), or
	// because it turned out to already belong to a claimed account and
	// 3.4節's account-link confirmation took over instead.
	Status string `json:"status"`
}

func (s *server) handleLocalSignup(w http.ResponseWriter, r *http.Request) {
	var req localSignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	localEnabled, selfSignupEnabled, requireConfirmation, _, err := s.authSettings.FindAuthSettings(ctx)
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

	result, err := s.localSignup.Start(ctx, addr.Address, req.Password, requireConfirmation)
	if errors.Is(err, auth.ErrPasswordTooShort) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		slog.Error("local signup failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if result.Outcome == auth.SignupOutcomeVerificationPending {
		writeJSON(w, http.StatusAccepted, localSignupResponse{Status: "verification_pending"})
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

// handleVerifyEmail completes the local-signup email-ownership gate
// (3.1節, local-auth専用): only after this succeeds does
// users/auth_identities/local_credentials get created for the address.
func (s *server) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}

	result, err := s.localSignup.VerifyEmail(r.Context(), token)
	switch {
	case errors.Is(err, auth.ErrTokenExpired):
		http.Error(w, "verification link has expired", http.StatusGone)
		return
	case errors.Is(err, auth.ErrNotFound):
		http.Error(w, "invalid verification link", http.StatusNotFound)
		return
	case err != nil:
		slog.Error("verify email failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if result.Outcome == auth.SignupOutcomeVerificationPending {
		// メール到達確認は完了したが、統合先アカウントは3.4節の確認メール
		// 待ち(まれなケース: 到達確認完了直後に別アカウントへのクレーム
		// 済みが判明した場合)。まだログインさせない。
		writeJSON(w, http.StatusAccepted, localSignupResponse{Status: "verification_pending"})
		return
	}

	token2, err := s.sessions.Create(r.Context(), result.User.ID, s.sessionTTL)
	if err != nil {
		slog.Error("session create failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.setSessionCookie(w, token2)
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

type pendingLinkResponse struct {
	ID           uuid.UUID `json:"id"`
	ProviderType string    `json:"provider_type"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// handleListPendingLinks shows the authenticated user their own pending
// account-link requests — the "review" step of the reauth-required flow
// (auth_settings.require_reauth_for_account_link, 3.4節-4改訂): reaching
// this endpoint at all already proves the caller logged in via their
// existing method, which is the point.
func (s *server) handleListPendingLinks(w http.ResponseWriter, r *http.Request) {
	subject, ok := subjectFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	pending, err := s.resolver.ListPendingLinks(r.Context(), subject.UserID)
	if err != nil {
		slog.Error("list pending links failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp := make([]pendingLinkResponse, 0, len(pending))
	for _, p := range pending {
		resp = append(resp, pendingLinkResponse{ID: p.ID, ProviderType: string(p.ProviderType), ExpiresAt: p.ExpiresAt})
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleApprovePendingLink approves one of the caller's own pending
// account-link requests. Resolver.ApprovePendingLink independently
// re-checks ownership, so this handler doesn't need to (and must not skip
// that check even though it looks redundant here).
func (s *server) handleApprovePendingLink(w http.ResponseWriter, r *http.Request) {
	subject, ok := subjectFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	requestID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}

	result, err := s.resolver.ApprovePendingLink(r.Context(), subject.UserID, requestID)
	switch {
	case errors.Is(err, auth.ErrNotFound):
		http.NotFound(w, r)
		return
	case errors.Is(err, auth.ErrTokenExpired):
		http.Error(w, "this request has expired", http.StatusGone)
		return
	case errors.Is(err, auth.ErrTokenAlreadyUsed):
		http.Error(w, "this request was already approved", http.StatusConflict)
		return
	case err != nil:
		slog.Error("approve pending link failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "approved", "user_id": result.User.ID.String()})
}

type setPasswordRequest struct {
	NewPassword string `json:"new_password"`
}

// handleSetPassword lets an already-authenticated user set/replace their
// local password — e.g. adding local login to an SSO-only account, or an
// ordinary password change. (Local self-signup itself carries its password
// through automatically via LocalSignup; it doesn't need this endpoint.)
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
