package main

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

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
