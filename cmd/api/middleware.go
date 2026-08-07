package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/aiuemon/knives/internal/auth"
	"github.com/aiuemon/knives/internal/permission"
)

type contextKey int

const subjectContextKey contextKey = iota

func withSubject(ctx context.Context, subject permission.Subject) context.Context {
	return context.WithValue(ctx, subjectContextKey, subject)
}

func subjectFromContext(ctx context.Context) (permission.Subject, bool) {
	subject, ok := ctx.Value(subjectContextKey).(permission.Subject)
	return subject, ok
}

// requireAuth resolves the session cookie into a permission.Subject
// (including the system_admin flag, needed for 4.1節's unlimited-view
// override) and extends the session's TTL on each authenticated request.
func (s *server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(s.sessionCookieName)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := r.Context()
		session, err := s.sessions.Find(ctx, cookie.Value)
		if errors.Is(err, auth.ErrSessionNotFound) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err != nil {
			slog.Error("session lookup failed", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if err := s.sessions.Touch(ctx, cookie.Value, s.sessionTTL); err != nil {
			// スライディングTTLの延長に失敗しても、そのリクエスト自体は
			// 認証済みとして処理を続ける(次回アクセスで再度延長を試みる)。
			slog.Error("session touch failed", "error", err)
		}

		isAdmin, err := s.permissions.IsSystemAdmin(ctx, session.UserID)
		if err != nil {
			slog.Error("system_admin lookup failed", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		subject := permission.Subject{UserID: session.UserID, IsSystemAdmin: isAdmin}
		next.ServeHTTP(w, r.WithContext(withSubject(ctx, subject)))
	})
}

func (s *server) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.sessionTTL.Seconds()),
	})
}

func (s *server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
