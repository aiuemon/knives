package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

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

// requireSystemAdmin gates the /api/admin/* routes. Unlike resolveAccess's
// 404-not-403 handling for a specific short URL's existence, these endpoints
// aren't secret — everyone knows /api/admin/users exists — so a plain 403
// is the right signal here, not a concealment 404.
func (s *server) requireSystemAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject, ok := subjectFromContext(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !subject.IsSystemAdmin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
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

var (
	errUnauthorized = errors.New("unauthorized")
	errHidden       = errors.New("not found or not visible to this subject")
)

// resolveAccess parses the "id" URL param as a short URL ID and resolves
// what the authenticated subject may do with it (permission.Resolve), plus
// the subject's own grant (nil if their access comes purely from
// AdminOverride) — callers that echo access back to the client (e.g. so
// the frontend can decide which buttons to show, or display the caller's
// role) need both. Handlers should treat a non-nil error as "already
// handled, stop" via writeAccessError rather than inspecting it themselves.
func (s *server) resolveAccess(ctx context.Context, r *http.Request) (uuid.UUID, permission.Access, *permission.Grant, permission.Subject, error) {
	subject, ok := subjectFromContext(ctx)
	if !ok {
		return uuid.Nil, permission.Access{}, nil, permission.Subject{}, errUnauthorized
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return uuid.Nil, permission.Access{}, nil, subject, errHidden
	}

	grant, err := s.permissions.FindGrant(ctx, id, subject.UserID)
	if err != nil {
		return uuid.Nil, permission.Access{}, nil, subject, err
	}

	access := permission.Resolve(subject, grant)
	if !access.Visible {
		// 4.2節: 権限が無いことを403で漏らさず、存在ごと404で秘匿する。
		return uuid.Nil, permission.Access{}, nil, subject, errHidden
	}
	return id, access, grant, subject, nil
}

// writeAccessError writes the appropriate HTTP response for a
// resolveAccess error and reports whether the caller should continue
// handling the request (false means a response was already written).
func (s *server) writeAccessError(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, errUnauthorized):
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	case errors.Is(err, errHidden):
		http.NotFound(w, r)
	default:
		slog.Error("access resolution failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
	return false
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
