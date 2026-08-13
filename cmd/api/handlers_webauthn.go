package main

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/aiuemon/knives/internal/auth"
)

type webauthnCeremonyResponse struct {
	CeremonyID string `json:"ceremony_id"`
	Options    any    `json:"options"`
}

// handleWebAuthnRegisterBegin starts a passkey registration ceremony for
// the currently logged-in user (3.1節: ログイン済みユーザが追加登録する
// モデル). options is go-webauthn's PublicKeyCredentialCreationOptions —
// exactly the shape @simplewebauthn/browser's startRegistration expects as
// optionsJSON.
func (s *server) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	subject, ok := subjectFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	creation, ceremonyID, err := s.webauthn.BeginRegistration(r.Context(), subject.UserID)
	if err != nil {
		slog.Error("webauthn begin registration failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, webauthnCeremonyResponse{CeremonyID: ceremonyID, Options: creation.Response})
}

// handleWebAuthnRegisterFinish completes a registration ceremony. The
// request body is the browser's RegistrationResponseJSON verbatim (from
// @simplewebauthn/browser's startRegistration) — ceremony_id travels
// out-of-band as a query param so the body can be handed to go-webauthn
// unmodified.
func (s *server) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	subject, ok := subjectFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ceremonyID := r.URL.Query().Get("ceremony_id")
	if ceremonyID == "" {
		http.Error(w, "missing ceremony_id", http.StatusBadRequest)
		return
	}

	err := s.webauthn.FinishRegistration(r.Context(), subject.UserID, ceremonyID, r)
	switch {
	case errors.Is(err, auth.ErrWebAuthnCeremonyExpired):
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	case errors.Is(err, auth.ErrWebAuthnCredentialAlreadyRegistered):
		http.Error(w, err.Error(), http.StatusConflict)
		return
	case err != nil:
		// FinishRegistrationの失敗理由の大半(署名検証・challenge不一致等)は
		// クライアント起因の不正なレスポンスなので400として扱う。
		slog.Warn("webauthn finish registration rejected", "error", err)
		http.Error(w, "invalid passkey registration", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// handleWebAuthnLoginBegin starts a usernameless (discoverable-credential)
// login ceremony — unauthenticated, since the whole point of a passkey is
// logging in without typing an email first (3.1節).
func (s *server) handleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	assertion, ceremonyID, err := s.webauthn.BeginLogin(r.Context())
	if err != nil {
		slog.Error("webauthn begin login failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, webauthnCeremonyResponse{CeremonyID: ceremonyID, Options: assertion.Response})
}

// handleWebAuthnLoginFinish completes a login ceremony and, on success,
// issues a session cookie exactly like handleLocalLogin does.
func (s *server) handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	ceremonyID := r.URL.Query().Get("ceremony_id")
	if ceremonyID == "" {
		http.Error(w, "missing ceremony_id", http.StatusBadRequest)
		return
	}

	user, err := s.webauthn.FinishLogin(r.Context(), ceremonyID, r)
	switch {
	case errors.Is(err, auth.ErrWebAuthnCeremonyExpired):
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	case errors.Is(err, auth.ErrWebAuthnCredentialCloned):
		slog.Warn("webauthn clone warning detected during login", "error", err)
		http.Error(w, "passkey verification failed", http.StatusUnauthorized)
		return
	case err != nil:
		http.Error(w, "passkey login failed", http.StatusUnauthorized)
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

type webauthnCredentialResponse struct {
	ID         string   `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

// handleListWebAuthnCredentials lists the caller's own registered
// passkeys, for the "登録済みのパスキー" management UI. Neither
// credential_id nor public_key is exposed — they're not secret, but the
// UI has no use for them and there's no reason to widen what's on the wire.
func (s *server) handleListWebAuthnCredentials(w http.ResponseWriter, r *http.Request) {
	subject, ok := subjectFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	creds, err := s.webauthnCredentials.FindWebAuthnCredentialsByUserID(r.Context(), subject.UserID)
	if err != nil {
		slog.Error("list webauthn credentials failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	resp := make([]webauthnCredentialResponse, 0, len(creds))
	for _, c := range creds {
		resp = append(resp, webauthnCredentialResponse{ID: c.ID.String(), Transports: c.Transports})
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleDeleteWebAuthnCredential revokes one of the caller's own passkeys.
// Deletion is scoped to the caller's own userID (WebAuthnCredentialStore's
// job), so id belonging to a different user 404s rather than succeeding or
// leaking whether that id exists at all.
func (s *server) handleDeleteWebAuthnCredential(w http.ResponseWriter, r *http.Request) {
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

	err = s.webauthnCredentials.DeleteWebAuthnCredential(r.Context(), id, subject.UserID)
	if errors.Is(err, auth.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		slog.Error("delete webauthn credential failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
