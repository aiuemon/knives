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
// @simplewebauthn/browser's startRegistration) — ceremony_id and the
// user-supplied passkey name both travel out-of-band as query params so
// the body can be handed to go-webauthn unmodified.
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
	name, err := auth.NormalizeWebAuthnCredentialName(r.URL.Query().Get("name"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = s.webauthn.FinishRegistration(r.Context(), subject.UserID, ceremonyID, name, r)
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
	// bodyの無い201はこのコードベースの他の201レスポンス(handleCreateShortURL
	// 等)の慣習から外れており、web/src/api/client.tsのrequest()は204以外は
	// 常にres.json()を呼ぶ前提のため、空bodyだとJSONパースに失敗して
	// フロント側が「登録成功したのに失敗と表示される」不具合になる。
	writeJSON(w, http.StatusCreated, struct{}{})
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
		// FinishLoginの失敗理由の大半(署名検証失敗・challenge不一致・
		// user handle解決失敗等)を診断できるよう、handleWebAuthnRegisterFinish
		// と同様にログへ残す(以前はここが完全に無音で、原因調査ができ
		// なかった)。
		slog.Warn("webauthn finish login rejected", "error", err)
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
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Transports []string   `json:"transports,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

func toWebAuthnCredentialResponse(c auth.WebAuthnCredential) webauthnCredentialResponse {
	return webauthnCredentialResponse{
		ID:         c.ID.String(),
		Name:       c.Name,
		Transports: c.Transports,
		CreatedAt:  c.CreatedAt,
		LastUsedAt: c.LastUsedAt,
	}
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
		resp = append(resp, toWebAuthnCredentialResponse(c))
	}
	writeJSON(w, http.StatusOK, resp)
}

type updateWebAuthnCredentialNameRequest struct {
	Name string `json:"name"`
}

// handleUpdateWebAuthnCredentialName renames one of the caller's own
// passkeys (the "一覧内で名称を変更" requirement). Scoped to the caller's
// own userID by WebAuthnCredentialStore, same as delete.
func (s *server) handleUpdateWebAuthnCredentialName(w http.ResponseWriter, r *http.Request) {
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

	var req updateWebAuthnCredentialNameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	name, err := auth.NormalizeWebAuthnCredentialName(req.Name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cred, err := s.webauthnCredentials.UpdateWebAuthnCredentialName(r.Context(), id, subject.UserID, name)
	if errors.Is(err, auth.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		slog.Error("update webauthn credential name failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, toWebAuthnCredentialResponse(*cred))
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
