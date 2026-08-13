package auth

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// ErrWebAuthnCredentialAlreadyRegistered is returned by
// WebAuthnCredentialStore.CreateWebAuthnCredential when credential_id
// already exists — the browser/authenticator returned a credential this
// system (or, in principle, another RP sharing the DB, though that can't
// actually happen here) already has on file.
var ErrWebAuthnCredentialAlreadyRegistered = errors.New("auth: webauthn credential already registered")

// WebAuthnCredential is one registered passkey (2.2節: webauthn_credentials,
// 3.1節). Unlike SAML/OIDC identities, a credential belongs to exactly one
// user with no account-linking ambiguity: it's created by an already
// logged-in user (registration) and, at login, resolves straight back to
// its owner via UserID — Resolver is never involved.
type WebAuthnCredential struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	CredentialID []byte
	PublicKey    []byte
	// SignCount is the authenticator's own monotonic usage counter.
	// WebAuthnService checks it via the go-webauthn library's
	// CloneWarning (a counter that goes backwards means the credential's
	// private key was likely cloned) and persists the latest value after
	// every successful login (3.1節).
	SignCount  uint32
	Transports []string
}

// WebAuthnCredentialStore is the persistence port for webauthn_credentials.
type WebAuthnCredentialStore interface {
	// FindWebAuthnCredentialsByUserID returns every passkey userID has
	// registered, newest first. Used both to build the WebAuthnCredentials()
	// list go-webauthn needs for a ceremony and to render the "登録済みの
	// パスキー" management list.
	FindWebAuthnCredentialsByUserID(ctx context.Context, userID uuid.UUID) ([]WebAuthnCredential, error)
	// CreateWebAuthnCredential inserts a newly-registered credential.
	// Returns ErrWebAuthnCredentialAlreadyRegistered on a credential_id
	// collision.
	CreateWebAuthnCredential(ctx context.Context, cred WebAuthnCredential) error
	// UpdateWebAuthnCredentialSignCount persists the authenticator's latest
	// counter value after a successful login.
	UpdateWebAuthnCredentialSignCount(ctx context.Context, credentialID []byte, signCount uint32) error
	// DeleteWebAuthnCredential removes id, scoped to userID so a caller can
	// never revoke another user's passkey by guessing an id. Returns
	// ErrNotFound if id doesn't exist or isn't owned by userID.
	DeleteWebAuthnCredential(ctx context.Context, id, userID uuid.UUID) error
}
