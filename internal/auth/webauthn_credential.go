package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ErrWebAuthnCredentialAlreadyRegistered is returned by
// WebAuthnCredentialStore.CreateWebAuthnCredential when credential_id
// already exists — the browser/authenticator returned a credential this
// system (or, in principle, another RP sharing the DB, though that can't
// actually happen here) already has on file.
var ErrWebAuthnCredentialAlreadyRegistered = errors.New("auth: webauthn credential already registered")

// maxWebAuthnCredentialNameLength bounds the user-supplied passkey label
// (e.g. "会社支給MacBook") — long enough for any reasonable device name,
// short enough that a management list column stays readable.
const maxWebAuthnCredentialNameLength = 100

// ErrInvalidWebAuthnCredentialName is returned by
// NormalizeWebAuthnCredentialName when the caller-supplied name exceeds
// maxWebAuthnCredentialNameLength.
var ErrInvalidWebAuthnCredentialName = errors.New("auth: passkey name must be at most 100 characters")

// NormalizeWebAuthnCredentialName trims raw and validates its length. An
// empty name is valid (the passkey is simply unnamed — the UI falls back
// to a transport-derived label); this only rejects names that are too
// long to display sensibly, shared by both registration (naming a new
// passkey) and rename (editing an existing one)'s validation.
func NormalizeWebAuthnCredentialName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if len(name) > maxWebAuthnCredentialNameLength {
		return "", ErrInvalidWebAuthnCredentialName
	}
	return name, nil
}

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
	// Name is a user-supplied label ("会社支給MacBook" etc.) set at
	// registration time and editable afterward. Empty means unnamed.
	Name      string
	CreatedAt time.Time
	// LastUsedAt is nil until the credential has actually been used to
	// log in at least once (registering it doesn't count — that happens
	// on an already-authenticated session).
	LastUsedAt *time.Time
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
	// counter value and last_used_at after a successful login.
	UpdateWebAuthnCredentialSignCount(ctx context.Context, credentialID []byte, signCount uint32) error
	// UpdateWebAuthnCredentialName renames id, scoped to userID (same
	// ownership rule as DeleteWebAuthnCredential). Returns ErrNotFound if
	// id doesn't exist or isn't owned by userID.
	UpdateWebAuthnCredentialName(ctx context.Context, id, userID uuid.UUID, name string) (*WebAuthnCredential, error)
	// DeleteWebAuthnCredential removes id, scoped to userID so a caller can
	// never revoke another user's passkey by guessing an id. Returns
	// ErrNotFound if id doesn't exist or isn't owned by userID.
	DeleteWebAuthnCredential(ctx context.Context, id, userID uuid.UUID) error
}
