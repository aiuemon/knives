package auth

import (
	"context"
	"time"
)

// WebAuthnSessionStore holds in-flight WebAuthn ceremony state
// (webauthn.SessionData, serialized) between a Begin*/Finish* pair — a
// registration or login ceremony is necessarily stateful across two HTTP
// round trips (the browser calls navigator.credentials in between), same
// operational shape as SAMLNonceStore/OIDCNonceStore's request state.
type WebAuthnSessionStore interface {
	// Create stores data under ceremonyID for ttl.
	Create(ctx context.Context, ceremonyID string, data []byte, ttl time.Duration) error
	// Consume atomically fetches and deletes ceremonyID's data — a
	// ceremony can only ever be finished once, both because SessionData
	// contains a single-use challenge and because replaying an already-
	// finished ceremony's response must not authenticate a second time.
	// found is false if ceremonyID doesn't exist (expired, already
	// consumed, or never issued).
	Consume(ctx context.Context, ceremonyID string) (data []byte, found bool, err error)
}
