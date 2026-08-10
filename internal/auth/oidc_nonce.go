package auth

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// OIDCPendingLogin is the server-side state recorded at BeginLogin and
// recovered at HandleCallback via the OAuth2 "state" parameter — mirrors
// SAMLNonceStore's role for the SAML flow (3.3節: state/nonce必須検証),
// but OIDC also needs the PKCE code_verifier to complete the token
// exchange, so this carries three fields instead of just a config ID.
type OIDCPendingLogin struct {
	ConfigID     uuid.UUID
	Nonce        string
	CodeVerifier string
}

// OIDCNonceStore provides one-time-use tracking for the state parameter of
// the OIDC Authorization Code flow. Unlike SAML (see SAMLNonceStore's
// doc comment on Assertion ID replay), OIDC doesn't need a second,
// separate replay store for the token itself: the authorization code is
// single-use by the IdP itself, and completing the exchange requires both
// this client's secret and the PKCE code_verifier that never left this
// server — state's single-use consumption here is what closes the loop.
type OIDCNonceStore interface {
	// CreateState records that state was issued for pending, valid for ttl.
	CreateState(ctx context.Context, state string, pending OIDCPendingLogin, ttl time.Duration) error
	// ConsumeState atomically looks up and deletes state (single use). ok
	// is false if it was never issued, already consumed, or has expired.
	ConsumeState(ctx context.Context, state string) (pending OIDCPendingLogin, ok bool, err error)
}
