package auth

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// SAMLNonceStore provides one-time-use tracking for the SP-initiated SAML
// flow (3.2節). RelayState doubles as a lookup key into server-side state
// recording which AuthnRequest we actually issued — ACS must not trust a
// client-supplied RelayState by itself (mirrors how OAuth2 "state" is meant
// to be validated: bound server-side, not just checked for presence).
// Separately, it tracks which Assertion IDs have already been consumed so a
// captured IdP response can't be replayed to log in a second time.
type SAMLNonceStore interface {
	// CreateRequest records that relayState was issued for configID, valid
	// for ttl.
	CreateRequest(ctx context.Context, relayState string, configID uuid.UUID, ttl time.Duration) error
	// ConsumeRequest atomically looks up and deletes relayState (single
	// use). ok is false if it was never issued, already consumed, or has
	// expired.
	ConsumeRequest(ctx context.Context, relayState string) (configID uuid.UUID, ok bool, err error)
	// MarkAssertionSeen atomically records assertionID as used.
	// alreadySeen is true if it had already been recorded — the caller
	// must then refuse the login as a replay.
	MarkAssertionSeen(ctx context.Context, assertionID string, ttl time.Duration) (alreadySeen bool, err error)
}
