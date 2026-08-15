package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// webauthnCeremonyTTL bounds how long a client has to complete a
// registration/login ceremony after Begin — generous enough for a user to
// notice their authenticator prompt, short enough that an abandoned
// ceremony's Redis entry doesn't linger.
const webauthnCeremonyTTL = 5 * time.Minute

var (
	// ErrWebAuthnCeremonyExpired is returned by Finish* when ceremonyID is
	// unknown to WebAuthnSessionStore — expired, already consumed
	// (replayed), or never issued.
	ErrWebAuthnCeremonyExpired = errors.New("auth: webauthn ceremony expired or already used")
	// ErrWebAuthnCredentialCloned is returned by FinishLogin when the
	// authenticator's sign_count went backwards relative to what's on
	// file — go-webauthn's CloneWarning, meaning the credential's private
	// key was likely extracted and cloned onto a second device (3.1節の
	// なりすまし対策). The login is rejected outright rather than merely
	// logged, since a cloned credential can no longer be trusted to prove
	// "something you have".
	ErrWebAuthnCredentialCloned = errors.New("auth: webauthn credential clone detected")
)

// webauthnUser adapts a domain User plus its registered credentials to the
// go-webauthn library's User interface (3.1節).
type webauthnUser struct {
	user        *User
	credentials []WebAuthnCredential
}

var _ webauthn.User = (*webauthnUser)(nil)

// WebAuthnID is the RP-scoped user handle. It round-trips through
// resolveWebAuthnUserHandle (used to identify who's logging in during a
// usernameless/discoverable ceremony), so its encoding must match exactly:
// the UUID's canonical string form, as bytes.
func (u *webauthnUser) WebAuthnID() []byte          { return []byte(u.user.ID.String()) }
func (u *webauthnUser) WebAuthnName() string        { return u.user.Email }
func (u *webauthnUser) WebAuthnDisplayName() string { return u.user.Email }
func (u *webauthnUser) WebAuthnIcon() string        { return "" }

func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	creds := make([]webauthn.Credential, 0, len(u.credentials))
	for _, c := range u.credentials {
		transports := make([]protocol.AuthenticatorTransport, 0, len(c.Transports))
		for _, t := range c.Transports {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}
		creds = append(creds, webauthn.Credential{
			ID:        c.CredentialID,
			PublicKey: c.PublicKey,
			Transport: transports,
			Authenticator: webauthn.Authenticator{
				SignCount: c.SignCount,
			},
		})
	}
	return creds
}

// resolveWebAuthnUserHandle parses a WebAuthn user handle (as produced by
// webauthnUser.WebAuthnID) back into a uuid — the inverse of that encoding.
// Split out from FinishLogin's discoverable-credential handler so the
// "does an attacker-controlled userHandle ever resolve to someone else's
// account" scoping logic is directly testable without a real ceremony.
func resolveWebAuthnUserHandle(userHandle []byte) (uuid.UUID, error) {
	return uuid.ParseBytes(userHandle)
}

// WebAuthnService implements passkey registration and login (3.1節).
// Unlike SAML/OIDC, there is no account-linking ambiguity to resolve:
// registration attaches a credential to whichever user is already logged
// in, and login resolves a credential straight back to its owning user via
// the RP-scoped user handle — Resolver is never involved.
type WebAuthnService struct {
	WebAuthn    *webauthn.WebAuthn
	Users       Store
	Credentials WebAuthnCredentialStore
	Sessions    WebAuthnSessionStore
}

func (s *WebAuthnService) loadWebAuthnUser(ctx context.Context, userID uuid.UUID) (*webauthnUser, error) {
	user, err := s.Users.FindUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	creds, err := s.Credentials.FindWebAuthnCredentialsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &webauthnUser{user: user, credentials: creds}, nil
}

func (s *WebAuthnService) storeSession(ctx context.Context, session *webauthn.SessionData) (string, error) {
	ceremonyID, _, err := generateToken()
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(session)
	if err != nil {
		return "", err
	}
	if err := s.Sessions.Create(ctx, ceremonyID, data, webauthnCeremonyTTL); err != nil {
		return "", err
	}
	return ceremonyID, nil
}

func (s *WebAuthnService) consumeSession(ctx context.Context, ceremonyID string) (*webauthn.SessionData, error) {
	data, found, err := s.Sessions.Consume(ctx, ceremonyID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrWebAuthnCeremonyExpired
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}
	return &session, nil
}

// BeginRegistration starts a registration ceremony for the already
// logged-in userID, returning the options to pass to the browser's
// navigator.credentials.create() (via @simplewebauthn/browser's
// startRegistration) and an opaque ceremonyID the client must echo back to
// FinishRegistration.
func (s *WebAuthnService) BeginRegistration(ctx context.Context, userID uuid.UUID) (*protocol.CredentialCreation, string, error) {
	user, err := s.loadWebAuthnUser(ctx, userID)
	if err != nil {
		return nil, "", err
	}
	creation, session, err := s.WebAuthn.BeginRegistration(user)
	if err != nil {
		return nil, "", err
	}
	ceremonyID, err := s.storeSession(ctx, session)
	if err != nil {
		return nil, "", err
	}
	return creation, ceremonyID, nil
}

// FinishRegistration completes a registration ceremony begun for userID
// and persists the new credential under name (already validated by the
// caller via NormalizeWebAuthnCredentialName — empty is fine, meaning
// unnamed).
func (s *WebAuthnService) FinishRegistration(ctx context.Context, userID uuid.UUID, ceremonyID, name string, r *http.Request) error {
	session, err := s.consumeSession(ctx, ceremonyID)
	if err != nil {
		return err
	}
	user, err := s.loadWebAuthnUser(ctx, userID)
	if err != nil {
		return err
	}

	credential, err := s.WebAuthn.FinishRegistration(user, *session, r)
	if err != nil {
		return err
	}

	transports := make([]string, 0, len(credential.Transport))
	for _, t := range credential.Transport {
		transports = append(transports, string(t))
	}
	return s.Credentials.CreateWebAuthnCredential(ctx, WebAuthnCredential{
		UserID:       userID,
		CredentialID: credential.ID,
		PublicKey:    credential.PublicKey,
		SignCount:    credential.Authenticator.SignCount,
		Transports:   transports,
		Name:         name,
	})
}

// BeginLogin starts a usernameless (discoverable-credential) login
// ceremony — the point of a passkey is not needing to type an email first.
func (s *WebAuthnService) BeginLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	assertion, session, err := s.WebAuthn.BeginDiscoverableLogin()
	if err != nil {
		return nil, "", err
	}
	ceremonyID, err := s.storeSession(ctx, session)
	if err != nil {
		return nil, "", err
	}
	return assertion, ceremonyID, nil
}

// FinishLogin completes a discoverable-credential login ceremony,
// resolving which user is logging in from the authenticator-supplied user
// handle, verifying the assertion signature, and enforcing clone detection
// via sign_count (3.1節). On success it returns the logged-in user; callers
// are responsible for actually issuing a session (mirrors LocalAuthenticator.
// Login, which also just returns *User).
func (s *WebAuthnService) FinishLogin(ctx context.Context, ceremonyID string, r *http.Request) (*User, error) {
	session, err := s.consumeSession(ctx, ceremonyID)
	if err != nil {
		return nil, err
	}

	var resolvedUser *webauthnUser
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		id, err := resolveWebAuthnUserHandle(userHandle)
		if err != nil {
			return nil, err
		}
		u, err := s.loadWebAuthnUser(ctx, id)
		if err != nil {
			return nil, err
		}
		resolvedUser = u
		return u, nil
	}

	_, credential, err := s.WebAuthn.FinishPasskeyLogin(handler, *session, r)
	if err != nil {
		return nil, err
	}

	if err := s.applyLoginResult(ctx, credential); err != nil {
		return nil, err
	}
	return resolvedUser.user, nil
}

// applyLoginResult decides what to do with a successfully-verified
// assertion's credential: reject on a clone warning (ErrWebAuthnCredentialCloned,
// leaving sign_count untouched so a genuinely cloned credential doesn't get
// its counter silently resynced), otherwise persist the authenticator's
// latest counter. Split out from FinishLogin so this actual security
// decision is unit-testable without needing a full cryptographic ceremony
// (go-webauthn's own signature verification is trusted, not re-tested
// here — see webauthn_test.go).
func (s *WebAuthnService) applyLoginResult(ctx context.Context, credential *webauthn.Credential) error {
	if credential.Authenticator.CloneWarning {
		return ErrWebAuthnCredentialCloned
	}
	return s.Credentials.UpdateWebAuthnCredentialSignCount(ctx, credential.ID, credential.Authenticator.SignCount)
}
