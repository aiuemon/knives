package auth

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// Test scope note: go-webauthn's own signature verification (the actual
// cryptographic heart of FinishRegistration/FinishLogin) is trusted rather
// than re-verified here, the same way this package trusts argon2id's
// hashing or crewjam/saml's XML-dsig — reproducing a full FIDO2
// authenticator ceremony in a unit test requires simulating COSE key
// encoding, CBOR attestation objects, and an assertion signature, which
// go-webauthn's own maintainers point out is enough friction that they
// recommend browser-driven E2E testing over it (see PR description for
// the research trail). What IS this package's own responsibility — and is
// tested below — is everything around that verification: ceremony
// replay/expiry, clone-warning handling, and that a login can only ever
// resolve to the user whose own credential was actually presented.

type fakeWebAuthnCredentialStore struct {
	byUser             map[uuid.UUID][]WebAuthnCredential
	signCountUpdates   map[string]uint32
	backupStateUpdates map[string]bool
}

func newFakeWebAuthnCredentialStore() *fakeWebAuthnCredentialStore {
	return &fakeWebAuthnCredentialStore{
		byUser:             map[uuid.UUID][]WebAuthnCredential{},
		signCountUpdates:   map[string]uint32{},
		backupStateUpdates: map[string]bool{},
	}
}

func (s *fakeWebAuthnCredentialStore) FindWebAuthnCredentialsByUserID(_ context.Context, userID uuid.UUID) ([]WebAuthnCredential, error) {
	return s.byUser[userID], nil
}

func (s *fakeWebAuthnCredentialStore) CreateWebAuthnCredential(_ context.Context, cred WebAuthnCredential) error {
	s.byUser[cred.UserID] = append(s.byUser[cred.UserID], cred)
	return nil
}

func (s *fakeWebAuthnCredentialStore) UpdateWebAuthnCredentialSignCount(_ context.Context, credentialID []byte, signCount uint32, backupState bool) error {
	s.signCountUpdates[string(credentialID)] = signCount
	s.backupStateUpdates[string(credentialID)] = backupState
	return nil
}

func (s *fakeWebAuthnCredentialStore) UpdateWebAuthnCredentialName(_ context.Context, id, userID uuid.UUID, name string) (*WebAuthnCredential, error) {
	creds := s.byUser[userID]
	for i, c := range creds {
		if c.ID == id {
			creds[i].Name = name
			return &creds[i], nil
		}
	}
	return nil, ErrNotFound
}

func (s *fakeWebAuthnCredentialStore) DeleteWebAuthnCredential(_ context.Context, id, userID uuid.UUID) error {
	creds := s.byUser[userID]
	for i, c := range creds {
		if c.ID == id {
			s.byUser[userID] = append(creds[:i], creds[i+1:]...)
			return nil
		}
	}
	return ErrNotFound
}

type fakeWebAuthnSessionStore struct {
	data map[string][]byte
}

func newFakeWebAuthnSessionStore() *fakeWebAuthnSessionStore {
	return &fakeWebAuthnSessionStore{data: map[string][]byte{}}
}

func (s *fakeWebAuthnSessionStore) Create(_ context.Context, ceremonyID string, data []byte, _ time.Duration) error {
	s.data[ceremonyID] = data
	return nil
}

func (s *fakeWebAuthnSessionStore) Consume(_ context.Context, ceremonyID string) ([]byte, bool, error) {
	data, ok := s.data[ceremonyID]
	if !ok {
		return nil, false, nil
	}
	delete(s.data, ceremonyID)
	return data, true, nil
}

func newTestWebAuthn(t *testing.T) *webauthn.WebAuthn {
	t.Helper()
	w, err := webauthn.New(&webauthn.Config{
		RPID:          "localhost",
		RPDisplayName: "knives-test",
		RPOrigins:     []string{"http://localhost:5173"},
	})
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}
	return w
}

func TestWebAuthnService_BeginRegistration_ScopesToTheRequestedUser(t *testing.T) {
	store := newFakeStore()
	user, err := store.CreateUser(context.Background(), "user@example.com", true)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	other, err := store.CreateUser(context.Background(), "other@example.com", true)
	if err != nil {
		t.Fatalf("CreateUser (other): %v", err)
	}

	sessions := newFakeWebAuthnSessionStore()
	svc := &WebAuthnService{
		WebAuthn:    newTestWebAuthn(t),
		Users:       store,
		Credentials: newFakeWebAuthnCredentialStore(),
		Sessions:    sessions,
	}

	creation, ceremonyID, err := svc.BeginRegistration(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if ceremonyID == "" {
		t.Fatalf("expected a non-empty ceremony id")
	}
	if len(sessions.data) != 1 {
		t.Fatalf("expected exactly one stored ceremony, got %d", len(sessions.data))
	}
	if creation.Response.User.Name != user.Email {
		t.Fatalf("expected the registration options to be scoped to %s, got %s", user.Email, creation.Response.User.Name)
	}
	if creation.Response.User.Name == other.Email {
		t.Fatalf("registration options must never be built for a different user")
	}
}

func TestWebAuthnService_BeginLogin_IsUsernameless(t *testing.T) {
	svc := &WebAuthnService{
		WebAuthn:    newTestWebAuthn(t),
		Users:       newFakeStore(),
		Credentials: newFakeWebAuthnCredentialStore(),
		Sessions:    newFakeWebAuthnSessionStore(),
	}

	assertion, ceremonyID, err := svc.BeginLogin(context.Background())
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if ceremonyID == "" {
		t.Fatalf("expected a non-empty ceremony id")
	}
	// 3.1節: パスキーの利点はメールアドレス入力なしでログインできること。
	// discoverable loginはallowCredentialsを空にして認証器側に選ばせる。
	if len(assertion.Response.AllowedCredentials) != 0 {
		t.Fatalf("expected a discoverable login to not pre-specify allowed credentials, got %+v", assertion.Response.AllowedCredentials)
	}
}

func TestWebAuthnService_FinishRegistration_RejectsUnknownCeremony(t *testing.T) {
	svc := &WebAuthnService{
		WebAuthn:    newTestWebAuthn(t),
		Users:       newFakeStore(),
		Credentials: newFakeWebAuthnCredentialStore(),
		Sessions:    newFakeWebAuthnSessionStore(),
	}

	req := httptest.NewRequest("POST", "/auth/webauthn/register/finish", nil)
	err := svc.FinishRegistration(context.Background(), uuid.New(), "never-issued", "My Passkey", req)
	if !errors.Is(err, ErrWebAuthnCeremonyExpired) {
		t.Fatalf("expected ErrWebAuthnCeremonyExpired for an unknown ceremony id, got %v", err)
	}
}

func TestWebAuthnService_FinishLogin_RejectsReplayedCeremony(t *testing.T) {
	store := newFakeStore()
	sessions := newFakeWebAuthnSessionStore()
	svc := &WebAuthnService{
		WebAuthn:    newTestWebAuthn(t),
		Users:       store,
		Credentials: newFakeWebAuthnCredentialStore(),
		Sessions:    sessions,
	}

	_, ceremonyID, err := svc.BeginLogin(context.Background())
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}

	// 1回目のconsumeでceremonyが消費される(レスポンス自体は不正なので
	// FinishPasskeyLoginの手前で別のエラーになるが、ここで検証したいのは
	// 「同じceremony_idを2回使えないこと」)。
	req := httptest.NewRequest("POST", "/auth/webauthn/login/finish", nil)
	_, _ = svc.FinishLogin(context.Background(), ceremonyID, req)

	if len(sessions.data) != 0 {
		t.Fatalf("expected the ceremony to be consumed after the first attempt")
	}

	_, err = svc.FinishLogin(context.Background(), ceremonyID, req)
	if !errors.Is(err, ErrWebAuthnCeremonyExpired) {
		t.Fatalf("expected a replayed ceremony id to be rejected with ErrWebAuthnCeremonyExpired, got %v", err)
	}
}

func TestResolveWebAuthnUserHandle_RejectsMalformedHandle(t *testing.T) {
	if _, err := resolveWebAuthnUserHandle([]byte("not-a-uuid")); err == nil {
		t.Fatalf("expected a malformed user handle to be rejected")
	}
}

func TestResolveWebAuthnUserHandle_RoundTripsWebAuthnID(t *testing.T) {
	id := uuid.New()
	u := &webauthnUser{user: &User{ID: id, Email: "user@example.com"}}

	got, err := resolveWebAuthnUserHandle(u.WebAuthnID())
	if err != nil {
		t.Fatalf("resolveWebAuthnUserHandle: %v", err)
	}
	if got != id {
		t.Fatalf("expected the handle to round-trip to %s, got %s", id, got)
	}
}

func TestWebAuthnService_ApplyLoginResult_ClonedCredentialIsRejectedWithoutUpdatingSignCount(t *testing.T) {
	credentials := newFakeWebAuthnCredentialStore()
	svc := &WebAuthnService{Credentials: credentials}

	credentialID := []byte("cred-1")
	err := svc.applyLoginResult(context.Background(), &webauthn.Credential{
		ID: credentialID,
		Authenticator: webauthn.Authenticator{
			SignCount:    42,
			CloneWarning: true,
		},
	})
	if !errors.Is(err, ErrWebAuthnCredentialCloned) {
		t.Fatalf("expected ErrWebAuthnCredentialCloned, got %v", err)
	}
	if _, updated := credentials.signCountUpdates[string(credentialID)]; updated {
		t.Fatalf("a cloned credential's sign_count must not be silently resynced")
	}
}

func TestWebAuthnService_ApplyLoginResult_PersistsLatestSignCountOnSuccess(t *testing.T) {
	credentials := newFakeWebAuthnCredentialStore()
	svc := &WebAuthnService{Credentials: credentials}

	credentialID := []byte("cred-2")
	if err := svc.applyLoginResult(context.Background(), &webauthn.Credential{
		ID: credentialID,
		Authenticator: webauthn.Authenticator{
			SignCount:    7,
			CloneWarning: false,
		},
	}); err != nil {
		t.Fatalf("applyLoginResult: %v", err)
	}
	if got := credentials.signCountUpdates[string(credentialID)]; got != 7 {
		t.Fatalf("expected sign_count to be persisted as 7, got %d", got)
	}
}

// TestWebAuthnUser_WebAuthnCredentials_PreservesBackupEligibleFlag guards
// against a real bug found via manual browser testing: passkey login always
// failed with a generic 401, for every registered passkey. go-webauthn's
// own validateLogin (webauthn/login.go) rejects a login outright if the
// stored credential's Flags.BackupEligible doesn't match what the current
// assertion reports — see go-webauthn's own storage documentation
// (webauthn/doc.go, "Storage" section), which explicitly requires these
// flags to be persisted and restored. This package was reconstructing
// every credential's Flags as the zero value (always false), so any
// backup-eligible (synced/cloud) passkey — which is the norm for iCloud
// Keychain, Google Password Manager, etc. — would always mismatch and be
// rejected, 100% reproducibly, regardless of which passkey was used.
func TestWebAuthnUser_WebAuthnCredentials_PreservesBackupEligibleFlag(t *testing.T) {
	u := &webauthnUser{
		user: &User{ID: uuid.New(), Email: "user@example.com"},
		credentials: []WebAuthnCredential{
			{
				CredentialID:   []byte("cred-1"),
				UserPresent:    true,
				UserVerified:   true,
				BackupEligible: true,
				BackupState:    true,
			},
		},
	}

	creds := u.WebAuthnCredentials()
	if len(creds) != 1 {
		t.Fatalf("expected exactly one credential, got %d", len(creds))
	}
	got := creds[0].Flags
	if !got.UserPresent || !got.UserVerified || !got.BackupEligible || !got.BackupState {
		t.Fatalf("expected all flags to round-trip from the domain credential, got %+v", got)
	}
}
