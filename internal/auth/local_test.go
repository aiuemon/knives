package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fakeCredentialStore struct {
	creds map[uuid.UUID]*LocalCredential
}

func newFakeCredentialStore() *fakeCredentialStore {
	return &fakeCredentialStore{creds: map[uuid.UUID]*LocalCredential{}}
}

func (s *fakeCredentialStore) FindLocalCredential(_ context.Context, userID uuid.UUID) (*LocalCredential, error) {
	c, ok := s.creds[userID]
	if !ok {
		return nil, ErrNotFound
	}
	copied := *c
	return &copied, nil
}

func (s *fakeCredentialStore) SetPassword(_ context.Context, userID uuid.UUID, passwordHash string) error {
	s.creds[userID] = &LocalCredential{UserID: userID, PasswordHash: passwordHash}
	return nil
}

func (s *fakeCredentialStore) RecordFailedAttempt(_ context.Context, userID uuid.UUID, failedAttempts int, lockedUntil *time.Time) error {
	c, ok := s.creds[userID]
	if !ok {
		return ErrNotFound
	}
	c.FailedAttempts = failedAttempts
	c.LockedUntil = lockedUntil
	return nil
}

func (s *fakeCredentialStore) ResetFailedAttempts(_ context.Context, userID uuid.UUID) error {
	c, ok := s.creds[userID]
	if !ok {
		return ErrNotFound
	}
	c.FailedAttempts = 0
	c.LockedUntil = nil
	return nil
}

func newTestAuthenticator(users *fakeStore, creds *fakeCredentialStore) *LocalAuthenticator {
	fixedNow := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	return &LocalAuthenticator{
		Users:       users,
		Credentials: creds,
		Now:         func() time.Time { return fixedNow },
	}
}

func TestLocalAuthenticator_LoginSucceedsWithCorrectPassword(t *testing.T) {
	users := newFakeStore()
	creds := newFakeCredentialStore()
	a := newTestAuthenticator(users, creds)
	ctx := context.Background()

	user, err := users.CreateUser(ctx, "person@example.com", true)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := a.SetPassword(ctx, user.ID, "correct horse battery staple"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	got, err := a.Login(ctx, "person@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != user.ID {
		t.Fatalf("expected to authenticate as %s, got %s", user.ID, got.ID)
	}
}

func TestLocalAuthenticator_LoginFailsWithWrongPassword(t *testing.T) {
	users := newFakeStore()
	creds := newFakeCredentialStore()
	a := newTestAuthenticator(users, creds)
	ctx := context.Background()

	user, _ := users.CreateUser(ctx, "person@example.com", true)
	if err := a.SetPassword(ctx, user.ID, "correct horse battery staple"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	if _, err := a.Login(ctx, "person@example.com", "wrong password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	if creds.creds[user.ID].FailedAttempts != 1 {
		t.Fatalf("expected failed_attempts=1, got %d", creds.creds[user.ID].FailedAttempts)
	}
}

func TestLocalAuthenticator_LoginFailsForUnknownEmail(t *testing.T) {
	a := newTestAuthenticator(newFakeStore(), newFakeCredentialStore())

	if _, err := a.Login(context.Background(), "nobody@example.com", "whatever"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for an unknown email, got %v", err)
	}
}

func TestLocalAuthenticator_LoginFailsForSSOOnlyAccount(t *testing.T) {
	users := newFakeStore()
	a := newTestAuthenticator(users, newFakeCredentialStore())
	ctx := context.Background()

	// SSO経由で作成されたユーザにはlocal_credentialsが無い(FindNotFound)。
	if _, err := users.CreateUser(ctx, "sso-only@example.com", true); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if _, err := a.Login(ctx, "sso-only@example.com", "whatever"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for an SSO-only account, got %v", err)
	}
}

func TestLocalAuthenticator_LocksAfterRepeatedFailures(t *testing.T) {
	users := newFakeStore()
	creds := newFakeCredentialStore()
	a := newTestAuthenticator(users, creds)
	ctx := context.Background()

	user, _ := users.CreateUser(ctx, "person@example.com", true)
	if err := a.SetPassword(ctx, user.ID, "correct horse battery staple"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	for i := 0; i < maxFailedAttempts; i++ {
		if _, err := a.Login(ctx, "person@example.com", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: expected ErrInvalidCredentials, got %v", i, err)
		}
	}

	// ロックされた後は、正しいパスワードでもErrAccountLockedになる。
	if _, err := a.Login(ctx, "person@example.com", "correct horse battery staple"); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("expected ErrAccountLocked once the threshold is reached, got %v", err)
	}
}

func TestLocalAuthenticator_SuccessfulLoginResetsFailedAttempts(t *testing.T) {
	users := newFakeStore()
	creds := newFakeCredentialStore()
	a := newTestAuthenticator(users, creds)
	ctx := context.Background()

	user, _ := users.CreateUser(ctx, "person@example.com", true)
	if err := a.SetPassword(ctx, user.ID, "correct horse battery staple"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if _, err := a.Login(ctx, "person@example.com", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected the seeded failure to be rejected, got %v", err)
	}
	if creds.creds[user.ID].FailedAttempts != 1 {
		t.Fatalf("expected failed_attempts=1 before the successful login")
	}

	if _, err := a.Login(ctx, "person@example.com", "correct horse battery staple"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds.creds[user.ID].FailedAttempts != 0 {
		t.Fatalf("expected failed_attempts to reset to 0 after a successful login, got %d", creds.creds[user.ID].FailedAttempts)
	}
}

func TestLocalAuthenticator_SetPasswordRejectsShortPassword(t *testing.T) {
	a := newTestAuthenticator(newFakeStore(), newFakeCredentialStore())

	if err := a.SetPassword(context.Background(), uuid.New(), "short"); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("expected ErrPasswordTooShort, got %v", err)
	}
}
