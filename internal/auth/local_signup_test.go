package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fakeSignupMailer struct {
	confirmCalls                  int
	verifyCalls                   int
	lastConfirmTo, lastConfirmURL string
	lastVerifyTo, lastVerifyURL   string
}

func (m *fakeSignupMailer) SendAccountLinkConfirmation(_ context.Context, toEmail, confirmURL string) error {
	m.confirmCalls++
	m.lastConfirmTo = toEmail
	m.lastConfirmURL = confirmURL
	return nil
}

func (m *fakeSignupMailer) SendSignupVerification(_ context.Context, toEmail, verifyURL string) error {
	m.verifyCalls++
	m.lastVerifyTo = toEmail
	m.lastVerifyURL = verifyURL
	return nil
}

type fakeSignupStore struct {
	byHash map[string]*SignupVerification
}

func newFakeSignupStore() *fakeSignupStore {
	return &fakeSignupStore{byHash: map[string]*SignupVerification{}}
}

func (s *fakeSignupStore) CreatePendingSignup(_ context.Context, email, passwordHash, tokenHash string, expiresAt time.Time) (uuid.UUID, error) {
	id := uuid.New()
	s.byHash[tokenHash] = &SignupVerification{ID: id, Email: email, PasswordHash: passwordHash, ExpiresAt: expiresAt}
	return id, nil
}

func (s *fakeSignupStore) FindPendingSignupByTokenHash(_ context.Context, tokenHash string) (*SignupVerification, error) {
	v, ok := s.byHash[tokenHash]
	if !ok {
		return nil, ErrNotFound
	}
	return v, nil
}

func (s *fakeSignupStore) DeletePendingSignup(_ context.Context, id uuid.UUID) error {
	for h, v := range s.byHash {
		if v.ID == id {
			delete(s.byHash, h)
		}
	}
	return nil
}

func newTestLocalSignup(users *fakeStore, creds *fakeCredentialStore, signupStore *fakeSignupStore, mailer *fakeSignupMailer) *LocalSignup {
	fixedNow := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	return &LocalSignup{
		Store:  signupStore,
		Mailer: mailer,
		Resolver: &Resolver{
			Store:          users,
			Mailer:         mailer,
			Now:            func() time.Time { return fixedNow },
			ConfirmBaseURL: "https://go.example.com/auth/confirm-link",
		},
		Credentials:   creds,
		Now:           func() time.Time { return fixedNow },
		VerifyBaseURL: "https://go.example.com/auth/verify-email",
	}
}

func TestLocalSignup_NoConfirmationRequired_CreatesAndLogsInImmediately(t *testing.T) {
	users := newFakeStore()
	creds := newFakeCredentialStore()
	ls := newTestLocalSignup(users, creds, newFakeSignupStore(), &fakeSignupMailer{})
	ctx := context.Background()

	result, err := ls.Start(ctx, "new@example.com", "correct horse battery staple", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Outcome != SignupOutcomeLoggedIn {
		t.Fatalf("expected SignupOutcomeLoggedIn, got %v", result.Outcome)
	}
	if _, ok := creds.creds[result.User.ID]; !ok {
		t.Fatalf("expected a password to be attached to the new user")
	}
}

func TestLocalSignup_ConfirmationRequired_DoesNotCreateAnyAccountUntilVerified(t *testing.T) {
	users := newFakeStore()
	creds := newFakeCredentialStore()
	mailer := &fakeSignupMailer{}
	ls := newTestLocalSignup(users, creds, newFakeSignupStore(), mailer)
	ctx := context.Background()

	result, err := ls.Start(ctx, "new@example.com", "correct horse battery staple", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Outcome != SignupOutcomeVerificationPending {
		t.Fatalf("expected SignupOutcomeVerificationPending, got %v", result.Outcome)
	}
	if mailer.verifyCalls != 1 || mailer.lastVerifyTo != "new@example.com" {
		t.Fatalf("expected one signup-verification email to the submitted address, got %+v", mailer)
	}
	if _, err := users.FindUserByEmail(ctx, "new@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no user must exist before the email is verified, got %v", err)
	}
}

func TestLocalSignup_VerifyEmail_CompletesSignupAndAttachesPassword(t *testing.T) {
	users := newFakeStore()
	creds := newFakeCredentialStore()
	signupStore := newFakeSignupStore()
	mailer := &fakeSignupMailer{}
	ls := newTestLocalSignup(users, creds, signupStore, mailer)
	ctx := context.Background()

	if _, err := ls.Start(ctx, "new@example.com", "correct horse battery staple", true); err != nil {
		t.Fatalf("Start: %v", err)
	}
	token := extractToken(t, mailer.lastVerifyURL)

	result, err := ls.VerifyEmail(ctx, token)
	if err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if result.Outcome != SignupOutcomeLoggedIn {
		t.Fatalf("expected SignupOutcomeLoggedIn, got %v", result.Outcome)
	}
	if _, ok := creds.creds[result.User.ID]; !ok {
		t.Fatalf("expected the password to be attached after verification")
	}
	if len(signupStore.byHash) != 0 {
		t.Fatalf("expected the pending verification record to be consumed, got %d remaining", len(signupStore.byHash))
	}

	// verifyトークンは使い切り(再利用不可)であることも確認する。
	if _, err := ls.VerifyEmail(ctx, token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound on reuse of a consumed token, got %v", err)
	}
}

func TestLocalSignup_VerifyEmail_ExpiredTokenIsRejected(t *testing.T) {
	users := newFakeStore()
	creds := newFakeCredentialStore()
	signupStore := newFakeSignupStore()
	mailer := &fakeSignupMailer{}

	current := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	ls := &LocalSignup{
		Store:         signupStore,
		Mailer:        mailer,
		Resolver:      &Resolver{Store: users, Mailer: mailer, Now: func() time.Time { return current }},
		Credentials:   creds,
		Now:           func() time.Time { return current },
		VerifyBaseURL: "https://go.example.com/auth/verify-email",
		TokenTTL:      time.Minute,
	}
	ctx := context.Background()

	if _, err := ls.Start(ctx, "new@example.com", "correct horse battery staple", true); err != nil {
		t.Fatalf("Start: %v", err)
	}
	token := extractToken(t, mailer.lastVerifyURL)

	current = current.Add(2 * time.Minute)

	if _, err := ls.VerifyEmail(ctx, token); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
	if _, err := users.FindUserByEmail(ctx, "new@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an expired verification must not create a user, got %v", err)
	}
}

func TestLocalSignup_WeakPasswordRejectedBeforeStoringAnything(t *testing.T) {
	signupStore := newFakeSignupStore()
	mailer := &fakeSignupMailer{}
	ls := newTestLocalSignup(newFakeStore(), newFakeCredentialStore(), signupStore, mailer)

	if _, err := ls.Start(context.Background(), "new@example.com", "short", true); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("expected ErrPasswordTooShort, got %v", err)
	}
	if len(signupStore.byHash) != 0 || mailer.verifyCalls != 0 {
		t.Fatalf("a rejected password must not create a pending record or send mail")
	}
}

func TestLocalSignup_CollidingEmailNeverAttachesPasswordToVictim(t *testing.T) {
	users := newFakeStore()
	creds := newFakeCredentialStore()
	mailer := &fakeSignupMailer{}
	ls := newTestLocalSignup(users, creds, newFakeSignupStore(), mailer)
	ctx := context.Background()

	// victimは信頼済みOIDCで既にアカウントをクレーム済み。
	victim, err := users.CreateUser(ctx, "victim@example.com", true)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	cfgID := uuid.New()
	if _, err := users.CreateAuthIdentity(ctx, victim.ID, ProviderOIDC, &cfgID, "victim-sub", "victim@example.com", true); err != nil {
		t.Fatalf("CreateAuthIdentity: %v", err)
	}

	// require_email_confirmation_for_signup=false でも、既存クレーム済み
	// アカウントへの統合はResolverの3.4節ポリシーに従い保留される。
	result, err := ls.Start(ctx, "victim@example.com", "attacker-chosen-password", false)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if result.Outcome != SignupOutcomeVerificationPending {
		t.Fatalf("expected SignupOutcomeVerificationPending on collision, got %v", result.Outcome)
	}
	if _, ok := creds.creds[victim.ID]; ok {
		t.Fatalf("the attacker's password must never be attached to the victim's account")
	}
	if mailer.confirmCalls != 1 || mailer.lastConfirmTo != "victim@example.com" {
		t.Fatalf("expected an account-link confirmation to the real owner, got %+v", mailer)
	}
}
