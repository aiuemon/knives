package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/google/uuid"
)

// SignupVerification is a pending local self-signup: the email has not yet
// been proven reachable, so no users/auth_identities/local_credentials row
// exists for it yet (local-auth専用の登録前ゲート、他のprovider種別には
// 適用されない).
type SignupVerification struct {
	ID           uuid.UUID
	Email        string
	PasswordHash string
	ExpiresAt    time.Time
}

// SignupVerificationStore is the persistence port for local_signup_verifications.
type SignupVerificationStore interface {
	CreatePendingSignup(ctx context.Context, email, passwordHash, tokenHash string, expiresAt time.Time) (uuid.UUID, error)
	// FindPendingSignupByTokenHash returns ErrNotFound if no such token exists.
	FindPendingSignupByTokenHash(ctx context.Context, tokenHash string) (*SignupVerification, error)
	DeletePendingSignup(ctx context.Context, id uuid.UUID) error
}

// SignupVerificationMailer sends the "prove you own this email" link,
// distinct from ConfirmationMailer's account-linking email (3.4節) even
// though both may end up mailing the same address in an edge case (see
// LocalSignup.resolveAndAttach).
type SignupVerificationMailer interface {
	SendSignupVerification(ctx context.Context, toEmail, verifyURL string) error
}

type SignupOutcome int

const (
	// SignupOutcomeLoggedIn: the account now exists (or was activated) and
	// the caller should issue a session.
	SignupOutcomeLoggedIn SignupOutcome = iota
	// SignupOutcomeVerificationPending: an email was sent (either the
	// email-ownership check, or — once that check has already passed —
	// 3.4節's account-linking confirmation because this email turned out
	// to already belong to a claimed account) and no session should be
	// issued yet.
	SignupOutcomeVerificationPending
)

type SignupResult struct {
	Outcome SignupOutcome
	// User is set only when Outcome == SignupOutcomeLoggedIn.
	User *User
}

// LocalSignup orchestrates local self-signup (3.1節). Unlike SSO logins,
// local signup has an extra registration-time gate: when
// requireEmailConfirmation is true, no user/identity/credential exists
// until the emailed link is clicked — Start only ever stores a pending,
// unlinked record.
type LocalSignup struct {
	Store       SignupVerificationStore
	Mailer      SignupVerificationMailer
	Resolver    *Resolver
	Credentials LocalCredentialStore
	// Now defaults to time.Now when nil; override in tests.
	Now func() time.Time
	// VerifyBaseURL is the email-verification page URL; the raw token is
	// appended as a "token" query parameter.
	VerifyBaseURL string
	// TokenTTL defaults to DefaultPendingLinkTTL when zero.
	TokenTTL time.Duration
}

func (ls *LocalSignup) now() time.Time {
	if ls.Now != nil {
		return ls.Now()
	}
	return time.Now()
}

// Start validates the password and either completes signup immediately
// (requireEmailConfirmation == false) or stores a pending, hashed-password
// verification record and emails a proof-of-ownership link.
func (ls *LocalSignup) Start(ctx context.Context, email, password string, requireEmailConfirmation bool) (*SignupResult, error) {
	if err := ValidatePasswordStrength(password); err != nil {
		return nil, err
	}
	passwordHash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		return nil, err
	}

	if !requireEmailConfirmation {
		return ls.resolveAndAttach(ctx, email, passwordHash, true)
	}
	return ls.startPendingVerification(ctx, email, passwordHash)
}

// VerifyEmail completes the flow after the user clicks the emailed link:
// the email is now proven reachable, so it hands off to Resolver.Resolve
// to actually create/attach the account per 3.4節's policy, then attaches
// the password that was hashed back at Start.
func (ls *LocalSignup) VerifyEmail(ctx context.Context, rawToken string) (*SignupResult, error) {
	pending, err := ls.Store.FindPendingSignupByTokenHash(ctx, hashToken(rawToken))
	if err != nil {
		return nil, err
	}
	if ls.now().After(pending.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	result, err := ls.resolveAndAttach(ctx, pending.Email, pending.PasswordHash, true)
	if err != nil {
		return nil, err
	}
	// 検証用レコードの役目(メール到達確認)はここで完了。以後の統合可否は
	// Resolver.Resolve(3.4節)の管轄であり、このレコードには依存しない。
	if err := ls.Store.DeletePendingSignup(ctx, pending.ID); err != nil {
		return nil, err
	}
	return result, nil
}

func (ls *LocalSignup) resolveAndAttach(ctx context.Context, email, passwordHash string, emailVerified bool) (*SignupResult, error) {
	result, err := ls.Resolver.Resolve(ctx, LoginAttempt{
		ProviderType:  ProviderLocal,
		Subject:       email, // localはIdP側IDを持たないため、emailをsubjectとして扱う
		Email:         email,
		EmailVerified: emailVerified,
		Trusted:       false, // ローカルセルフサインアップは3.4節のIdP信頼バイパス対象外
	})
	if err != nil {
		return nil, err
	}
	if result.Outcome == OutcomePendingConfirmation {
		// このメールは既に他アカウントにクレーム済み。メール到達確認は
		// 済んでいても、3.4節のなりすまし対策として既存アカウント宛の
		// 別の確認メールが送られる(同じ受信箱に2通届く場合があるが、
		// どちらも本人が開けるものなので許容する)。
		return &SignupResult{Outcome: SignupOutcomeVerificationPending}, nil
	}
	if err := ls.Credentials.SetPassword(ctx, result.User.ID, passwordHash); err != nil {
		return nil, err
	}
	return &SignupResult{Outcome: SignupOutcomeLoggedIn, User: result.User}, nil
}

func (ls *LocalSignup) startPendingVerification(ctx context.Context, email, passwordHash string) (*SignupResult, error) {
	rawToken, tokenHash, err := generateToken()
	if err != nil {
		return nil, err
	}
	ttl := ls.TokenTTL
	if ttl <= 0 {
		ttl = DefaultPendingLinkTTL
	}
	if _, err := ls.Store.CreatePendingSignup(ctx, email, passwordHash, tokenHash, ls.now().Add(ttl)); err != nil {
		return nil, err
	}

	verifyURL := fmt.Sprintf("%s?token=%s", ls.VerifyBaseURL, rawToken)
	if err := ls.Mailer.SendSignupVerification(ctx, email, verifyURL); err != nil {
		return nil, err
	}
	return &SignupResult{Outcome: SignupOutcomeVerificationPending}, nil
}
