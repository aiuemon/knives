package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// DefaultPendingLinkTTL is the confirmation link lifetime used when
// Resolver.TokenTTL is unset (docs/architecture.md 3.4節-4: 「例: 30分」).
const DefaultPendingLinkTTL = 30 * time.Minute

var (
	ErrNotFound         = errors.New("auth: not found")
	ErrTokenExpired     = errors.New("auth: confirmation token expired")
	ErrTokenAlreadyUsed = errors.New("auth: confirmation token already used")
)

type ProviderType string

const (
	ProviderLocal ProviderType = "local"
	ProviderSAML  ProviderType = "saml"
	ProviderOIDC  ProviderType = "oidc"
)

type User struct {
	ID            uuid.UUID
	Email         string
	EmailVerified bool
}

type AuthIdentity struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	EmailAtLink string
}

type PendingLinkRequest struct {
	ID               uuid.UUID
	ExistingUserID   uuid.UUID
	ProviderType     ProviderType
	ProviderConfigID *uuid.UUID
	Subject          string
	ExpiresAt        time.Time
	ConfirmedAt      *time.Time
}

type AuditLogEntry struct {
	ActorUserID *uuid.UUID
	Action      string
	TargetType  string
	TargetID    string
	Metadata    map[string]any
}

// LoginAttempt is the provider-agnostic input to identity resolution. The
// SAML/OIDC/local HTTP handlers are responsible for extracting these values
// (NameID/sub, email claim, and the trust decision) before calling Resolve;
// this package never talks to an IdP directly.
type LoginAttempt struct {
	ProviderType ProviderType
	// ProviderConfigID references idp_saml_configs/idp_oidc_configs; nil for local.
	ProviderConfigID *uuid.UUID
	// Subject is the IdP-side identifier (NameID/sub). For local, callers
	// should pass the email itself, since local has no separate ID namespace.
	Subject string
	Email   string
	// EmailVerified seeds users.email_verified when this attempt results in
	// a brand-new user (e.g. OIDC email_verified claim, or
	// !auth_settings.require_email_confirmation_for_signup for local signup).
	EmailVerified bool
	// Trusted is the already-evaluated IdP trust decision that allows
	// bypassing the confirmation-email flow when linking onto an
	// already-claimed existing user (3.4節1,2): for OIDC this is
	// require_email_verified_claim && claim.email_verified; for SAML it is
	// idp_saml_configs.trusted; for local self-signup it is always false.
	Trusted bool
}

// Store is the persistence port this package depends on. Implementations
// (internal/storage) must run the read-then-write sequence inside Resolve
// atomically per (provider_type, provider_config_id, subject) — e.g. via a
// serializable transaction or the auth_identities UNIQUE constraint plus
// retry-on-conflict — since concurrent logins for the same never-seen
// identity would otherwise race between FindAuthIdentity and CreateUser/
// CreateAuthIdentity.
type Store interface {
	FindAuthIdentity(ctx context.Context, providerType ProviderType, providerConfigID *uuid.UUID, subject string) (*AuthIdentity, error)
	FindUserByEmail(ctx context.Context, email string) (*User, error)
	FindUserByID(ctx context.Context, id uuid.UUID) (*User, error)
	CountAuthIdentitiesForUser(ctx context.Context, userID uuid.UUID) (int, error)
	CreateUser(ctx context.Context, email string, emailVerified bool) (*User, error)
	CreateAuthIdentity(ctx context.Context, userID uuid.UUID, providerType ProviderType, providerConfigID *uuid.UUID, subject, emailAtLink string, verified bool) (*AuthIdentity, error)
	TouchAuthIdentity(ctx context.Context, id uuid.UUID, at time.Time) error
	CreatePendingLinkRequest(ctx context.Context, existingUserID uuid.UUID, providerType ProviderType, providerConfigID *uuid.UUID, subject, tokenHash string, expiresAt time.Time) (uuid.UUID, error)
	FindPendingLinkRequestByTokenHash(ctx context.Context, tokenHash string) (*PendingLinkRequest, error)
	ConfirmPendingLinkRequest(ctx context.Context, id uuid.UUID, at time.Time) error
	RecordAuditLog(ctx context.Context, entry AuditLogEntry) error
}

// ConfirmationMailer sends the account-linking confirmation email
// (3.4節-4). It is always addressed to the existing account's current
// registered email, never to the email claimed by the new login attempt.
type ConfirmationMailer interface {
	SendAccountLinkConfirmation(ctx context.Context, toEmail, confirmURL string) error
}

type Outcome int

const (
	OutcomeLoggedIn Outcome = iota
	OutcomePendingConfirmation
)

type Result struct {
	Outcome Outcome
	// User is set only when Outcome == OutcomeLoggedIn.
	User *User
}

type Resolver struct {
	Store  Store
	Mailer ConfirmationMailer
	// Now defaults to time.Now when nil; override in tests.
	Now func() time.Time
	// ConfirmBaseURL is the confirmation page URL; the raw token is appended
	// as a "token" query parameter.
	ConfirmBaseURL string
	// TokenTTL defaults to DefaultPendingLinkTTL when zero.
	TokenTTL time.Duration
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Resolve implements the account-integration policy of docs/architecture.md
// 3.4節: 「信頼済みSSOは自動統合、それ以外は確認メール必須」. It never
// authenticates the caller — it is the single place identity/linking
// decisions are made once a SAML/OIDC/local handler has produced a
// LoginAttempt.
func (r *Resolver) Resolve(ctx context.Context, attempt LoginAttempt) (*Result, error) {
	now := r.now()

	identity, err := r.Store.FindAuthIdentity(ctx, attempt.ProviderType, attempt.ProviderConfigID, attempt.Subject)
	switch {
	case err == nil:
		if !strings.EqualFold(identity.EmailAtLink, attempt.Email) {
			// メール再割当て対策(3.4節5): このIDが以前と違うメールを
			// 名乗ってきた場合は自動更新せず再確認フローに回す。
			if err := r.requestConfirmation(ctx, identity.UserID, attempt, now); err != nil {
				return nil, err
			}
			return &Result{Outcome: OutcomePendingConfirmation}, nil
		}
		if err := r.Store.TouchAuthIdentity(ctx, identity.ID, now); err != nil {
			return nil, err
		}
		user, err := r.Store.FindUserByID(ctx, identity.UserID)
		if err != nil {
			return nil, err
		}
		return &Result{Outcome: OutcomeLoggedIn, User: user}, nil
	case errors.Is(err, ErrNotFound):
		// このprovider/subjectの組み合わせは初見。以下で新規/既存ユーザへの
		// 統合可否を判定する。
	default:
		return nil, err
	}

	existingUser, err := r.Store.FindUserByEmail(ctx, attempt.Email)
	if errors.Is(err, ErrNotFound) {
		user, err := r.Store.CreateUser(ctx, attempt.Email, attempt.EmailVerified)
		if err != nil {
			return nil, err
		}
		if err := r.attachIdentity(ctx, user.ID, attempt, true); err != nil {
			return nil, err
		}
		return &Result{Outcome: OutcomeLoggedIn, User: user}, nil
	}
	if err != nil {
		return nil, err
	}

	identityCount, err := r.Store.CountAuthIdentitiesForUser(ctx, existingUser.ID)
	if err != nil {
		return nil, err
	}

	// identityCount == 0 は誰もログインしたことのないプレースホルダ
	// (例: YOURLS移行時に事前作成したユーザ、10節)の初回有効化であり、
	// 乗っ取りリスクがないため直接アタッチしてよい。それ以外で許可されるのは
	// IdPが検証済みと保証する場合(Trusted)のみ。
	if identityCount == 0 || attempt.Trusted {
		if err := r.attachIdentity(ctx, existingUser.ID, attempt, false); err != nil {
			return nil, err
		}
		return &Result{Outcome: OutcomeLoggedIn, User: existingUser}, nil
	}

	// 既に他の手段でクレーム済みのアカウントへの非信頼な統合要求
	// (未信頼SAML/未検証OIDC/ローカルセルフサインアップ、3.4節3)。
	if err := r.requestConfirmation(ctx, existingUser.ID, attempt, now); err != nil {
		return nil, err
	}
	return &Result{Outcome: OutcomePendingConfirmation}, nil
}

// ConfirmPendingLink completes the confirmation-email flow (3.4節-4) after
// the existing account owner clicks the link mailed by requestConfirmation.
func (r *Resolver) ConfirmPendingLink(ctx context.Context, rawToken string) (*Result, error) {
	now := r.now()

	pending, err := r.Store.FindPendingLinkRequestByTokenHash(ctx, hashToken(rawToken))
	if err != nil {
		return nil, err
	}
	if pending.ConfirmedAt != nil {
		return nil, ErrTokenAlreadyUsed
	}
	if now.After(pending.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	user, err := r.Store.FindUserByID(ctx, pending.ExistingUserID)
	if err != nil {
		return nil, err
	}

	// email_at_link はこのアカウントの現在の正規メールで記録する
	// (pending_link_requests は候補側のメールを保持しないため)。
	identity, err := r.Store.CreateAuthIdentity(ctx, user.ID, pending.ProviderType, pending.ProviderConfigID, pending.Subject, user.Email, true)
	if err != nil {
		return nil, err
	}
	if err := r.Store.ConfirmPendingLinkRequest(ctx, pending.ID, now); err != nil {
		return nil, err
	}
	if err := r.recordLinkAudit(ctx, user.ID, identity.ID, pending.ProviderType, map[string]any{
		"via": "email_confirmation",
	}); err != nil {
		return nil, err
	}
	return &Result{Outcome: OutcomeLoggedIn, User: user}, nil
}

func (r *Resolver) attachIdentity(ctx context.Context, userID uuid.UUID, attempt LoginAttempt, newUser bool) error {
	identity, err := r.Store.CreateAuthIdentity(ctx, userID, attempt.ProviderType, attempt.ProviderConfigID, attempt.Subject, attempt.Email, true)
	if err != nil {
		return err
	}
	return r.recordLinkAudit(ctx, userID, identity.ID, attempt.ProviderType, map[string]any{
		"new_user": newUser,
		"trusted":  attempt.Trusted,
	})
}

func (r *Resolver) recordLinkAudit(ctx context.Context, userID, identityID uuid.UUID, providerType ProviderType, extra map[string]any) error {
	metadata := map[string]any{"provider_type": string(providerType)}
	for k, v := range extra {
		metadata[k] = v
	}
	return r.Store.RecordAuditLog(ctx, AuditLogEntry{
		ActorUserID: &userID,
		Action:      "account.link",
		TargetType:  "auth_identity",
		TargetID:    identityID.String(),
		Metadata:    metadata,
	})
}

func (r *Resolver) requestConfirmation(ctx context.Context, existingUserID uuid.UUID, attempt LoginAttempt, now time.Time) error {
	rawToken, tokenHash, err := generateToken()
	if err != nil {
		return err
	}
	ttl := r.TokenTTL
	if ttl <= 0 {
		ttl = DefaultPendingLinkTTL
	}
	if _, err := r.Store.CreatePendingLinkRequest(ctx, existingUserID, attempt.ProviderType, attempt.ProviderConfigID, attempt.Subject, tokenHash, now.Add(ttl)); err != nil {
		return err
	}

	// 確認メールは常に「現在の」既存アカウントの登録メール宛に送る。
	// attempt.Email(なりすましの可能性がある側)には絶対に送らない。
	existingUser, err := r.Store.FindUserByID(ctx, existingUserID)
	if err != nil {
		return err
	}
	confirmURL := fmt.Sprintf("%s?token=%s", r.ConfirmBaseURL, rawToken)
	return r.Mailer.SendAccountLinkConfirmation(ctx, existingUser.Email, confirmURL)
}

func generateToken() (raw, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(buf)
	return raw, hashToken(raw), nil
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
