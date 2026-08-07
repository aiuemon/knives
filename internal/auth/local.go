package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/google/uuid"
)

const (
	// maxFailedAttempts/lockoutDuration implement local_credentials'
	// failed_attempts/locked_until columns, documented in 2.2節 as
	// "ブルートフォース対策" without prescribing exact numbers.
	maxFailedAttempts = 5
	lockoutDuration   = 15 * time.Minute

	minPasswordLength = 8
)

var (
	// ErrInvalidCredentials is returned for every rejected-login reason
	// (unknown email, no local password set, wrong password) so callers
	// can't distinguish "no such account" from "wrong password" — doing so
	// would let an attacker enumerate registered emails.
	ErrInvalidCredentials = errors.New("auth: invalid email or password")
	ErrAccountLocked      = errors.New("auth: account temporarily locked due to too many failed attempts")
	ErrPasswordTooShort   = fmt.Errorf("auth: password must be at least %d characters", minPasswordLength)
)

// dummyHash lets Login always run one argon2id comparison, even when there
// is no real hash to check against (unknown email, SSO-only account),
// so those paths take roughly the same time as a real wrong-password
// check and don't leak account existence via a timing side channel.
var dummyHash = mustHash("knives-timing-safety-dummy-password")

func mustHash(password string) string {
	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		panic(err)
	}
	return hash
}

type LocalCredential struct {
	UserID         uuid.UUID
	PasswordHash   string // empty if this user has never set a local password
	FailedAttempts int
	LockedUntil    *time.Time
}

// LocalCredentialStore is the persistence port for local_credentials.
type LocalCredentialStore interface {
	// FindLocalCredential returns ErrNotFound if userID has no
	// local_credentials row at all (e.g. an SSO-only account).
	FindLocalCredential(ctx context.Context, userID uuid.UUID) (*LocalCredential, error)
	// SetPassword replaces userID's password hash and clears any lockout
	// state, creating the row if it doesn't exist yet. Used by both local
	// self-signup and password resets.
	SetPassword(ctx context.Context, userID uuid.UUID, passwordHash string) error
	// RecordFailedAttempt persists the new failed_attempts count and,
	// once the threshold is reached, a lockedUntil deadline.
	RecordFailedAttempt(ctx context.Context, userID uuid.UUID, failedAttempts int, lockedUntil *time.Time) error
	// ResetFailedAttempts clears the counters after a successful login.
	ResetFailedAttempts(ctx context.Context, userID uuid.UUID) error
}

// LocalAuthenticator verifies local email+password logins (3.1節). Account
// creation/linking itself goes through Resolver.Resolve — this type only
// checks a password against an already-linked local identity's credential.
type LocalAuthenticator struct {
	Users       Store
	Credentials LocalCredentialStore
	// Now defaults to time.Now when nil; override in tests.
	Now func() time.Time
}

func (a *LocalAuthenticator) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// Login verifies email+password, enforcing the lockout policy on repeated
// failures. Every rejection reason collapses to ErrInvalidCredentials
// except ErrAccountLocked, which is intentionally distinguishable so the
// UI can explain the lockout without revealing whether the password itself
// was correct.
func (a *LocalAuthenticator) Login(ctx context.Context, email, password string) (*User, error) {
	user, err := a.Users.FindUserByEmail(ctx, email)
	if errors.Is(err, ErrNotFound) {
		_, _ = argon2id.ComparePasswordAndHash(password, dummyHash)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}

	cred, err := a.Credentials.FindLocalCredential(ctx, user.ID)
	if errors.Is(err, ErrNotFound) {
		_, _ = argon2id.ComparePasswordAndHash(password, dummyHash)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	if cred.PasswordHash == "" {
		_, _ = argon2id.ComparePasswordAndHash(password, dummyHash)
		return nil, ErrInvalidCredentials
	}

	now := a.now()
	if cred.LockedUntil != nil && now.Before(*cred.LockedUntil) {
		return nil, ErrAccountLocked
	}

	match, err := argon2id.ComparePasswordAndHash(password, cred.PasswordHash)
	if err != nil {
		return nil, err
	}
	if !match {
		attempts := cred.FailedAttempts + 1
		var lockedUntil *time.Time
		if attempts >= maxFailedAttempts {
			t := now.Add(lockoutDuration)
			lockedUntil = &t
		}
		if err := a.Credentials.RecordFailedAttempt(ctx, user.ID, attempts, lockedUntil); err != nil {
			return nil, err
		}
		return nil, ErrInvalidCredentials
	}

	if cred.FailedAttempts > 0 || cred.LockedUntil != nil {
		if err := a.Credentials.ResetFailedAttempts(ctx, user.ID); err != nil {
			return nil, err
		}
	}
	return user, nil
}

// SetPassword hashes and stores a new password for userID. Used for local
// self-signup (after Resolver.Resolve links the identity) and for password
// resets.
func (a *LocalAuthenticator) SetPassword(ctx context.Context, userID uuid.UUID, newPassword string) error {
	if len(newPassword) < minPasswordLength {
		return ErrPasswordTooShort
	}
	hash, err := argon2id.CreateHash(newPassword, argon2id.DefaultParams)
	if err != nil {
		return err
	}
	return a.Credentials.SetPassword(ctx, userID, hash)
}
