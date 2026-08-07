package storage

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aiuemon/knives/internal/auth"
)

// LocalSignupVerificationStore adapts the sqlc-generated Queries to the
// auth.SignupVerificationStore port.
type LocalSignupVerificationStore struct {
	Q Querier
}

var _ auth.SignupVerificationStore = (*LocalSignupVerificationStore)(nil)

func NewLocalSignupVerificationStore(db DBTX) *LocalSignupVerificationStore {
	return &LocalSignupVerificationStore{Q: New(db)}
}

func (s *LocalSignupVerificationStore) CreatePendingSignup(ctx context.Context, email, passwordHash, tokenHash string, expiresAt time.Time) (uuid.UUID, error) {
	return s.Q.CreateLocalSignupVerification(ctx, CreateLocalSignupVerificationParams{
		Email:        email,
		PasswordHash: passwordHash,
		TokenHash:    tokenHash,
		ExpiresAt:    timestamptzOrNull(&expiresAt),
	})
}

func (s *LocalSignupVerificationStore) FindPendingSignupByTokenHash(ctx context.Context, tokenHash string) (*auth.SignupVerification, error) {
	row, err := s.Q.FindLocalSignupVerificationByTokenHash(ctx, tokenHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, auth.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &auth.SignupVerification{
		ID:           row.ID,
		Email:        row.Email,
		PasswordHash: row.PasswordHash,
		ExpiresAt:    row.ExpiresAt.Time,
	}, nil
}

func (s *LocalSignupVerificationStore) DeletePendingSignup(ctx context.Context, id uuid.UUID) error {
	return s.Q.DeleteLocalSignupVerification(ctx, id)
}
