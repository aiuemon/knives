package storage

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/aiuemon/knives/internal/auth"
)

// LocalCredentialStore adapts the sqlc-generated Queries to the
// auth.LocalCredentialStore port that LocalAuthenticator depends on.
type LocalCredentialStore struct {
	Q Querier
}

var _ auth.LocalCredentialStore = (*LocalCredentialStore)(nil)

func NewLocalCredentialStore(db DBTX) *LocalCredentialStore {
	return &LocalCredentialStore{Q: New(db)}
}

func (s *LocalCredentialStore) FindLocalCredential(ctx context.Context, userID uuid.UUID) (*auth.LocalCredential, error) {
	row, err := s.Q.FindLocalCredential(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, auth.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	var lockedUntil *time.Time
	if row.LockedUntil.Valid {
		t := row.LockedUntil.Time
		lockedUntil = &t
	}
	return &auth.LocalCredential{
		UserID:         row.UserID,
		PasswordHash:   row.PasswordHash.String, // zero value ("") when NULL, matching auth's "no password set" contract
		FailedAttempts: int(row.FailedAttempts),
		LockedUntil:    lockedUntil,
	}, nil
}

func (s *LocalCredentialStore) SetPassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	return s.Q.UpsertLocalCredentialPassword(ctx, UpsertLocalCredentialPasswordParams{
		UserID:       userID,
		PasswordHash: pgtype.Text{String: passwordHash, Valid: true},
	})
}

func (s *LocalCredentialStore) RecordFailedAttempt(ctx context.Context, userID uuid.UUID, failedAttempts int, lockedUntil *time.Time) error {
	return s.Q.RecordFailedLoginAttempt(ctx, RecordFailedLoginAttemptParams{
		UserID:         userID,
		FailedAttempts: int32(failedAttempts),
		LockedUntil:    timestamptzOrNull(lockedUntil),
	})
}

func (s *LocalCredentialStore) ResetFailedAttempts(ctx context.Context, userID uuid.UUID) error {
	return s.Q.ResetFailedLoginAttempts(ctx, userID)
}
