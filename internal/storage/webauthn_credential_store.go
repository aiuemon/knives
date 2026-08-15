package storage

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aiuemon/knives/internal/auth"
)

// WebAuthnCredentialStore adapts the sqlc-generated webauthn_credentials
// queries to the auth.WebAuthnCredentialStore port (3.1節).
type WebAuthnCredentialStore struct {
	Q Querier
}

var _ auth.WebAuthnCredentialStore = (*WebAuthnCredentialStore)(nil)

func NewWebAuthnCredentialStore(db DBTX) *WebAuthnCredentialStore {
	return &WebAuthnCredentialStore{Q: New(db)}
}

func (s *WebAuthnCredentialStore) FindWebAuthnCredentialsByUserID(ctx context.Context, userID uuid.UUID) ([]auth.WebAuthnCredential, error) {
	rows, err := s.Q.FindWebAuthnCredentialsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]auth.WebAuthnCredential, 0, len(rows))
	for _, row := range rows {
		result = append(result, toDomainWebAuthnCredential(row))
	}
	return result, nil
}

func (s *WebAuthnCredentialStore) CreateWebAuthnCredential(ctx context.Context, cred auth.WebAuthnCredential) error {
	err := s.Q.InsertWebAuthnCredential(ctx, InsertWebAuthnCredentialParams{
		UserID:       cred.UserID,
		CredentialID: cred.CredentialID,
		PublicKey:    cred.PublicKey,
		SignCount:    int64(cred.SignCount),
		Transports:   cred.Transports,
		Name:         textOrNull(cred.Name),
	})
	if isUniqueViolation(err) {
		return auth.ErrWebAuthnCredentialAlreadyRegistered
	}
	return err
}

func (s *WebAuthnCredentialStore) UpdateWebAuthnCredentialSignCount(ctx context.Context, credentialID []byte, signCount uint32) error {
	return s.Q.UpdateWebAuthnCredentialSignCount(ctx, UpdateWebAuthnCredentialSignCountParams{
		CredentialID: credentialID,
		SignCount:    int64(signCount),
	})
}

func (s *WebAuthnCredentialStore) UpdateWebAuthnCredentialName(ctx context.Context, id, userID uuid.UUID, name string) (*auth.WebAuthnCredential, error) {
	row, err := s.Q.UpdateWebAuthnCredentialName(ctx, UpdateWebAuthnCredentialNameParams{
		ID:     id,
		UserID: userID,
		Name:   textOrNull(name),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, auth.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	cred := toDomainWebAuthnCredential(row)
	return &cred, nil
}

func (s *WebAuthnCredentialStore) DeleteWebAuthnCredential(ctx context.Context, id, userID uuid.UUID) error {
	rows, err := s.Q.DeleteWebAuthnCredential(ctx, DeleteWebAuthnCredentialParams{ID: id, UserID: userID})
	if err != nil {
		return err
	}
	if rows == 0 {
		return auth.ErrNotFound
	}
	return nil
}

func toDomainWebAuthnCredential(row *WebauthnCredential) auth.WebAuthnCredential {
	cred := auth.WebAuthnCredential{
		ID:           row.ID,
		UserID:       row.UserID,
		CredentialID: row.CredentialID,
		PublicKey:    row.PublicKey,
		SignCount:    uint32(row.SignCount),
		Transports:   row.Transports,
		Name:         row.Name.String,
		CreatedAt:    row.CreatedAt.Time,
	}
	if row.LastUsedAt.Valid {
		t := row.LastUsedAt.Time
		cred.LastUsedAt = &t
	}
	return cred
}
