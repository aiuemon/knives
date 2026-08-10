package storage

import (
	"context"

	"github.com/aiuemon/knives/internal/auth"
	"github.com/google/uuid"
)

// OIDCConfigStore adapts the sqlc-generated Queries to the
// auth.OIDCConfigStore port, encrypting/decrypting client_secret at the
// boundary so nothing above this layer ever has to think about it.
type OIDCConfigStore struct {
	Q      Querier
	Cipher *CredentialCipher
}

var _ auth.OIDCConfigStore = (*OIDCConfigStore)(nil)

func NewOIDCConfigStore(db DBTX, cipher *CredentialCipher) *OIDCConfigStore {
	return &OIDCConfigStore{Q: New(db), Cipher: cipher}
}

func (s *OIDCConfigStore) toDomain(row *IdpOidcConfig) (*auth.OIDCConfig, error) {
	secret, err := s.Cipher.Decrypt(row.ClientSecretEncrypted)
	if err != nil {
		return nil, err
	}
	return &auth.OIDCConfig{
		ID:                        row.ID,
		Name:                      row.Name,
		Issuer:                    row.Issuer,
		ClientID:                  row.ClientID,
		ClientSecret:              secret,
		Scopes:                    row.Scopes,
		RequireEmailVerifiedClaim: row.RequireEmailVerifiedClaim,
		Enabled:                   row.Enabled,
	}, nil
}

func (s *OIDCConfigStore) ListOIDCConfigs(ctx context.Context) ([]*auth.OIDCConfig, error) {
	rows, err := s.Q.ListOIDCConfigs(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]*auth.OIDCConfig, 0, len(rows))
	for _, row := range rows {
		cfg, err := s.toDomain(row)
		if err != nil {
			return nil, err
		}
		result = append(result, cfg)
	}
	return result, nil
}

func (s *OIDCConfigStore) FindOIDCConfigByID(ctx context.Context, id uuid.UUID) (*auth.OIDCConfig, error) {
	row, err := s.Q.FindOIDCConfigByID(ctx, id)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return s.toDomain(row)
}

func (s *OIDCConfigStore) CreateOIDCConfig(ctx context.Context, in auth.OIDCConfigInput) (*auth.OIDCConfig, error) {
	encrypted, err := s.Cipher.Encrypt(in.ClientSecret)
	if err != nil {
		return nil, err
	}
	row, err := s.Q.CreateOIDCConfig(ctx, CreateOIDCConfigParams{
		Name:                      in.Name,
		Issuer:                    in.Issuer,
		ClientID:                  in.ClientID,
		ClientSecretEncrypted:     encrypted,
		Scopes:                    in.Scopes,
		RequireEmailVerifiedClaim: in.RequireEmailVerifiedClaim,
		Enabled:                   in.Enabled,
	})
	if err != nil {
		return nil, err
	}
	return s.toDomain(row)
}

// UpdateOIDCConfig replaces every field; in.ClientSecret == "" leaves the
// existing encrypted secret untouched (auth.OIDCConfigInput's contract) by
// using a different query that doesn't SET client_secret_encrypted at all.
func (s *OIDCConfigStore) UpdateOIDCConfig(ctx context.Context, id uuid.UUID, in auth.OIDCConfigInput) (*auth.OIDCConfig, error) {
	if in.ClientSecret == "" {
		row, err := s.Q.UpdateOIDCConfig(ctx, UpdateOIDCConfigParams{
			ID: id, Name: in.Name, Issuer: in.Issuer, ClientID: in.ClientID,
			Scopes: in.Scopes, RequireEmailVerifiedClaim: in.RequireEmailVerifiedClaim, Enabled: in.Enabled,
		})
		if err != nil {
			return nil, mapNotFound(err)
		}
		return s.toDomain(row)
	}

	encrypted, err := s.Cipher.Encrypt(in.ClientSecret)
	if err != nil {
		return nil, err
	}
	row, err := s.Q.UpdateOIDCConfigWithSecret(ctx, UpdateOIDCConfigWithSecretParams{
		ID: id, Name: in.Name, Issuer: in.Issuer, ClientID: in.ClientID,
		ClientSecretEncrypted: encrypted, Scopes: in.Scopes,
		RequireEmailVerifiedClaim: in.RequireEmailVerifiedClaim, Enabled: in.Enabled,
	})
	if err != nil {
		return nil, mapNotFound(err)
	}
	return s.toDomain(row)
}

func (s *OIDCConfigStore) DeleteOIDCConfig(ctx context.Context, id uuid.UUID) error {
	rowsAffected, err := s.Q.DeleteOIDCConfig(ctx, id)
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return auth.ErrNotFound
	}
	return nil
}

func (s *OIDCConfigStore) CountAuthIdentitiesForOIDCConfig(ctx context.Context, id uuid.UUID) (int, error) {
	count, err := s.Q.CountAuthIdentitiesForOIDCConfig(ctx, uuid.NullUUID{UUID: id, Valid: true})
	if err != nil {
		return 0, err
	}
	return int(count), nil
}
