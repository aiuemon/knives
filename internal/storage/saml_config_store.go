package storage

import (
	"context"

	"github.com/aiuemon/knives/internal/auth"
	"github.com/google/uuid"
)

// SAMLConfigStore adapts the sqlc-generated Queries to the
// auth.SAMLConfigStore port.
type SAMLConfigStore struct {
	Q Querier
}

var _ auth.SAMLConfigStore = (*SAMLConfigStore)(nil)

func NewSAMLConfigStore(db DBTX) *SAMLConfigStore {
	return &SAMLConfigStore{Q: New(db)}
}

func toDomainSAMLConfig(row *IdpSamlConfig) *auth.SAMLConfig {
	return &auth.SAMLConfig{
		ID:             row.ID,
		Name:           row.Name,
		IdPEntityID:    row.IdpEntityID,
		IdPSSOURL:      row.IdpSsoUrl,
		IdPCertificate: row.IdpCertificate,
		EmailAttribute: row.EmailAttribute,
		Trusted:        row.Trusted,
		Enabled:        row.Enabled,
	}
}

func (s *SAMLConfigStore) ListSAMLConfigs(ctx context.Context) ([]*auth.SAMLConfig, error) {
	rows, err := s.Q.ListSAMLConfigs(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]*auth.SAMLConfig, 0, len(rows))
	for _, row := range rows {
		result = append(result, toDomainSAMLConfig(row))
	}
	return result, nil
}

func (s *SAMLConfigStore) FindSAMLConfigByID(ctx context.Context, id uuid.UUID) (*auth.SAMLConfig, error) {
	row, err := s.Q.FindSAMLConfigByID(ctx, id)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return toDomainSAMLConfig(row), nil
}

func (s *SAMLConfigStore) CreateSAMLConfig(ctx context.Context, in auth.SAMLConfigInput) (*auth.SAMLConfig, error) {
	row, err := s.Q.CreateSAMLConfig(ctx, CreateSAMLConfigParams{
		Name:           in.Name,
		IdpEntityID:    in.IdPEntityID,
		IdpSsoUrl:      in.IdPSSOURL,
		IdpCertificate: in.IdPCertificate,
		EmailAttribute: in.EmailAttribute,
		Trusted:        in.Trusted,
		Enabled:        in.Enabled,
	})
	if err != nil {
		return nil, err
	}
	return toDomainSAMLConfig(row), nil
}

func (s *SAMLConfigStore) UpdateSAMLConfig(ctx context.Context, id uuid.UUID, in auth.SAMLConfigInput) (*auth.SAMLConfig, error) {
	row, err := s.Q.UpdateSAMLConfig(ctx, UpdateSAMLConfigParams{
		ID:             id,
		Name:           in.Name,
		IdpEntityID:    in.IdPEntityID,
		IdpSsoUrl:      in.IdPSSOURL,
		IdpCertificate: in.IdPCertificate,
		EmailAttribute: in.EmailAttribute,
		Trusted:        in.Trusted,
		Enabled:        in.Enabled,
	})
	if err != nil {
		return nil, mapNotFound(err)
	}
	return toDomainSAMLConfig(row), nil
}

func (s *SAMLConfigStore) DeleteSAMLConfig(ctx context.Context, id uuid.UUID) error {
	rowsAffected, err := s.Q.DeleteSAMLConfig(ctx, id)
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return auth.ErrNotFound
	}
	return nil
}

func (s *SAMLConfigStore) CountAuthIdentitiesForSAMLConfig(ctx context.Context, id uuid.UUID) (int, error) {
	count, err := s.Q.CountAuthIdentitiesForSAMLConfig(ctx, uuid.NullUUID{UUID: id, Valid: true})
	if err != nil {
		return 0, err
	}
	return int(count), nil
}
