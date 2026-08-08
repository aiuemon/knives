package storage

import (
	"context"

	"github.com/aiuemon/knives/internal/auth"
)

// AuthSettingsStore reads the single-row auth_settings table (2.2節).
type AuthSettingsStore struct {
	Q Querier
}

var _ auth.AuthSettingsProvider = (*AuthSettingsStore)(nil)

func NewAuthSettingsStore(db DBTX) *AuthSettingsStore {
	return &AuthSettingsStore{Q: New(db)}
}

func (s *AuthSettingsStore) FindAuthSettings(ctx context.Context) (localAuthEnabled, selfSignupEnabled, requireEmailConfirmation, requireReauthForAccountLink bool, err error) {
	row, err := s.Q.FindAuthSettings(ctx)
	if err != nil {
		return false, false, false, false, err
	}
	return row.LocalAuthEnabled, row.SelfSignupEnabled, row.RequireEmailConfirmationForSignup, row.RequireReauthForAccountLink, nil
}

// RequireReauthForAccountLink implements auth.AuthSettingsProvider for
// Resolver, which only needs this one field out of the full settings row.
func (s *AuthSettingsStore) RequireReauthForAccountLink(ctx context.Context) (bool, error) {
	_, _, _, requireReauth, err := s.FindAuthSettings(ctx)
	return requireReauth, err
}
