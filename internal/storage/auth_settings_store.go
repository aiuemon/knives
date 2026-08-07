package storage

import "context"

// AuthSettingsStore reads the single-row auth_settings table (2.2節).
type AuthSettingsStore struct {
	Q Querier
}

func NewAuthSettingsStore(db DBTX) *AuthSettingsStore {
	return &AuthSettingsStore{Q: New(db)}
}

func (s *AuthSettingsStore) FindAuthSettings(ctx context.Context) (localAuthEnabled, selfSignupEnabled, requireEmailConfirmation bool, err error) {
	row, err := s.Q.FindAuthSettings(ctx)
	if err != nil {
		return false, false, false, err
	}
	return row.LocalAuthEnabled, row.SelfSignupEnabled, row.RequireEmailConfirmationForSignup, nil
}
