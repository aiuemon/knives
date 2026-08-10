package auth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/google/uuid"
)

// OIDCConfig is one configured OIDC IdP connection (3.3節・4節).
type OIDCConfig struct {
	ID     uuid.UUID
	Name   string
	Issuer string

	ClientID string
	// ClientSecret is plaintext in memory. Persistence encrypts it at rest
	// (idp_oidc_configs.client_secret_encrypted) — that's the storage
	// layer's concern, not this package's; the domain type just carries
	// whatever the login flow needs to build an oauth2.Config.
	ClientSecret string

	Scopes []string
	// RequireEmailVerifiedClaim gates auto-linking (3.4節-1): true (the
	// default) trusts a login only when the IdP's email_verified claim is
	// also true; false means this IdP's claim is never trusted as a basis
	// for auto-linking, and every login goes through the confirm-email
	// flow regardless of what the claim says.
	RequireEmailVerifiedClaim bool
	Enabled                   bool
}

var (
	// ErrInvalidOIDCConfig wraps every field-validation failure so callers
	// can map the whole family to 400 Bad Request with errors.Is.
	ErrInvalidOIDCConfig = errors.New("auth: invalid oidc config")
	// ErrOIDCConfigInUse is returned by OIDCConfigService.Delete when
	// auth_identities still reference this config — mirrors
	// ErrSAMLConfigInUse for the same reason (idp_oidc_configs isn't a DB
	// foreign key target).
	ErrOIDCConfigInUse = errors.New("auth: oidc config still has linked users; disable it instead of deleting")
)

// OIDCConfigInput is the create/update payload. Every field is a full
// replace except ClientSecret: an empty ClientSecret on Update means "keep
// the existing secret" (the API never round-trips the secret back to the
// client, so there's nothing for an edit form to resend unless the admin
// is deliberately rotating it). Create requires a non-empty ClientSecret.
type OIDCConfigInput struct {
	Name                      string
	Issuer                    string
	ClientID                  string
	ClientSecret              string
	Scopes                    []string
	RequireEmailVerifiedClaim bool
	Enabled                   bool
}

func (in OIDCConfigInput) normalize(requireSecret bool) (OIDCConfigInput, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Issuer = strings.TrimSpace(in.Issuer)
	in.ClientID = strings.TrimSpace(in.ClientID)

	if in.Name == "" {
		return in, fmt.Errorf("%w: name is required", ErrInvalidOIDCConfig)
	}
	if in.ClientID == "" {
		return in, fmt.Errorf("%w: client_id is required", ErrInvalidOIDCConfig)
	}
	if requireSecret && in.ClientSecret == "" {
		return in, fmt.Errorf("%w: client_secret is required", ErrInvalidOIDCConfig)
	}

	u, err := url.Parse(in.Issuer)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return in, fmt.Errorf("%w: issuer must be an absolute http(s) URL", ErrInvalidOIDCConfig)
	}

	scopes := make([]string, 0, len(in.Scopes))
	for _, s := range in.Scopes {
		if s = strings.TrimSpace(s); s != "" {
			scopes = append(scopes, s)
		}
	}
	if !slices.Contains(scopes, "openid") {
		return in, fmt.Errorf("%w: scopes must include \"openid\"", ErrInvalidOIDCConfig)
	}
	in.Scopes = scopes

	return in, nil
}

// OIDCConfigStore is the persistence port for managing OIDC IdP
// connections (system_admin only, 4節).
type OIDCConfigStore interface {
	ListOIDCConfigs(ctx context.Context) ([]*OIDCConfig, error)
	// FindOIDCConfigByID returns ErrNotFound if no such config exists.
	FindOIDCConfigByID(ctx context.Context, id uuid.UUID) (*OIDCConfig, error)
	CreateOIDCConfig(ctx context.Context, in OIDCConfigInput) (*OIDCConfig, error)
	// UpdateOIDCConfig returns ErrNotFound if id doesn't exist.
	// in.ClientSecret == "" means keep the existing encrypted secret.
	UpdateOIDCConfig(ctx context.Context, id uuid.UUID, in OIDCConfigInput) (*OIDCConfig, error)
	// DeleteOIDCConfig returns ErrNotFound if id doesn't exist.
	DeleteOIDCConfig(ctx context.Context, id uuid.UUID) error
	// CountAuthIdentitiesForOIDCConfig lets Delete refuse to remove a
	// config that auth_identities still reference.
	CountAuthIdentitiesForOIDCConfig(ctx context.Context, id uuid.UUID) (int, error)
}

// OIDCConfigService validates input before delegating to Store, mirroring
// SAMLConfigService.
type OIDCConfigService struct {
	Store OIDCConfigStore
}

func (s *OIDCConfigService) List(ctx context.Context) ([]*OIDCConfig, error) {
	return s.Store.ListOIDCConfigs(ctx)
}

func (s *OIDCConfigService) Get(ctx context.Context, id uuid.UUID) (*OIDCConfig, error) {
	return s.Store.FindOIDCConfigByID(ctx, id)
}

func (s *OIDCConfigService) Create(ctx context.Context, in OIDCConfigInput) (*OIDCConfig, error) {
	normalized, err := in.normalize(true)
	if err != nil {
		return nil, err
	}
	return s.Store.CreateOIDCConfig(ctx, normalized)
}

func (s *OIDCConfigService) Update(ctx context.Context, id uuid.UUID, in OIDCConfigInput) (*OIDCConfig, error) {
	normalized, err := in.normalize(false)
	if err != nil {
		return nil, err
	}
	return s.Store.UpdateOIDCConfig(ctx, id, normalized)
}

// Delete refuses to remove a config still referenced by auth_identities —
// see ErrOIDCConfigInUse.
func (s *OIDCConfigService) Delete(ctx context.Context, id uuid.UUID) error {
	count, err := s.Store.CountAuthIdentitiesForOIDCConfig(ctx, id)
	if err != nil {
		return err
	}
	if count > 0 {
		return ErrOIDCConfigInUse
	}
	return s.Store.DeleteOIDCConfig(ctx, id)
}
