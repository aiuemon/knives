package auth

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

// SAMLConfig is one configured SAML IdP connection (3.2節・4節).
type SAMLConfig struct {
	ID             uuid.UUID
	Name           string
	IdPEntityID    string
	IdPSSOURL      string
	IdPCertificate string
	EmailAttribute string
	// Trusted marks this IdP as fully organization-managed (e.g. 社内
	// ADFS/Entra ID) — unlike OIDC, SAML has no standard verified-email
	// claim, so this is the admin's explicit substitute (3.4節-2).
	// Trusted=true auto-links a login to an existing user by email;
	// otherwise the confirm-email flow (3.4節-4) applies.
	Trusted bool
	Enabled bool
}

var (
	// ErrInvalidSAMLConfig wraps every field-validation failure so callers
	// can map the whole family to 400 Bad Request with errors.Is, while the
	// wrapped message still says which field was the problem.
	ErrInvalidSAMLConfig = errors.New("auth: invalid saml config")
	// ErrSAMLConfigInUse is returned by SAMLConfigService.Delete when
	// auth_identities still reference this config — deleting it out from
	// under those identities would leave provider_config_id dangling
	// (idp_saml_configs isn't a DB foreign key target; see
	// db/migrations/0001_init.up.sql). Disable it instead.
	ErrSAMLConfigInUse = errors.New("auth: saml config still has linked users; disable it instead of deleting")
)

// SAMLConfigInput is the create/update payload; both share the same
// validation, so update is a full replace, not a partial merge.
type SAMLConfigInput struct {
	Name           string
	IdPEntityID    string
	IdPSSOURL      string
	IdPCertificate string
	EmailAttribute string
	Trusted        bool
	Enabled        bool
}

func (in SAMLConfigInput) normalize() (SAMLConfigInput, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.IdPEntityID = strings.TrimSpace(in.IdPEntityID)
	in.EmailAttribute = strings.TrimSpace(in.EmailAttribute)
	in.IdPCertificate = strings.TrimSpace(in.IdPCertificate)

	if in.Name == "" {
		return in, fmt.Errorf("%w: name is required", ErrInvalidSAMLConfig)
	}
	if in.IdPEntityID == "" {
		return in, fmt.Errorf("%w: idp_entity_id is required", ErrInvalidSAMLConfig)
	}
	if in.EmailAttribute == "" {
		return in, fmt.Errorf("%w: email_attribute is required", ErrInvalidSAMLConfig)
	}

	u, err := url.Parse(in.IdPSSOURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return in, fmt.Errorf("%w: idp_sso_url must be an absolute http(s) URL", ErrInvalidSAMLConfig)
	}

	block, _ := pem.Decode([]byte(in.IdPCertificate))
	if block == nil {
		return in, fmt.Errorf("%w: idp_certificate must be a PEM-encoded certificate", ErrInvalidSAMLConfig)
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return in, fmt.Errorf("%w: idp_certificate is not a valid X.509 certificate", ErrInvalidSAMLConfig)
	}
	return in, nil
}

// SAMLConfigStore is the persistence port for managing SAML IdP
// connections (system_admin only, 4節).
type SAMLConfigStore interface {
	ListSAMLConfigs(ctx context.Context) ([]*SAMLConfig, error)
	// FindSAMLConfigByID returns ErrNotFound if no such config exists.
	FindSAMLConfigByID(ctx context.Context, id uuid.UUID) (*SAMLConfig, error)
	CreateSAMLConfig(ctx context.Context, in SAMLConfigInput) (*SAMLConfig, error)
	// UpdateSAMLConfig returns ErrNotFound if id doesn't exist.
	UpdateSAMLConfig(ctx context.Context, id uuid.UUID, in SAMLConfigInput) (*SAMLConfig, error)
	// DeleteSAMLConfig returns ErrNotFound if id doesn't exist.
	DeleteSAMLConfig(ctx context.Context, id uuid.UUID) error
	// CountAuthIdentitiesForSAMLConfig lets Delete refuse to remove a
	// config that auth_identities still reference.
	CountAuthIdentitiesForSAMLConfig(ctx context.Context, id uuid.UUID) (int, error)
}

// SAMLConfigService validates input before delegating to Store, so Store
// implementations can trust that whatever they receive is already
// well-formed (mirrors internal/shorturl.Service's Store/validation split).
type SAMLConfigService struct {
	Store SAMLConfigStore
}

func (s *SAMLConfigService) List(ctx context.Context) ([]*SAMLConfig, error) {
	return s.Store.ListSAMLConfigs(ctx)
}

func (s *SAMLConfigService) Get(ctx context.Context, id uuid.UUID) (*SAMLConfig, error) {
	return s.Store.FindSAMLConfigByID(ctx, id)
}

func (s *SAMLConfigService) Create(ctx context.Context, in SAMLConfigInput) (*SAMLConfig, error) {
	normalized, err := in.normalize()
	if err != nil {
		return nil, err
	}
	return s.Store.CreateSAMLConfig(ctx, normalized)
}

func (s *SAMLConfigService) Update(ctx context.Context, id uuid.UUID, in SAMLConfigInput) (*SAMLConfig, error) {
	normalized, err := in.normalize()
	if err != nil {
		return nil, err
	}
	return s.Store.UpdateSAMLConfig(ctx, id, normalized)
}

// Delete refuses to remove a config still referenced by auth_identities —
// see ErrSAMLConfigInUse.
func (s *SAMLConfigService) Delete(ctx context.Context, id uuid.UUID) error {
	count, err := s.Store.CountAuthIdentitiesForSAMLConfig(ctx, id)
	if err != nil {
		return err
	}
	if count > 0 {
		return ErrSAMLConfigInUse
	}
	return s.Store.DeleteSAMLConfig(ctx, id)
}
