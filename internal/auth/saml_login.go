package auth

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml"
	"github.com/google/uuid"
)

var (
	// ErrSAMLResponseInvalid covers every way an incoming SAMLResponse can
	// fail to validate: bad signature, expired, wrong audience/recipient,
	// unknown/expired/already-consumed RelayState, missing NameID or the
	// configured email attribute. Deliberately coarse-grained so the HTTP
	// layer can't leak which specific check failed to an unauthenticated
	// caller.
	ErrSAMLResponseInvalid = errors.New("auth: saml response invalid")
	// ErrSAMLReplay is returned when an Assertion ID has already been
	// consumed once — a captured IdP response replayed at the ACS endpoint
	// (3.2節: リプレイ対策のためAssertion IDを記録).
	ErrSAMLReplay = errors.New("auth: saml assertion replayed")
)

// SAMLLoginService drives the SP-initiated SAML login flow (3.2節): builds
// the AuthnRequest redirect, and on the way back validates the Assertion
// (signature, audience, recipient, freshness, InResponseTo, replay) before
// handing the extracted identity to Resolver for the account-linking
// decision (3.4節).
type SAMLLoginService struct {
	Configs  SAMLConfigStore
	Nonces   SAMLNonceStore
	Resolver *Resolver

	// PublicBaseURL is this API server's own externally-reachable base URL
	// (e.g. https://api.example.com), used to build this SP's fixed
	// EntityID/MetadataURL and each IdP config's own ACS URL
	// (.../auth/saml/{id}/acs). One SP entity serves every configured IdP.
	PublicBaseURL string

	// RequestTTL bounds how long an outstanding AuthnRequest may be
	// completed before ConsumeRequest refuses it. Defaults to 10 minutes.
	RequestTTL time.Duration
	// AssertionReplayTTL bounds how long a consumed Assertion ID is
	// remembered to block replay. Defaults to 10 minutes — comfortably
	// past saml.MaxIssueDelay (90s) + saml.MaxClockSkew (180s), the
	// window during which a captured assertion could still otherwise
	// pass freshness checks.
	AssertionReplayTTL time.Duration
}

func (s *SAMLLoginService) requestTTL() time.Duration {
	if s.RequestTTL > 0 {
		return s.RequestTTL
	}
	return 10 * time.Minute
}

func (s *SAMLLoginService) assertionReplayTTL() time.Duration {
	if s.AssertionReplayTTL > 0 {
		return s.AssertionReplayTTL
	}
	return 10 * time.Minute
}

func (s *SAMLLoginService) metadataURL() (*url.URL, error) {
	return url.Parse(s.PublicBaseURL + "/api/auth/saml/metadata")
}

func (s *SAMLLoginService) acsURL(configID uuid.UUID) (*url.URL, error) {
	return url.Parse(s.PublicBaseURL + "/api/auth/saml/" + configID.String() + "/acs")
}

// newServiceProvider builds a fresh *saml.ServiceProvider for cfg. Setting
// IDPCertificate directly (rather than assembling a full IDPMetadata with
// KeyDescriptors) is deliberate: idp_saml_configs stores exactly one
// signing certificate per IdP, not a metadata document, and crewjam/saml
// supports this shortcut as long as IDPMetadata is non-nil (checked in
// (*ServiceProvider).validateSignature).
func (s *SAMLLoginService) newServiceProvider(cfg *SAMLConfig) (*saml.ServiceProvider, error) {
	metadataURL, err := s.metadataURL()
	if err != nil {
		return nil, err
	}
	acsURL, err := s.acsURL(cfg.ID)
	if err != nil {
		return nil, err
	}
	// sp.IDPCertificate must be raw base64 (no PEM armor) — it feeds
	// directly into x509.ParseCertificate via base64.StdEncoding, unlike
	// SAMLConfigInput.normalize's PEM validation.
	block, _ := pem.Decode([]byte(cfg.IdPCertificate))
	if block == nil {
		return nil, fmt.Errorf("%w: idp_certificate is not valid PEM", ErrSAMLResponseInvalid)
	}
	cert := base64.StdEncoding.EncodeToString(block.Bytes)
	return &saml.ServiceProvider{
		EntityID:       metadataURL.String(),
		MetadataURL:    *metadataURL,
		AcsURL:         *acsURL,
		IDPMetadata:    &saml.EntityDescriptor{EntityID: cfg.IdPEntityID},
		IDPCertificate: &cert,
	}, nil
}

// BeginLogin returns the URL to redirect the browser to for SP-initiated
// login against configID (3.2節: /auth/saml/{idp_config_id}/login). Returns
// ErrNotFound if configID doesn't exist or is currently disabled — the two
// cases are deliberately indistinguishable to an unauthenticated caller.
func (s *SAMLLoginService) BeginLogin(ctx context.Context, configID uuid.UUID) (string, error) {
	cfg, err := s.Configs.FindSAMLConfigByID(ctx, configID)
	if err != nil {
		return "", err
	}
	if !cfg.Enabled {
		return "", ErrNotFound
	}

	sp, err := s.newServiceProvider(cfg)
	if err != nil {
		return "", err
	}

	authnReq, err := sp.MakeAuthenticationRequest(cfg.IdPSSOURL, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return "", err
	}

	// authnReq.ID doubles as RelayState: the IdP round-trips RelayState
	// verbatim, so ACS can recover exactly which AuthnRequest ID to expect
	// in InResponseTo without needing a cookie (which HTTP-POST binding's
	// cross-site form submission would drop under SameSite=Lax/Strict) or
	// any other client-side state.
	if err := s.Nonces.CreateRequest(ctx, authnReq.ID, configID, s.requestTTL()); err != nil {
		return "", err
	}

	redirectURL, err := authnReq.Redirect(authnReq.ID, sp)
	if err != nil {
		return "", err
	}
	return redirectURL.String(), nil
}

// HandleACS validates the posted SAMLResponse (3.2節: 署名検証・Replay対策)
// and resolves the resulting identity via Resolver (3.4節). Returns
// ErrNotFound if configID doesn't exist or is disabled, ErrSAMLResponseInvalid
// for any validation failure, or ErrSAMLReplay if the Assertion ID was
// already consumed.
func (s *SAMLLoginService) HandleACS(ctx context.Context, configID uuid.UUID, r *http.Request) (*Result, error) {
	cfg, err := s.Configs.FindSAMLConfigByID(ctx, configID)
	if err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return nil, ErrNotFound
	}

	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSAMLResponseInvalid, err)
	}
	relayState := r.PostForm.Get("RelayState")
	if relayState == "" {
		return nil, fmt.Errorf("%w: missing RelayState", ErrSAMLResponseInvalid)
	}

	requestConfigID, ok, err := s.Nonces.ConsumeRequest(ctx, relayState)
	if err != nil {
		return nil, err
	}
	if !ok || requestConfigID != configID {
		return nil, fmt.Errorf("%w: unknown or expired login request", ErrSAMLResponseInvalid)
	}

	sp, err := s.newServiceProvider(cfg)
	if err != nil {
		return nil, err
	}

	assertion, err := sp.ParseResponse(r, []string{relayState})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSAMLResponseInvalid, err)
	}

	alreadySeen, err := s.Nonces.MarkAssertionSeen(ctx, assertion.ID, s.assertionReplayTTL())
	if err != nil {
		return nil, err
	}
	if alreadySeen {
		return nil, ErrSAMLReplay
	}

	if assertion.Subject == nil || assertion.Subject.NameID == nil || assertion.Subject.NameID.Value == "" {
		return nil, fmt.Errorf("%w: assertion has no NameID", ErrSAMLResponseInvalid)
	}
	email := extractSAMLAttribute(assertion, cfg.EmailAttribute)
	if email == "" {
		return nil, fmt.Errorf("%w: assertion is missing the %q attribute", ErrSAMLResponseInvalid, cfg.EmailAttribute)
	}

	return s.Resolver.Resolve(ctx, LoginAttempt{
		ProviderType:     ProviderSAML,
		ProviderConfigID: &configID,
		Subject:          assertion.Subject.NameID.Value,
		Email:            email,
		// SAML has no standard verified-email claim (3.4節-2); Trusted
		// (an admin-set property of the whole IdP config) is the closest
		// substitute, so it seeds EmailVerified for brand-new users too.
		EmailVerified: cfg.Trusted,
		Trusted:       cfg.Trusted,
	})
}

// extractSAMLAttribute returns the first value of the attribute matching
// name, checked against both Name (the usual URN/OID form) and
// FriendlyName (the human-readable form), since IdP admins configuring
// email_attribute may reasonably supply either.
func extractSAMLAttribute(assertion *saml.Assertion, name string) string {
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			if (attr.Name == name || attr.FriendlyName == name) && len(attr.Values) > 0 {
				return attr.Values[0].Value
			}
		}
	}
	return ""
}
