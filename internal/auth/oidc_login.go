package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

// ErrOIDCResponseInvalid covers every way an OIDC callback can fail to
// validate: IdP-reported error, discovery/token-exchange failure, bad or
// missing ID token signature, nonce mismatch, unknown/expired/
// already-consumed state, or missing required claims. Deliberately
// coarse-grained, mirroring ErrSAMLResponseInvalid, so the HTTP layer
// can't leak which specific check failed to an unauthenticated caller.
var ErrOIDCResponseInvalid = errors.New("auth: oidc response invalid")

// OIDCLoginService drives the OIDC Authorization Code + PKCE flow
// (3.3節): builds the authorization redirect, and on the way back
// exchanges the code, verifies the ID token (signature, issuer, audience,
// nonce), and hands the extracted identity to Resolver for the
// account-linking decision (3.4節-1).
type OIDCLoginService struct {
	Configs  OIDCConfigStore
	Nonces   OIDCNonceStore
	Resolver *Resolver

	// PublicBaseURL is this API server's own externally-reachable base
	// URL, used to build each IdP config's own callback URL
	// (.../auth/oidc/{id}/callback) — mirrors SAMLLoginService.PublicBaseURL.
	PublicBaseURL string

	// RequestTTL bounds how long an outstanding authorization request may
	// be completed before ConsumeState refuses it. Defaults to 10 minutes.
	RequestTTL time.Duration
}

func (s *OIDCLoginService) requestTTL() time.Duration {
	if s.RequestTTL > 0 {
		return s.RequestTTL
	}
	return 10 * time.Minute
}

func (s *OIDCLoginService) callbackURL(configID uuid.UUID) string {
	return s.PublicBaseURL + "/api/auth/oidc/" + configID.String() + "/callback"
}

func (s *OIDCLoginService) oauth2Config(cfg *OIDCConfig, provider *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  s.callbackURL(cfg.ID),
		Scopes:       cfg.Scopes,
	}
}

// BeginLogin returns the URL to redirect the browser to for the
// Authorization Code request against configID (3.3節:
// /auth/oidc/{idp_config_id}/login). Returns ErrNotFound if configID
// doesn't exist or is currently disabled — the two cases are deliberately
// indistinguishable to an unauthenticated caller, mirroring
// SAMLLoginService.BeginLogin.
func (s *OIDCLoginService) BeginLogin(ctx context.Context, configID uuid.UUID) (string, error) {
	cfg, err := s.Configs.FindOIDCConfigByID(ctx, configID)
	if err != nil {
		return "", err
	}
	if !cfg.Enabled {
		return "", ErrNotFound
	}

	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return "", fmt.Errorf("%w: discovery failed: %v", ErrOIDCResponseInvalid, err)
	}
	conf := s.oauth2Config(cfg, provider)

	state, _, err := generateToken()
	if err != nil {
		return "", err
	}
	nonce, _, err := generateToken()
	if err != nil {
		return "", err
	}
	codeVerifier := oauth2.GenerateVerifier()

	pending := OIDCPendingLogin{ConfigID: configID, Nonce: nonce, CodeVerifier: codeVerifier}
	if err := s.Nonces.CreateState(ctx, state, pending, s.requestTTL()); err != nil {
		return "", err
	}

	return conf.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(codeVerifier)), nil
}

// HandleCallback validates the callback (3.3節: トークン検証、email/
// email_verifiedクレーム取得) and resolves the resulting identity via
// Resolver (3.4節-1). Returns ErrNotFound if configID doesn't exist or is
// disabled, or ErrOIDCResponseInvalid for any validation failure.
func (s *OIDCLoginService) HandleCallback(ctx context.Context, configID uuid.UUID, r *http.Request) (*Result, error) {
	cfg, err := s.Configs.FindOIDCConfigByID(ctx, configID)
	if err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return nil, ErrNotFound
	}

	query := r.URL.Query()
	if idpErr := query.Get("error"); idpErr != "" {
		return nil, fmt.Errorf("%w: idp returned error %q", ErrOIDCResponseInvalid, idpErr)
	}
	code := query.Get("code")
	state := query.Get("state")
	if code == "" || state == "" {
		return nil, fmt.Errorf("%w: missing code or state", ErrOIDCResponseInvalid)
	}

	pending, ok, err := s.Nonces.ConsumeState(ctx, state)
	if err != nil {
		return nil, err
	}
	if !ok || pending.ConfigID != configID {
		return nil, fmt.Errorf("%w: unknown or expired login request", ErrOIDCResponseInvalid)
	}

	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: discovery failed: %v", ErrOIDCResponseInvalid, err)
	}
	conf := s.oauth2Config(cfg, provider)

	token, err := conf.Exchange(ctx, code, oauth2.VerifierOption(pending.CodeVerifier))
	if err != nil {
		return nil, fmt.Errorf("%w: token exchange failed: %v", ErrOIDCResponseInvalid, err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("%w: token response has no id_token", ErrOIDCResponseInvalid)
	}

	idToken, err := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOIDCResponseInvalid, err)
	}
	// go-oidc verifies issuer/audience/signature/expiry but deliberately
	// leaves nonce verification to the caller (see IDToken.Nonce's doc
	// comment) — this is what ties the response back to the specific
	// authorization request we issued, so it must be checked here.
	if idToken.Nonce != pending.Nonce {
		return nil, fmt.Errorf("%w: nonce mismatch", ErrOIDCResponseInvalid)
	}
	if idToken.Subject == "" {
		return nil, fmt.Errorf("%w: id_token missing sub", ErrOIDCResponseInvalid)
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOIDCResponseInvalid, err)
	}
	if claims.Email == "" {
		return nil, fmt.Errorf("%w: id_token missing email claim", ErrOIDCResponseInvalid)
	}

	// 3.4節-1: require_email_verified_claim=falseの場合、このIdPのクレームは
	// 統合の根拠として一切信用しない(常に確認メールフローへ)。
	trusted := cfg.RequireEmailVerifiedClaim && claims.EmailVerified

	return s.Resolver.Resolve(ctx, LoginAttempt{
		ProviderType:     ProviderOIDC,
		ProviderConfigID: &configID,
		Subject:          idToken.Subject,
		Email:            claims.Email,
		EmailVerified:    trusted,
		Trusted:          trusted,
	})
}
