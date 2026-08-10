package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
	"github.com/google/uuid"
)

// --- fakes ------------------------------------------------------------

type fakeOIDCNonceStore struct {
	states map[string]OIDCPendingLogin
}

func newFakeOIDCNonceStore() *fakeOIDCNonceStore {
	return &fakeOIDCNonceStore{states: map[string]OIDCPendingLogin{}}
}

func (s *fakeOIDCNonceStore) CreateState(_ context.Context, state string, pending OIDCPendingLogin, _ time.Duration) error {
	s.states[state] = pending
	return nil
}

func (s *fakeOIDCNonceStore) ConsumeState(_ context.Context, state string) (OIDCPendingLogin, bool, error) {
	pending, ok := s.states[state]
	if !ok {
		return OIDCPendingLogin{}, false, nil
	}
	delete(s.states, state)
	return pending, true, nil
}

// --- test IdP harness ------------------------------------------------------

// oidcTestIdP is a real (in-process) OIDC provider: genuine discovery
// document, genuine JWKS, genuine JWT signature verification via go-oidc —
// only the token endpoint is faked, since driving a real /authorize UI
// isn't meaningful for testing the SP side. This mirrors saml_login_test.go's
// approach of exercising the real crewjam/saml signature-verification path
// rather than mocking it.
type oidcTestIdP struct {
	server      *httptest.Server
	key         *rsa.PrivateKey
	keyID       string
	nextClaims  string
	nextIDToken string // overrides nextClaims when set (e.g. to send a garbage token)
}

func newOIDCTestIdP(t *testing.T) *oidcTestIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	idp := &oidcTestIdP{key: key, keyID: "test-key"}

	oidcSrv := &oidctest.Server{
		PublicKeys: []oidctest.PublicKey{
			{PublicKey: key.Public(), KeyID: idp.keyID, Algorithm: oidc.RS256},
		},
	}

	mux := http.NewServeMux()
	mux.Handle("/.well-known/openid-configuration", oidcSrv)
	mux.Handle("/keys", oidcSrv)
	mux.HandleFunc("/token", idp.serveToken)

	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	oidcSrv.SetIssuer(idp.server.URL)
	return idp
}

func (idp *oidcTestIdP) serveToken(w http.ResponseWriter, r *http.Request) {
	if idp.nextIDToken == "" && idp.nextClaims == "" {
		http.Error(w, "test idp: no response configured", http.StatusInternalServerError)
		return
	}
	rawIDToken := idp.nextIDToken
	if rawIDToken == "" {
		rawIDToken = oidctest.SignIDToken(idp.key, idp.keyID, oidc.RS256, idp.nextClaims)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "test-access-token",
		"token_type":   "Bearer",
		"id_token":     rawIDToken,
	})
}

// setClaims configures the next /token response's ID token, filling in
// iss/aud/exp/iat automatically. Callers add sub/nonce/email/email_verified
// etc. via extra (already-encoded JSON object body, no surrounding braces).
func (idp *oidcTestIdP) setClaims(clientID, extra string) {
	idp.nextIDToken = ""
	idp.nextClaims = `{
		"iss": "` + idp.server.URL + `",
		"aud": "` + clientID + `",
		"exp": ` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `,
		"iat": ` + strconv.FormatInt(time.Now().Unix(), 10) + `,
		` + extra + `
	}`
}

// signWithWrongKey signs a token for this IdP's issuer using a key that
// isn't the one advertised in this IdP's JWKS — used to prove signature
// verification actually rejects a mismatched key.
func (idp *oidcTestIdP) signWithWrongKey(t *testing.T, clientID, extra string) string {
	t.Helper()
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}
	claims := `{
		"iss": "` + idp.server.URL + `",
		"aud": "` + clientID + `",
		"exp": ` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `,
		"iat": ` + strconv.FormatInt(time.Now().Unix(), 10) + `,
		` + extra + `
	}`
	return oidctest.SignIDToken(wrongKey, idp.keyID, oidc.RS256, claims)
}

// --- test harness --------------------------------------------------------

type oidcTestHarness struct {
	t       *testing.T
	store   *fakeStore
	mailer  *fakeMailer
	configs *fakeOIDCConfigStore
	nonces  *fakeOIDCNonceStore
	svc     *OIDCLoginService
	idp     *oidcTestIdP
	cfg     *OIDCConfig
}

func newOIDCTestHarness(t *testing.T, requireEmailVerified bool) *oidcTestHarness {
	t.Helper()
	idp := newOIDCTestIdP(t)

	store := newFakeStore()
	mailer := &fakeMailer{}
	resolver := newTestResolver(store, mailer)

	configs := newFakeOIDCConfigStore()
	cfg, err := (&OIDCConfigService{Store: configs}).Create(context.Background(), OIDCConfigInput{
		Name:                      "Test OIDC IdP",
		Issuer:                    idp.server.URL,
		ClientID:                  "test-client",
		ClientSecret:              "test-secret",
		Scopes:                    []string{"openid", "email"},
		RequireEmailVerifiedClaim: requireEmailVerified,
		Enabled:                   true,
	})
	if err != nil {
		t.Fatalf("seed oidc config: %v", err)
	}

	nonces := newFakeOIDCNonceStore()
	svc := &OIDCLoginService{
		Configs:       configs,
		Nonces:        nonces,
		Resolver:      resolver,
		PublicBaseURL: "https://api.example.com",
	}

	return &oidcTestHarness{t: t, store: store, mailer: mailer, configs: configs, nonces: nonces, svc: svc, idp: idp, cfg: cfg}
}

// beginAndExtract drives BeginLogin and returns the state/nonce embedded
// in the resulting authorization URL, so the test can configure the fake
// IdP's next ID token to match.
func (h *oidcTestHarness) beginAndExtract(configID uuid.UUID) (state, nonce string) {
	h.t.Helper()
	redirectURL, err := h.svc.BeginLogin(context.Background(), configID)
	if err != nil {
		h.t.Fatalf("BeginLogin: %v", err)
	}
	u, err := url.Parse(redirectURL)
	if err != nil {
		h.t.Fatalf("parse redirect url: %v", err)
	}
	return u.Query().Get("state"), u.Query().Get("nonce")
}

func (h *oidcTestHarness) callback(configID uuid.UUID, state string) (*Result, error) {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/api/auth/oidc/"+configID.String()+"/callback?code=fake-code&state="+state, nil)
	return h.svc.HandleCallback(context.Background(), configID, req)
}

// --- tests -----------------------------------------------------------------

func TestOIDCLoginService_NewUserIsCreatedAndLoggedIn(t *testing.T) {
	h := newOIDCTestHarness(t, true)
	state, nonce := h.beginAndExtract(h.cfg.ID)
	h.idp.setClaims(h.cfg.ClientID, `"sub": "user-1", "nonce": "`+nonce+`", "email": "newuser@example.com", "email_verified": true`)

	result, err := h.callback(h.cfg.ID, state)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if result.Outcome != OutcomeLoggedIn {
		t.Fatalf("expected OutcomeLoggedIn, got %v", result.Outcome)
	}
	if result.User.Email != "newuser@example.com" {
		t.Fatalf("unexpected user: %+v", result.User)
	}
}

func TestOIDCLoginService_VerifiedEmailAutoLinksExistingClaimedUser(t *testing.T) {
	h := newOIDCTestHarness(t, true)
	ctx := context.Background()

	existing, err := h.store.CreateUser(ctx, "existing@example.com", true)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := h.store.CreateAuthIdentity(ctx, existing.ID, ProviderLocal, nil, existing.Email, existing.Email, true); err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	state, nonce := h.beginAndExtract(h.cfg.ID)
	h.idp.setClaims(h.cfg.ClientID, `"sub": "oidc-subject-1", "nonce": "`+nonce+`", "email": "existing@example.com", "email_verified": true`)

	result, err := h.callback(h.cfg.ID, state)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if result.Outcome != OutcomeLoggedIn {
		t.Fatalf("expected email_verified=true to auto-link, got outcome %v", result.Outcome)
	}
	if result.User.ID != existing.ID {
		t.Fatalf("expected to log in as the existing user %s, got %s", existing.ID, result.User.ID)
	}
}

func TestOIDCLoginService_UnverifiedEmailRequiresConfirmationForClaimedUser(t *testing.T) {
	h := newOIDCTestHarness(t, true)
	ctx := context.Background()

	existing, err := h.store.CreateUser(ctx, "existing@example.com", true)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := h.store.CreateAuthIdentity(ctx, existing.ID, ProviderLocal, nil, existing.Email, existing.Email, true); err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	state, nonce := h.beginAndExtract(h.cfg.ID)
	h.idp.setClaims(h.cfg.ClientID, `"sub": "oidc-subject-1", "nonce": "`+nonce+`", "email": "existing@example.com", "email_verified": false`)

	result, err := h.callback(h.cfg.ID, state)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	// なりすまし対策(3.4節1): email_verified=falseのクレームは統合の根拠に
	// できないため、確認メールフローに倒す。
	if result.Outcome != OutcomePendingConfirmation {
		t.Fatalf("expected OutcomePendingConfirmation for email_verified=false, got %v", result.Outcome)
	}
}

func TestOIDCLoginService_RequireEmailVerifiedClaimFalseNeverAutoLinks(t *testing.T) {
	h := newOIDCTestHarness(t, false) // admin turned off trust for this IdP
	ctx := context.Background()

	existing, err := h.store.CreateUser(ctx, "existing@example.com", true)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := h.store.CreateAuthIdentity(ctx, existing.ID, ProviderLocal, nil, existing.Email, existing.Email, true); err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	state, nonce := h.beginAndExtract(h.cfg.ID)
	// email_verified=trueでも、config側でrequireをOFFにしていれば信用しない。
	h.idp.setClaims(h.cfg.ClientID, `"sub": "oidc-subject-1", "nonce": "`+nonce+`", "email": "existing@example.com", "email_verified": true`)

	result, err := h.callback(h.cfg.ID, state)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if result.Outcome != OutcomePendingConfirmation {
		t.Fatalf("expected require_email_verified_claim=false to never auto-link regardless of the claim, got %v", result.Outcome)
	}
}

func TestOIDCLoginService_NonceMismatchIsRejected(t *testing.T) {
	h := newOIDCTestHarness(t, true)
	state, _ := h.beginAndExtract(h.cfg.ID)
	h.idp.setClaims(h.cfg.ClientID, `"sub": "user-1", "nonce": "wrong-nonce", "email": "a@example.com", "email_verified": true`)

	if _, err := h.callback(h.cfg.ID, state); !errors.Is(err, ErrOIDCResponseInvalid) {
		t.Fatalf("expected ErrOIDCResponseInvalid for a nonce mismatch, got %v", err)
	}
}

func TestOIDCLoginService_TamperedSignatureIsRejected(t *testing.T) {
	h := newOIDCTestHarness(t, true)
	state, nonce := h.beginAndExtract(h.cfg.ID)
	h.idp.nextIDToken = h.idp.signWithWrongKey(t, h.cfg.ClientID, `"sub": "user-1", "nonce": "`+nonce+`", "email": "a@example.com", "email_verified": true`)

	if _, err := h.callback(h.cfg.ID, state); !errors.Is(err, ErrOIDCResponseInvalid) {
		t.Fatalf("expected ErrOIDCResponseInvalid for a response signed with the wrong key, got %v", err)
	}
}

func TestOIDCLoginService_ReplayedStateIsRejected(t *testing.T) {
	h := newOIDCTestHarness(t, true)
	state, nonce := h.beginAndExtract(h.cfg.ID)
	h.idp.setClaims(h.cfg.ClientID, `"sub": "user-1", "nonce": "`+nonce+`", "email": "a@example.com", "email_verified": true`)

	if _, err := h.callback(h.cfg.ID, state); err != nil {
		t.Fatalf("first callback should succeed: %v", err)
	}
	// リプレイ・CSRF対策(3.3節): 同じstateは二度使えない。
	if _, err := h.callback(h.cfg.ID, state); !errors.Is(err, ErrOIDCResponseInvalid) {
		t.Fatalf("expected ErrOIDCResponseInvalid on replay, got %v", err)
	}
}

func TestOIDCLoginService_IdPErrorParamIsRejected(t *testing.T) {
	h := newOIDCTestHarness(t, true)
	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/api/auth/oidc/"+h.cfg.ID.String()+"/callback?error=access_denied", nil)

	if _, err := h.svc.HandleCallback(context.Background(), h.cfg.ID, req); !errors.Is(err, ErrOIDCResponseInvalid) {
		t.Fatalf("expected ErrOIDCResponseInvalid when the IdP reports an error, got %v", err)
	}
}

func TestOIDCLoginService_CallbackRejectsRequestIssuedForADifferentConfig(t *testing.T) {
	h := newOIDCTestHarness(t, true)
	ctx := context.Background()

	other, err := (&OIDCConfigService{Store: h.configs}).Create(ctx, OIDCConfigInput{
		Name: "Other IdP", Issuer: h.idp.server.URL, ClientID: "other-client", ClientSecret: "other-secret",
		Scopes: []string{"openid", "email"}, RequireEmailVerifiedClaim: true, Enabled: true,
	})
	if err != nil {
		t.Fatalf("seed second config: %v", err)
	}

	state, nonce := h.beginAndExtract(h.cfg.ID)
	h.idp.setClaims(h.cfg.ClientID, `"sub": "user-1", "nonce": "`+nonce+`", "email": "a@example.com", "email_verified": true`)

	if _, err := h.callback(other.ID, state); !errors.Is(err, ErrOIDCResponseInvalid) {
		t.Fatalf("expected ErrOIDCResponseInvalid for a state/config mismatch, got %v", err)
	}
}

func TestOIDCLoginService_DisabledConfigRejectsBeginLogin(t *testing.T) {
	h := newOIDCTestHarness(t, true)
	ctx := context.Background()

	if _, err := (&OIDCConfigService{Store: h.configs}).Update(ctx, h.cfg.ID, OIDCConfigInput{
		Name: h.cfg.Name, Issuer: h.cfg.Issuer, ClientID: h.cfg.ClientID,
		Scopes: h.cfg.Scopes, RequireEmailVerifiedClaim: h.cfg.RequireEmailVerifiedClaim, Enabled: false,
	}); err != nil {
		t.Fatalf("disable config: %v", err)
	}

	if _, err := h.svc.BeginLogin(ctx, h.cfg.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for a disabled config, got %v", err)
	}
}

func TestOIDCLoginService_UnknownConfigRejectsBeginLogin(t *testing.T) {
	h := newOIDCTestHarness(t, true)

	if _, err := h.svc.BeginLogin(context.Background(), uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for an unknown config, got %v", err)
	}
}

func TestOIDCLoginService_MissingEmailClaimIsRejected(t *testing.T) {
	h := newOIDCTestHarness(t, true)
	state, nonce := h.beginAndExtract(h.cfg.ID)
	h.idp.setClaims(h.cfg.ClientID, `"sub": "user-1", "nonce": "`+nonce+`"`)

	if _, err := h.callback(h.cfg.ID, state); !errors.Is(err, ErrOIDCResponseInvalid) {
		t.Fatalf("expected ErrOIDCResponseInvalid when the email claim is missing, got %v", err)
	}
}
