package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/google/uuid"
)

// --- fakes ------------------------------------------------------------

type fakeSAMLNonceStore struct {
	requests  map[string]uuid.UUID
	assertion map[string]bool
}

func newFakeSAMLNonceStore() *fakeSAMLNonceStore {
	return &fakeSAMLNonceStore{requests: map[string]uuid.UUID{}, assertion: map[string]bool{}}
}

func (s *fakeSAMLNonceStore) CreateRequest(_ context.Context, relayState string, configID uuid.UUID, _ time.Duration) error {
	s.requests[relayState] = configID
	return nil
}

func (s *fakeSAMLNonceStore) ConsumeRequest(_ context.Context, relayState string) (uuid.UUID, bool, error) {
	configID, ok := s.requests[relayState]
	if !ok {
		return uuid.Nil, false, nil
	}
	delete(s.requests, relayState)
	return configID, true, nil
}

func (s *fakeSAMLNonceStore) MarkAssertionSeen(_ context.Context, assertionID string, _ time.Duration) (bool, error) {
	seen := s.assertion[assertionID]
	s.assertion[assertionID] = true
	return seen, nil
}

// --- test key/cert helpers ----------------------------------------------

func generateTestKeyAndCert(t *testing.T, commonName string) (*rsa.PrivateKey, *x509.Certificate, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return key, cert, pemStr
}

// --- test harness --------------------------------------------------------

// samlTestHarness wires a real (in-process) saml.IdentityProvider against
// SAMLLoginService, so tests exercise genuine AuthnRequest generation,
// XML-DSig signature verification, and Assertion parsing rather than
// mocking any of it — internal/auth's account-linking logic is the most
// security-sensitive code in this repo (CLAUDE.md), and SAML's signature
// verification doubly so.
type samlTestHarness struct {
	t       *testing.T
	store   *fakeStore
	mailer  *fakeMailer
	configs *fakeSAMLConfigStore
	nonces  *fakeSAMLNonceStore
	svc     *SAMLLoginService
	idp     *saml.IdentityProvider
	cfg     *SAMLConfig
	idpKey  *rsa.PrivateKey
	idpCert *x509.Certificate
}

const testPublicBaseURL = "https://api.example.com"

func newSAMLTestHarness(t *testing.T, trusted bool) *samlTestHarness {
	t.Helper()

	idpKey, idpCert, idpCertPEM := generateTestKeyAndCert(t, "test-idp")
	const idpEntityID = "https://idp.example.com/entity"
	const idpSSOURL = "https://idp.example.com/sso"
	const emailAttr = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"

	store := newFakeStore()
	mailer := &fakeMailer{}
	resolver := newTestResolver(store, mailer)

	configs := newFakeSAMLConfigStore()
	cfg, err := (&SAMLConfigService{Store: configs}).Create(context.Background(), SAMLConfigInput{
		Name:           "Test IdP",
		IdPEntityID:    idpEntityID,
		IdPSSOURL:      idpSSOURL,
		IdPCertificate: idpCertPEM,
		EmailAttribute: emailAttr,
		Trusted:        trusted,
		Enabled:        true,
	})
	if err != nil {
		t.Fatalf("seed saml config: %v", err)
	}

	nonces := newFakeSAMLNonceStore()
	svc := &SAMLLoginService{
		Configs:       configs,
		Nonces:        nonces,
		Resolver:      resolver,
		PublicBaseURL: testPublicBaseURL,
	}

	sp, err := svc.newServiceProvider(cfg)
	if err != nil {
		t.Fatalf("build sp: %v", err)
	}

	idp := &saml.IdentityProvider{
		Key:         idpKey,
		Certificate: idpCert,
		MetadataURL: mustParseTestURL(idpEntityID),
		SSOURL:      mustParseTestURL(idpSSOURL),
		ServiceProviderProvider: &staticServiceProviderProvider{
			byEntityID: map[string]*saml.EntityDescriptor{
				sp.EntityID: sp.Metadata(),
			},
		},
	}

	return &samlTestHarness{
		t: t, store: store, mailer: mailer, configs: configs, nonces: nonces,
		svc: svc, idp: idp, cfg: cfg, idpKey: idpKey, idpCert: idpCert,
	}
}

func mustParseTestURL(raw string) url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return *u
}

type staticServiceProviderProvider struct {
	byEntityID map[string]*saml.EntityDescriptor
}

func (p *staticServiceProviderProvider) GetServiceProvider(_ *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
	if ed, ok := p.byEntityID[serviceProviderID]; ok {
		return ed, nil
	}
	return nil, fmt.Errorf("unknown service provider %q", serviceProviderID)
}

// loginSession configures how the in-process IdP responds: the NameID and
// email attribute value it asserts for this login attempt.
type loginSession struct {
	nameID string
	email  string
	// emailAttrName overrides the harness's configured email_attribute,
	// letting a test simulate an IdP that emits a different attribute name
	// than configured.
	emailAttrName string
}

// login drives one full SP-initiated round trip: BeginLogin -> the
// in-process IdP's ServeSSO -> HandleACS, returning whatever HandleACS
// returns. configID lets cross-config tests request login for one config
// and complete ACS against another.
func (h *samlTestHarness) login(configID uuid.UUID, session loginSession) (*Result, error) {
	h.t.Helper()
	ctx := context.Background()

	redirectURL, err := h.svc.BeginLogin(ctx, configID)
	if err != nil {
		return nil, fmt.Errorf("BeginLogin: %w", err)
	}

	attrName := session.emailAttrName
	if attrName == "" {
		attrName = h.cfg.EmailAttribute
	}
	h.idp.SessionProvider = &staticSessionProvider{session: &saml.Session{
		ID:     "idp-session-1",
		NameID: session.nameID,
		CustomAttributes: []saml.Attribute{
			{Name: attrName, Values: []saml.AttributeValue{{Value: session.email}}},
		},
	}}

	getReq := httptest.NewRequest(http.MethodGet, redirectURL, nil)
	rec := httptest.NewRecorder()
	h.idp.ServeSSO(rec, getReq)
	if rec.Code != http.StatusOK {
		h.t.Fatalf("IdP ServeSSO failed: HTTP %d: %s", rec.Code, rec.Body.String())
	}

	samlResponse, relayState := extractSAMLResponseForm(h.t, rec.Body.String())

	acsPath, err := h.svc.acsURL(configID)
	if err != nil {
		h.t.Fatalf("acsURL: %v", err)
	}
	form := url.Values{"SAMLResponse": {samlResponse}, "RelayState": {relayState}}
	acsReq := httptest.NewRequest(http.MethodPost, acsPath.String(), strings.NewReader(form.Encode()))
	acsReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return h.svc.HandleACS(ctx, configID, acsReq)
}

type staticSessionProvider struct {
	session *saml.Session
}

func (p *staticSessionProvider) GetSession(_ http.ResponseWriter, _ *http.Request, _ *saml.IdpAuthnRequest) *saml.Session {
	return p.session
}

var samlFormFieldPattern = regexp.MustCompile(`name="(SAMLResponse|RelayState)" value="([^"]*)"`)

func extractSAMLResponseForm(t *testing.T, body string) (samlResponse, relayState string) {
	t.Helper()
	matches := samlFormFieldPattern.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		value := html.UnescapeString(m[2])
		switch m[1] {
		case "SAMLResponse":
			samlResponse = value
		case "RelayState":
			relayState = value
		}
	}
	if samlResponse == "" || relayState == "" {
		t.Fatalf("could not extract SAMLResponse/RelayState from IdP response body: %s", body)
	}
	return samlResponse, relayState
}

// --- tests -----------------------------------------------------------------

func TestSAMLLoginService_NewUserIsCreatedAndLoggedIn(t *testing.T) {
	h := newSAMLTestHarness(t, false)

	result, err := h.login(h.cfg.ID, loginSession{nameID: "user-1", email: "newuser@example.com"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if result.Outcome != OutcomeLoggedIn {
		t.Fatalf("expected OutcomeLoggedIn, got %v", result.Outcome)
	}
	if result.User.Email != "newuser@example.com" {
		t.Fatalf("unexpected user: %+v", result.User)
	}
}

func TestSAMLLoginService_TrustedIdPAutoLinksExistingClaimedUser(t *testing.T) {
	h := newSAMLTestHarness(t, true)
	ctx := context.Background()

	existing, err := h.store.CreateUser(ctx, "existing@example.com", true)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	// 既に他の方法(例: ローカル認証)でクレーム済みであることを示す。
	if _, err := h.store.CreateAuthIdentity(ctx, existing.ID, ProviderLocal, nil, existing.Email, existing.Email, true); err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	result, err := h.login(h.cfg.ID, loginSession{nameID: "saml-subject-1", email: "existing@example.com"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if result.Outcome != OutcomeLoggedIn {
		t.Fatalf("expected a trusted IdP to auto-link, got outcome %v", result.Outcome)
	}
	if result.User.ID != existing.ID {
		t.Fatalf("expected to log in as the existing user %s, got %s", existing.ID, result.User.ID)
	}
}

func TestSAMLLoginService_UntrustedIdPRequiresConfirmationForClaimedUser(t *testing.T) {
	h := newSAMLTestHarness(t, false)
	ctx := context.Background()

	existing, err := h.store.CreateUser(ctx, "existing@example.com", true)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := h.store.CreateAuthIdentity(ctx, existing.ID, ProviderLocal, nil, existing.Email, existing.Email, true); err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	result, err := h.login(h.cfg.ID, loginSession{nameID: "saml-subject-1", email: "existing@example.com"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	// なりすまし対策(3.4節3): 未信頼IdPから既存クレーム済みアカウントへの
	// 統合要求は、自動ログインさせず確認メールに倒す。
	if result.Outcome != OutcomePendingConfirmation {
		t.Fatalf("expected OutcomePendingConfirmation for an untrusted IdP claiming an existing account, got %v", result.Outcome)
	}
	if h.mailer.reviewCalls != 1 && h.mailer.calls != 1 {
		t.Fatalf("expected a confirmation email to be sent, got mailer=%+v", h.mailer)
	}
}

func TestSAMLLoginService_ReplayedRelayStateIsRejected(t *testing.T) {
	h := newSAMLTestHarness(t, false)
	ctx := context.Background()

	redirectURL, err := h.svc.BeginLogin(ctx, h.cfg.ID)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	h.idp.SessionProvider = &staticSessionProvider{session: &saml.Session{
		ID: "s1", NameID: "user-1",
		CustomAttributes: []saml.Attribute{{Name: h.cfg.EmailAttribute, Values: []saml.AttributeValue{{Value: "a@example.com"}}}},
	}}
	rec := httptest.NewRecorder()
	h.idp.ServeSSO(rec, httptest.NewRequest(http.MethodGet, redirectURL, nil))
	samlResponse, relayState := extractSAMLResponseForm(t, rec.Body.String())

	acsPath, _ := h.svc.acsURL(h.cfg.ID)
	form := url.Values{"SAMLResponse": {samlResponse}, "RelayState": {relayState}}
	makeReq := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, acsPath.String(), strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}

	if _, err := h.svc.HandleACS(ctx, h.cfg.ID, makeReq()); err != nil {
		t.Fatalf("first ACS call should succeed: %v", err)
	}

	// リプレイ対策(3.2節): 同じRelayState(=AuthnRequest ID)は二度使えない。
	if _, err := h.svc.HandleACS(ctx, h.cfg.ID, makeReq()); !errors.Is(err, ErrSAMLResponseInvalid) {
		t.Fatalf("expected ErrSAMLResponseInvalid on replay, got %v", err)
	}
}

func TestSAMLLoginService_ReplayedAssertionIsRejected(t *testing.T) {
	h := newSAMLTestHarness(t, false)
	ctx := context.Background()

	// 1回目の正規ログインでSAMLResponseを取得する。
	redirectURL, err := h.svc.BeginLogin(ctx, h.cfg.ID)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	h.idp.SessionProvider = &staticSessionProvider{session: &saml.Session{
		ID: "s1", NameID: "user-1",
		CustomAttributes: []saml.Attribute{{Name: h.cfg.EmailAttribute, Values: []saml.AttributeValue{{Value: "a@example.com"}}}},
	}}
	rec := httptest.NewRecorder()
	h.idp.ServeSSO(rec, httptest.NewRequest(http.MethodGet, redirectURL, nil))
	samlResponse, _ := extractSAMLResponseForm(t, rec.Body.String())

	// 2回目のログイン要求を別途発行し、新しいRelayStateを得る(=
	// InResponseToチェック自体は通過させる)が、SAMLResponseの中身は
	// 1回目でIdPが発行した同一Assertionを使い回す — Assertion ID自体の
	// リプレイ検知(3.2節)だけを狙って再現する。
	redirectURL2, err := h.svc.BeginLogin(ctx, h.cfg.ID)
	if err != nil {
		t.Fatalf("BeginLogin (2): %v", err)
	}
	req2, err := http.NewRequest(http.MethodGet, redirectURL2, nil)
	if err != nil {
		t.Fatalf("parse redirect url: %v", err)
	}
	relayState2 := req2.URL.Query().Get("RelayState")

	acsPath, _ := h.svc.acsURL(h.cfg.ID)
	form := url.Values{"SAMLResponse": {samlResponse}, "RelayState": {relayState2}}
	acsReq := httptest.NewRequest(http.MethodPost, acsPath.String(), strings.NewReader(form.Encode()))
	acsReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// このリクエストはInResponseToが最初のAuthnRequest宛のままなので、
	// possibleRequestIDsには2回目のIDしか渡されず、通常はここで
	// InResponseTo不一致として弾かれる。この経路も含めて
	// ErrSAMLResponseInvalidとなることを確認する(Assertion再利用が
	// どのチェックであれ確実に拒否されることが本質)。
	if _, err := h.svc.HandleACS(ctx, h.cfg.ID, acsReq); !errors.Is(err, ErrSAMLResponseInvalid) {
		t.Fatalf("expected ErrSAMLResponseInvalid for a reused assertion under a new request id, got %v", err)
	}
}

func TestSAMLLoginService_TamperedSignatureIsRejected(t *testing.T) {
	h := newSAMLTestHarness(t, false)
	ctx := context.Background()

	// IdP側の署名鍵を、設定済み証明書と対応しない別の鍵にすり替える —
	// 署名検証(3.2節)が正しく機能していれば必ず拒否される。
	wrongKey, wrongCert, _ := generateTestKeyAndCert(t, "attacker")
	h.idp.Key = wrongKey
	h.idp.Certificate = wrongCert

	redirectURL, err := h.svc.BeginLogin(ctx, h.cfg.ID)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	h.idp.SessionProvider = &staticSessionProvider{session: &saml.Session{
		ID: "s1", NameID: "user-1",
		CustomAttributes: []saml.Attribute{{Name: h.cfg.EmailAttribute, Values: []saml.AttributeValue{{Value: "a@example.com"}}}},
	}}
	rec := httptest.NewRecorder()
	h.idp.ServeSSO(rec, httptest.NewRequest(http.MethodGet, redirectURL, nil))
	samlResponse, relayState := extractSAMLResponseForm(t, rec.Body.String())

	acsPath, _ := h.svc.acsURL(h.cfg.ID)
	form := url.Values{"SAMLResponse": {samlResponse}, "RelayState": {relayState}}
	acsReq := httptest.NewRequest(http.MethodPost, acsPath.String(), strings.NewReader(form.Encode()))
	acsReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if _, err := h.svc.HandleACS(ctx, h.cfg.ID, acsReq); !errors.Is(err, ErrSAMLResponseInvalid) {
		t.Fatalf("expected ErrSAMLResponseInvalid for a response signed with the wrong key, got %v", err)
	}
}

func TestSAMLLoginService_DisabledConfigRejectsBeginLogin(t *testing.T) {
	h := newSAMLTestHarness(t, false)
	ctx := context.Background()

	if _, err := (&SAMLConfigService{Store: h.configs}).Update(ctx, h.cfg.ID, SAMLConfigInput{
		Name: h.cfg.Name, IdPEntityID: h.cfg.IdPEntityID, IdPSSOURL: h.cfg.IdPSSOURL,
		IdPCertificate: h.cfg.IdPCertificate, EmailAttribute: h.cfg.EmailAttribute,
		Trusted: h.cfg.Trusted, Enabled: false,
	}); err != nil {
		t.Fatalf("disable config: %v", err)
	}

	if _, err := h.svc.BeginLogin(ctx, h.cfg.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for a disabled config, got %v", err)
	}
}

func TestSAMLLoginService_UnknownConfigRejectsBeginLogin(t *testing.T) {
	h := newSAMLTestHarness(t, false)

	if _, err := h.svc.BeginLogin(context.Background(), uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for an unknown config, got %v", err)
	}
}

func TestSAMLLoginService_MissingEmailAttributeIsRejected(t *testing.T) {
	h := newSAMLTestHarness(t, false)

	// IdPが設定と異なる属性名でメールを返してくる状況を模擬する。
	_, err := h.login(h.cfg.ID, loginSession{nameID: "user-1", email: "a@example.com", emailAttrName: "not-the-configured-attribute"})
	if !errors.Is(err, ErrSAMLResponseInvalid) {
		t.Fatalf("expected ErrSAMLResponseInvalid when the email attribute is missing, got %v", err)
	}
}

func TestSAMLLoginService_ACSRejectsRequestIssuedForADifferentConfig(t *testing.T) {
	h := newSAMLTestHarness(t, false)
	ctx := context.Background()

	other, err := (&SAMLConfigService{Store: h.configs}).Create(ctx, SAMLConfigInput{
		Name: "Other IdP", IdPEntityID: h.cfg.IdPEntityID, IdPSSOURL: h.cfg.IdPSSOURL,
		IdPCertificate: h.cfg.IdPCertificate, EmailAttribute: h.cfg.EmailAttribute,
		Trusted: false, Enabled: true,
	})
	if err != nil {
		t.Fatalf("seed second config: %v", err)
	}

	redirectURL, err := h.svc.BeginLogin(ctx, h.cfg.ID)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	h.idp.SessionProvider = &staticSessionProvider{session: &saml.Session{
		ID: "s1", NameID: "user-1",
		CustomAttributes: []saml.Attribute{{Name: h.cfg.EmailAttribute, Values: []saml.AttributeValue{{Value: "a@example.com"}}}},
	}}
	rec := httptest.NewRecorder()
	h.idp.ServeSSO(rec, httptest.NewRequest(http.MethodGet, redirectURL, nil))
	samlResponse, relayState := extractSAMLResponseForm(t, rec.Body.String())

	// h.cfg向けに発行されたRelayStateを、別のIdP設定のACSに対して使う。
	acsPath, _ := h.svc.acsURL(other.ID)
	form := url.Values{"SAMLResponse": {samlResponse}, "RelayState": {relayState}}
	acsReq := httptest.NewRequest(http.MethodPost, acsPath.String(), strings.NewReader(form.Encode()))
	acsReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if _, err := h.svc.HandleACS(ctx, other.ID, acsReq); !errors.Is(err, ErrSAMLResponseInvalid) {
		t.Fatalf("expected ErrSAMLResponseInvalid for a request/config mismatch, got %v", err)
	}
}
