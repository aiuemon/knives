package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aiuemon/knives/internal/auth"
	"github.com/aiuemon/knives/internal/permission"
	"github.com/aiuemon/knives/internal/shorturl"
)

// --- fakes -------------------------------------------------------------

type fakeSessions struct {
	byToken map[string]uuid.UUID
}

func newFakeSessions() *fakeSessions {
	return &fakeSessions{byToken: map[string]uuid.UUID{}}
}

func (f *fakeSessions) Create(_ context.Context, userID uuid.UUID, _ time.Duration) (string, error) {
	token := uuid.NewString()
	f.byToken[token] = userID
	return token, nil
}

func (f *fakeSessions) Find(_ context.Context, token string) (*auth.Session, error) {
	userID, ok := f.byToken[token]
	if !ok {
		return nil, auth.ErrSessionNotFound
	}
	return &auth.Session{UserID: userID}, nil
}

func (f *fakeSessions) Touch(_ context.Context, token string, _ time.Duration) error {
	if _, ok := f.byToken[token]; !ok {
		return auth.ErrSessionNotFound
	}
	return nil
}

func (f *fakeSessions) Delete(_ context.Context, token string) error {
	delete(f.byToken, token)
	return nil
}

func (f *fakeSessions) DeleteAllForUser(_ context.Context, userID uuid.UUID) error {
	for token, u := range f.byToken {
		if u == userID {
			delete(f.byToken, token)
		}
	}
	return nil
}

// fakeAuthStore is a full in-memory auth.Store, needed because these tests
// exercise auth.Resolver (self-signup, account-link confirmation) and not
// just the individual lookups the earlier session/short-URL tests used.
type fakeAuthStore struct {
	users       map[uuid.UUID]*auth.User
	usersByMail map[string]uuid.UUID
	identities  map[string]*auth.AuthIdentity
	identCount  map[uuid.UUID]int
	pending     map[string]*auth.PendingLinkRequest
	audit       []auth.AuditLogEntry
}

func newFakeAuthStore() *fakeAuthStore {
	return &fakeAuthStore{
		users:       map[uuid.UUID]*auth.User{},
		usersByMail: map[string]uuid.UUID{},
		identities:  map[string]*auth.AuthIdentity{},
		identCount:  map[uuid.UUID]int{},
		pending:     map[string]*auth.PendingLinkRequest{},
	}
}

func authIdentKey(pt auth.ProviderType, pcID *uuid.UUID, subject string) string {
	cfg := ""
	if pcID != nil {
		cfg = pcID.String()
	}
	return string(pt) + "|" + cfg + "|" + subject
}

func (s *fakeAuthStore) FindAuthIdentity(_ context.Context, providerType auth.ProviderType, providerConfigID *uuid.UUID, subject string) (*auth.AuthIdentity, error) {
	if id, ok := s.identities[authIdentKey(providerType, providerConfigID, subject)]; ok {
		return id, nil
	}
	return nil, auth.ErrNotFound
}

func (s *fakeAuthStore) FindUserByEmail(_ context.Context, email string) (*auth.User, error) {
	id, ok := s.usersByMail[email]
	if !ok {
		return nil, auth.ErrNotFound
	}
	return s.users[id], nil
}

func (s *fakeAuthStore) FindUserByID(_ context.Context, id uuid.UUID) (*auth.User, error) {
	u, ok := s.users[id]
	if !ok {
		return nil, auth.ErrNotFound
	}
	return u, nil
}

func (s *fakeAuthStore) CountAuthIdentitiesForUser(_ context.Context, userID uuid.UUID) (int, error) {
	return s.identCount[userID], nil
}

func (s *fakeAuthStore) CreateUser(_ context.Context, email string, emailVerified bool) (*auth.User, error) {
	u := &auth.User{ID: uuid.New(), Email: email, EmailVerified: emailVerified}
	s.users[u.ID] = u
	s.usersByMail[email] = u.ID
	return u, nil
}

func (s *fakeAuthStore) CreateAuthIdentity(_ context.Context, userID uuid.UUID, providerType auth.ProviderType, providerConfigID *uuid.UUID, subject, emailAtLink string, _ bool) (*auth.AuthIdentity, error) {
	ident := &auth.AuthIdentity{ID: uuid.New(), UserID: userID, EmailAtLink: emailAtLink}
	s.identities[authIdentKey(providerType, providerConfigID, subject)] = ident
	s.identCount[userID]++
	return ident, nil
}

func (s *fakeAuthStore) TouchAuthIdentity(context.Context, uuid.UUID, time.Time) error { return nil }

func (s *fakeAuthStore) CreatePendingLinkRequest(_ context.Context, existingUserID uuid.UUID, providerType auth.ProviderType, providerConfigID *uuid.UUID, subject, tokenHash string, expiresAt time.Time) (uuid.UUID, error) {
	id := uuid.New()
	s.pending[tokenHash] = &auth.PendingLinkRequest{
		ID:               id,
		ExistingUserID:   existingUserID,
		ProviderType:     providerType,
		ProviderConfigID: providerConfigID,
		Subject:          subject,
		ExpiresAt:        expiresAt,
	}
	return id, nil
}

func (s *fakeAuthStore) FindPendingLinkRequestByTokenHash(_ context.Context, tokenHash string) (*auth.PendingLinkRequest, error) {
	if p, ok := s.pending[tokenHash]; ok {
		return p, nil
	}
	return nil, auth.ErrNotFound
}

func (s *fakeAuthStore) ConfirmPendingLinkRequest(_ context.Context, id uuid.UUID, at time.Time) error {
	for _, p := range s.pending {
		if p.ID == id {
			t := at
			p.ConfirmedAt = &t
			return nil
		}
	}
	return auth.ErrNotFound
}

func (s *fakeAuthStore) RecordAuditLog(_ context.Context, entry auth.AuditLogEntry) error {
	s.audit = append(s.audit, entry)
	return nil
}

type fakeCredentials struct {
	byUser map[uuid.UUID]*auth.LocalCredential
}

func newFakeCredentials() *fakeCredentials {
	return &fakeCredentials{byUser: map[uuid.UUID]*auth.LocalCredential{}}
}

func (s *fakeCredentials) FindLocalCredential(_ context.Context, userID uuid.UUID) (*auth.LocalCredential, error) {
	c, ok := s.byUser[userID]
	if !ok {
		return nil, auth.ErrNotFound
	}
	copied := *c
	return &copied, nil
}

func (s *fakeCredentials) SetPassword(_ context.Context, userID uuid.UUID, passwordHash string) error {
	s.byUser[userID] = &auth.LocalCredential{UserID: userID, PasswordHash: passwordHash}
	return nil
}

func (s *fakeCredentials) RecordFailedAttempt(_ context.Context, userID uuid.UUID, failedAttempts int, lockedUntil *time.Time) error {
	c := s.byUser[userID]
	c.FailedAttempts = failedAttempts
	c.LockedUntil = lockedUntil
	return nil
}

func (s *fakeCredentials) ResetFailedAttempts(_ context.Context, userID uuid.UUID) error {
	if c, ok := s.byUser[userID]; ok {
		c.FailedAttempts = 0
		c.LockedUntil = nil
	}
	return nil
}

type fakeShortURLStore struct {
	byID    map[uuid.UUID]shorturl.ShortURL
	charset string
	length  int
}

func newFakeShortURLStore() *fakeShortURLStore {
	return &fakeShortURLStore{byID: map[uuid.UUID]shorturl.ShortURL{}, charset: "abcdefghijklmnopqrstuvwxyz0123456789", length: 7}
}

func (s *fakeShortURLStore) ShortCodeSettings(context.Context) (string, int, error) {
	return s.charset, s.length, nil
}

func (s *fakeShortURLStore) CreateShortURL(_ context.Context, in shorturl.ShortURL) (*shorturl.ShortURL, error) {
	in.ID = uuid.New()
	s.byID[in.ID] = in
	return &in, nil
}

func (s *fakeShortURLStore) FindByID(_ context.Context, id uuid.UUID) (*shorturl.ShortURL, error) {
	su, ok := s.byID[id]
	if !ok {
		return nil, shorturl.ErrNotFound
	}
	return &su, nil
}

type fakePermissions struct {
	grants map[string]*permission.Grant
	admins map[uuid.UUID]bool
}

func newFakePermissions() *fakePermissions {
	return &fakePermissions{grants: map[string]*permission.Grant{}, admins: map[uuid.UUID]bool{}}
}

func grantKey(shortURLID, userID uuid.UUID) string {
	return shortURLID.String() + ":" + userID.String()
}

func (p *fakePermissions) FindGrant(_ context.Context, shortURLID, userID uuid.UUID) (*permission.Grant, error) {
	return p.grants[grantKey(shortURLID, userID)], nil
}

func (p *fakePermissions) IsSystemAdmin(_ context.Context, userID uuid.UUID) (bool, error) {
	return p.admins[userID], nil
}

type fakeMailer struct {
	sentTo  string
	sentURL string
	calls   int

	verifySentTo  string
	verifySentURL string
	verifyCalls   int
}

func (m *fakeMailer) SendAccountLinkConfirmation(_ context.Context, toEmail, confirmURL string) error {
	m.sentTo = toEmail
	m.sentURL = confirmURL
	m.calls++
	return nil
}

func (m *fakeMailer) SendSignupVerification(_ context.Context, toEmail, verifyURL string) error {
	m.verifySentTo = toEmail
	m.verifySentURL = verifyURL
	m.verifyCalls++
	return nil
}

type fakeSignupStore struct {
	byHash map[string]*auth.SignupVerification
}

func newFakeSignupStore() *fakeSignupStore {
	return &fakeSignupStore{byHash: map[string]*auth.SignupVerification{}}
}

func (s *fakeSignupStore) CreatePendingSignup(_ context.Context, email, passwordHash, tokenHash string, expiresAt time.Time) (uuid.UUID, error) {
	id := uuid.New()
	s.byHash[tokenHash] = &auth.SignupVerification{ID: id, Email: email, PasswordHash: passwordHash, ExpiresAt: expiresAt}
	return id, nil
}

func (s *fakeSignupStore) FindPendingSignupByTokenHash(_ context.Context, tokenHash string) (*auth.SignupVerification, error) {
	v, ok := s.byHash[tokenHash]
	if !ok {
		return nil, auth.ErrNotFound
	}
	return v, nil
}

func (s *fakeSignupStore) DeletePendingSignup(_ context.Context, id uuid.UUID) error {
	for h, v := range s.byHash {
		if v.ID == id {
			delete(s.byHash, h)
		}
	}
	return nil
}

type fakeAuthSettings struct {
	localAuthEnabled    bool
	selfSignupEnabled   bool
	requireConfirmation bool
}

func (f *fakeAuthSettings) FindAuthSettings(context.Context) (bool, bool, bool, error) {
	return f.localAuthEnabled, f.selfSignupEnabled, f.requireConfirmation, nil
}

// --- test harness --------------------------------------------------------

type testDeps struct {
	server       *server
	authStore    *fakeAuthStore
	credentials  *fakeCredentials
	sessions     *fakeSessions
	shortURLs    *fakeShortURLStore
	permissions  *fakePermissions
	mailer       *fakeMailer
	authSettings *fakeAuthSettings
	signupStore  *fakeSignupStore
}

func newTestServer() *testDeps {
	d := &testDeps{
		authStore:   newFakeAuthStore(),
		credentials: newFakeCredentials(),
		sessions:    newFakeSessions(),
		shortURLs:   newFakeShortURLStore(),
		permissions: newFakePermissions(),
		mailer:      &fakeMailer{},
		authSettings: &fakeAuthSettings{
			localAuthEnabled:    true,
			selfSignupEnabled:   true,
			requireConfirmation: false,
		},
		signupStore: newFakeSignupStore(),
	}
	resolver := &auth.Resolver{
		Store:          d.authStore,
		Mailer:         d.mailer,
		ConfirmBaseURL: "http://localhost:8080/api/auth/confirm-link",
	}
	d.server = &server{
		sessions:  d.sessions,
		authStore: d.authStore,
		localAuth: &auth.LocalAuthenticator{Users: d.authStore, Credentials: d.credentials},
		resolver:  resolver,
		localSignup: &auth.LocalSignup{
			Store:         d.signupStore,
			Mailer:        d.mailer,
			Resolver:      resolver,
			Credentials:   d.credentials,
			VerifyBaseURL: "http://localhost:8080/api/auth/local/verify-email",
		},
		authSettings:      d.authSettings,
		permissions:       d.permissions,
		shortURLs:         &shorturl.Creator{Store: d.shortURLs},
		shortURLGet:       d.shortURLs,
		domainID:          uuid.New(),
		sessionCookieName: "knives_session",
		sessionTTL:        time.Hour,
		secureCookies:     false,
	}
	return d
}

func withSessionCookie(req *http.Request, token string) *http.Request {
	req.AddCookie(&http.Cookie{Name: "knives_session", Value: token})
	return req
}

// --- auth handler tests ---------------------------------------------------

func TestHandleLocalLogin_Success(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	user, err := d.authStore.CreateUser(ctx, "person@example.com", true)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := d.server.localAuth.SetPassword(ctx, user.ID, "correct horse battery staple"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	body, _ := json.Marshal(localLoginRequest{Email: "person@example.com", Password: "correct horse battery staple"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/local/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "knives_session" || cookies[0].Value == "" {
		t.Fatalf("expected a session cookie to be set, got %+v", cookies)
	}
	if _, err := d.sessions.Find(ctx, cookies[0].Value); err != nil {
		t.Fatalf("expected the issued token to resolve to a session: %v", err)
	}
}

func TestHandleLocalLogin_InvalidCredentials(t *testing.T) {
	d := newTestServer()

	body, _ := json.Marshal(localLoginRequest{Email: "nobody@example.com", Password: "whatever"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/local/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestHandleLogout_DeletesSessionAndClearsCookie(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	token, err := d.sessions.Create(ctx, uuid.New(), time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	req := withSessionCookie(httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
	if _, err := d.sessions.Find(ctx, token); err == nil {
		t.Fatalf("expected the session to be deleted")
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge >= 0 {
		t.Fatalf("expected the cookie to be cleared (MaxAge<0), got %+v", cookies)
	}
}

func TestRequireAuth_RejectsRequestsWithoutCookie(t *testing.T) {
	d := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/api/short-urls/"+uuid.New().String(), nil)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// --- short URL handler tests -----------------------------------------------

func TestHandleCreateShortURL_Success(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	user, _ := d.authStore.CreateUser(ctx, "creator@example.com", true)
	token, _ := d.sessions.Create(ctx, user.ID, time.Hour)

	body, _ := json.Marshal(createShortURLRequest{LongURL: "https://example.com/landing", CustomAlias: "my-alias"})
	req := withSessionCookie(httptest.NewRequest(http.MethodPost, "/api/short-urls", bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp shortURLResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ShortCode != "my-alias" {
		t.Fatalf("expected short_code %q, got %q", "my-alias", resp.ShortCode)
	}
	stored, ok := d.shortURLs.byID[resp.ID]
	if !ok || stored.CreatedBy != user.ID {
		t.Fatalf("expected the created short URL to record CreatedBy=%s, got %+v", user.ID, stored)
	}
}

func TestHandleCreateShortURL_InvalidLongURLIsRejected(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	user, _ := d.authStore.CreateUser(ctx, "creator@example.com", true)
	token, _ := d.sessions.Create(ctx, user.ID, time.Hour)

	body, _ := json.Marshal(createShortURLRequest{LongURL: "javascript:alert(1)"})
	req := withSessionCookie(httptest.NewRequest(http.MethodPost, "/api/short-urls", bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHandleGetShortURL_NotFoundWithoutGrant(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	created, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com", CreatedBy: owner.ID})
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}

	viewer, _ := d.authStore.CreateUser(ctx, "viewer@example.com", true)
	token, _ := d.sessions.Create(ctx, viewer.ID, time.Hour)

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/short-urls/"+created.ID.String(), nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for a user with no grant (4.2節: 403ではなく404), got %d", rec.Code)
	}
}

func TestHandleGetShortURL_OwnerCanView(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	token, _ := d.sessions.Create(ctx, owner.ID, time.Hour)

	created, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com", CreatedBy: owner.ID})
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}
	d.permissions.grants[grantKey(created.ID, owner.ID)] = &permission.Grant{UserID: owner.ID, Role: permission.RoleOwner}

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/short-urls/"+created.ID.String(), nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp shortURLResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ID != created.ID {
		t.Fatalf("expected id %s, got %s", created.ID, resp.ID)
	}
	if len(d.authStore.audit) != 0 {
		t.Fatalf("an owner viewing their own URL must not write a stats.admin_view audit entry, got %+v", d.authStore.audit)
	}
}

func TestHandleGetShortURL_AdminOverrideRecordsAudit(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	admin, _ := d.authStore.CreateUser(ctx, "admin@example.com", true)
	d.permissions.admins[admin.ID] = true
	token, _ := d.sessions.Create(ctx, admin.ID, time.Hour)

	created, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com", CreatedBy: owner.ID})
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/short-urls/"+created.ID.String(), nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (system_admin override), got %d: %s", rec.Code, rec.Body.String())
	}
	if len(d.authStore.audit) != 1 || d.authStore.audit[0].Action != "stats.admin_view" {
		t.Fatalf("expected one stats.admin_view audit entry (4.1節), got %+v", d.authStore.audit)
	}
}
