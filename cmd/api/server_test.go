package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aiuemon/knives/internal/auth"
	"github.com/aiuemon/knives/internal/permission"
	"github.com/aiuemon/knives/internal/shorturl"
	"github.com/aiuemon/knives/internal/storage"
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
	adminUsers  map[uuid.UUID]*auth.AdminUser
	identities  map[string]*auth.AuthIdentity
	identCount  map[uuid.UUID]int
	pending     map[string]*auth.PendingLinkRequest
	audit       []auth.AuditLogEntry
}

func newFakeAuthStore() *fakeAuthStore {
	return &fakeAuthStore{
		users:       map[uuid.UUID]*auth.User{},
		usersByMail: map[string]uuid.UUID{},
		adminUsers:  map[uuid.UUID]*auth.AdminUser{},
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
	s.adminUsers[u.ID] = &auth.AdminUser{
		ID:            u.ID,
		Email:         email,
		EmailVerified: emailVerified,
		Status:        auth.UserStatusActive,
		CreatedAt:     time.Now(),
	}
	return u, nil
}

func (s *fakeAuthStore) ListUsers(_ context.Context, limit, offset int) ([]*auth.AdminUser, error) {
	result := make([]*auth.AdminUser, 0, len(s.adminUsers))
	for _, u := range s.adminUsers {
		result = append(result, u)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })
	if offset >= len(result) {
		return nil, nil
	}
	end := len(result)
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	return result[offset:end], nil
}

func (s *fakeAuthStore) FindAdminUserByID(_ context.Context, id uuid.UUID) (*auth.AdminUser, error) {
	u, ok := s.adminUsers[id]
	if !ok {
		return nil, auth.ErrNotFound
	}
	cp := *u
	return &cp, nil
}

func (s *fakeAuthStore) SetSystemAdmin(_ context.Context, id uuid.UUID, isAdmin bool) error {
	u, ok := s.adminUsers[id]
	if !ok {
		return auth.ErrNotFound
	}
	u.IsSystemAdmin = isAdmin
	return nil
}

func (s *fakeAuthStore) SetUserStatus(_ context.Context, id uuid.UUID, status auth.UserStatus) error {
	u, ok := s.adminUsers[id]
	if !ok {
		return auth.ErrNotFound
	}
	u.Status = status
	return nil
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

func (s *fakeAuthStore) FindPendingLinkRequestByID(_ context.Context, id uuid.UUID) (*auth.PendingLinkRequest, error) {
	for _, p := range s.pending {
		if p.ID == id {
			return p, nil
		}
	}
	return nil, auth.ErrNotFound
}

func (s *fakeAuthStore) FindPendingLinkRequestsForUser(_ context.Context, userID uuid.UUID) ([]*auth.PendingLinkRequest, error) {
	var result []*auth.PendingLinkRequest
	for _, p := range s.pending {
		if p.ExistingUserID == userID && p.ConfirmedAt == nil {
			result = append(result, p)
		}
	}
	return result, nil
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

func (s *fakeShortURLStore) ListForUser(_ context.Context, userID uuid.UUID, page shorturl.ListPage) ([]*shorturl.ShortURL, error) {
	var result []*shorturl.ShortURL
	for _, su := range s.byID {
		if su.CreatedBy == userID {
			cp := su
			result = append(result, &cp)
		}
	}
	return paginateShortURLs(result, page), nil
}

func (s *fakeShortURLStore) ListAll(_ context.Context, page shorturl.ListPage) ([]*shorturl.ShortURL, error) {
	var result []*shorturl.ShortURL
	for _, su := range s.byID {
		cp := su
		result = append(result, &cp)
	}
	return paginateShortURLs(result, page), nil
}

func paginateShortURLs(all []*shorturl.ShortURL, page shorturl.ListPage) []*shorturl.ShortURL {
	if page.Offset >= len(all) {
		return nil
	}
	limit := page.Limit
	if limit <= 0 {
		limit = 50
	}
	end := page.Offset + limit
	if end > len(all) {
		end = len(all)
	}
	return all[page.Offset:end]
}

func (s *fakeShortURLStore) UpdateFields(_ context.Context, id uuid.UUID, in shorturl.UpdateInput) (*shorturl.ShortURL, error) {
	su, ok := s.byID[id]
	if !ok {
		return nil, shorturl.ErrNotFound
	}
	su.LongURL = in.LongURL
	su.Title = in.Title
	su.Description = in.Description
	su.ExpiresAt = in.ExpiresAt
	s.byID[id] = su
	return &su, nil
}

func (s *fakeShortURLStore) SetStatus(_ context.Context, id uuid.UUID, status shorturl.Status) error {
	su, ok := s.byID[id]
	if !ok {
		return shorturl.ErrNotFound
	}
	su.Status = status
	s.byID[id] = su
	return nil
}

type fakePermissions struct {
	grants map[string]*permission.Grant
	admins map[uuid.UUID]bool
	emails map[uuid.UUID]string
}

func newFakePermissions() *fakePermissions {
	return &fakePermissions{
		grants: map[string]*permission.Grant{},
		admins: map[uuid.UUID]bool{},
		emails: map[uuid.UUID]string{},
	}
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

func (p *fakePermissions) ListGrants(_ context.Context, shortURLID uuid.UUID) ([]storage.GrantWithEmail, error) {
	prefix := shortURLID.String() + ":"
	result := make([]storage.GrantWithEmail, 0)
	for key, g := range p.grants {
		if len(key) < len(prefix) || key[:len(prefix)] != prefix {
			continue
		}
		result = append(result, storage.GrantWithEmail{UserID: g.UserID, Email: p.emails[g.UserID], Role: g.Role})
	}
	return result, nil
}

func (p *fakePermissions) CountOwners(_ context.Context, shortURLID uuid.UUID) (int, error) {
	prefix := shortURLID.String() + ":"
	count := 0
	for key, g := range p.grants {
		if len(key) < len(prefix) || key[:len(prefix)] != prefix {
			continue
		}
		if g.Role == permission.RoleOwner {
			count++
		}
	}
	return count, nil
}

func (p *fakePermissions) Grant(_ context.Context, shortURLID, userID uuid.UUID, role permission.Role, _ uuid.UUID) error {
	p.grants[grantKey(shortURLID, userID)] = &permission.Grant{UserID: userID, Role: role}
	return nil
}

func (p *fakePermissions) Revoke(_ context.Context, shortURLID, userID uuid.UUID) error {
	delete(p.grants, grantKey(shortURLID, userID))
	return nil
}

// fakeCacheInvalidator satisfies shortURLCacheInvalidator without a real
// Redis connection.
type fakeCacheInvalidator struct {
	invalidatedKeys []string
}

func (c *fakeCacheInvalidator) Invalidate(_ context.Context, key string) error {
	c.invalidatedKeys = append(c.invalidatedKeys, key)
	return nil
}

type fakeMailer struct {
	sentTo  string
	sentURL string
	calls   int

	reviewSentTo  string
	reviewSentURL string
	reviewCalls   int

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

func (m *fakeMailer) SendAccountLinkReviewNotice(_ context.Context, toEmail, reviewURL string) error {
	m.reviewSentTo = toEmail
	m.reviewSentURL = reviewURL
	m.reviewCalls++
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
	localAuthEnabled            bool
	selfSignupEnabled           bool
	requireConfirmation         bool
	requireReauthForAccountLink bool
}

func (f *fakeAuthSettings) FindAuthSettings(context.Context) (bool, bool, bool, bool, error) {
	return f.localAuthEnabled, f.selfSignupEnabled, f.requireConfirmation, f.requireReauthForAccountLink, nil
}

// RequireReauthForAccountLink implements auth.AuthSettingsProvider so the
// same fake can back both server.authSettings and server.resolver.AuthSettings.
func (f *fakeAuthSettings) RequireReauthForAccountLink(context.Context) (bool, error) {
	return f.requireReauthForAccountLink, nil
}

func (f *fakeAuthSettings) UpdateAuthSettings(_ context.Context, localAuthEnabled, selfSignupEnabled, requireConfirmation, requireReauthForAccountLink bool) error {
	f.localAuthEnabled = localAuthEnabled
	f.selfSignupEnabled = selfSignupEnabled
	f.requireConfirmation = requireConfirmation
	f.requireReauthForAccountLink = requireReauthForAccountLink
	return nil
}

// --- test harness --------------------------------------------------------

type testDeps struct {
	server       *server
	authStore    *fakeAuthStore
	credentials  *fakeCredentials
	sessions     *fakeSessions
	shortURLs    *fakeShortURLStore
	permissions  *fakePermissions
	cache        *fakeCacheInvalidator
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
		cache:       &fakeCacheInvalidator{},
		mailer:      &fakeMailer{},
		authSettings: &fakeAuthSettings{
			localAuthEnabled:    true,
			selfSignupEnabled:   true,
			requireConfirmation: false,
		},
		signupStore: newFakeSignupStore(),
	}
	resolver := &auth.Resolver{
		Store:           d.authStore,
		Mailer:          d.mailer,
		AuthSettings:    d.authSettings,
		ConfirmBaseURL:  "http://localhost:8080/api/auth/confirm-link",
		PendingLinksURL: "http://localhost:8080/auth/pending-links",
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
		shortURLs:         &shorturl.Service{Store: d.shortURLs},
		shortURLGet:       d.shortURLs,
		cache:             d.cache,
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

func TestHandleMe_ReportsIsSystemAdmin(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	admin, _ := d.authStore.CreateUser(ctx, "admin@example.com", true)
	d.permissions.admins[admin.ID] = true
	token, _ := d.sessions.Create(ctx, admin.ID, time.Hour)

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/auth/me", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp meResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.IsSystemAdmin {
		t.Fatalf("expected is_system_admin=true for an admin subject, got %+v", resp)
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

func TestHandleListShortURLs_RegularUserSeesOwnOnly(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	other, _ := d.authStore.CreateUser(ctx, "other@example.com", true)
	token, _ := d.sessions.Create(ctx, owner.ID, time.Hour)

	if _, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com/mine", CreatedBy: owner.ID}); err != nil {
		t.Fatalf("seed create: %v", err)
	}
	if _, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com/theirs", CreatedBy: other.ID}); err != nil {
		t.Fatalf("seed create: %v", err)
	}

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/short-urls", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp []shortURLResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 1 || resp[0].LongURL != "https://example.com/mine" {
		t.Fatalf("expected a regular user to see only their own short URL, got %+v", resp)
	}
}

func TestHandleListShortURLs_AdminSeesAllByDefault(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	admin, _ := d.authStore.CreateUser(ctx, "admin@example.com", true)
	d.permissions.admins[admin.ID] = true
	token, _ := d.sessions.Create(ctx, admin.ID, time.Hour)

	if _, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com/mine", CreatedBy: owner.ID}); err != nil {
		t.Fatalf("seed create: %v", err)
	}

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/short-urls", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	var resp []shortURLResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("expected system_admin to see every short URL by default (4.1節), got %+v", resp)
	}

	req = withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/short-urls?scope=mine", nil), token)
	rec = httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	resp = nil
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 0 {
		t.Fatalf("expected ?scope=mine to restrict an admin to their own short URLs, got %+v", resp)
	}
}

func TestHandleUpdateShortURL_EditorCanUpdateAndCacheInvalidated(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	editor, _ := d.authStore.CreateUser(ctx, "editor@example.com", true)
	token, _ := d.sessions.Create(ctx, editor.ID, time.Hour)

	created, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com/old", CreatedBy: owner.ID})
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}
	d.permissions.grants[grantKey(created.ID, editor.ID)] = &permission.Grant{UserID: editor.ID, Role: permission.RoleEditor}

	body, _ := json.Marshal(updateShortURLRequest{LongURL: "https://example.com/new"})
	req := withSessionCookie(httptest.NewRequest(http.MethodPatch, "/api/short-urls/"+created.ID.String(), bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp shortURLResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.LongURL != "https://example.com/new" {
		t.Fatalf("expected updated long_url, got %+v", resp)
	}

	wantKey := d.server.domainID.String() + ":" + created.ShortCode
	if len(d.cache.invalidatedKeys) != 1 || d.cache.invalidatedKeys[0] != wantKey {
		t.Fatalf("expected cache invalidation for key %q, got %+v", wantKey, d.cache.invalidatedKeys)
	}
}

func TestHandleUpdateShortURL_ViewerCannotUpdate(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	viewer, _ := d.authStore.CreateUser(ctx, "viewer@example.com", true)
	token, _ := d.sessions.Create(ctx, viewer.ID, time.Hour)

	created, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com/old", CreatedBy: owner.ID})
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}
	d.permissions.grants[grantKey(created.ID, viewer.ID)] = &permission.Grant{UserID: viewer.ID, Role: permission.RoleViewer}

	body, _ := json.Marshal(updateShortURLRequest{LongURL: "https://example.com/new"})
	req := withSessionCookie(httptest.NewRequest(http.MethodPatch, "/api/short-urls/"+created.ID.String(), bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for a viewer attempting to edit (4.2節: 403ではなく404), got %d", rec.Code)
	}
	if len(d.cache.invalidatedKeys) != 0 {
		t.Fatalf("a rejected update must not invalidate the cache, got %+v", d.cache.invalidatedKeys)
	}
}

func TestHandleDeleteShortURL_OwnerCanDeleteAndCacheInvalidated(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	token, _ := d.sessions.Create(ctx, owner.ID, time.Hour)

	created, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com", CreatedBy: owner.ID})
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}
	d.permissions.grants[grantKey(created.ID, owner.ID)] = &permission.Grant{UserID: owner.ID, Role: permission.RoleOwner}

	req := withSessionCookie(httptest.NewRequest(http.MethodDelete, "/api/short-urls/"+created.ID.String(), nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
	stored := d.shortURLs.byID[created.ID]
	if stored.Status != shorturl.StatusDisabled {
		t.Fatalf("expected soft-delete (status=disabled), got %+v", stored)
	}
	wantKey := d.server.domainID.String() + ":" + created.ShortCode
	if len(d.cache.invalidatedKeys) != 1 || d.cache.invalidatedKeys[0] != wantKey {
		t.Fatalf("expected cache invalidation for key %q, got %+v", wantKey, d.cache.invalidatedKeys)
	}
}

func TestHandleDeleteShortURL_EditorCannotDelete(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	editor, _ := d.authStore.CreateUser(ctx, "editor@example.com", true)
	token, _ := d.sessions.Create(ctx, editor.ID, time.Hour)

	created, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com", CreatedBy: owner.ID})
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}
	d.permissions.grants[grantKey(created.ID, editor.ID)] = &permission.Grant{UserID: editor.ID, Role: permission.RoleEditor}

	req := withSessionCookie(httptest.NewRequest(http.MethodDelete, "/api/short-urls/"+created.ID.String(), nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for an editor attempting to delete (4.2節: ownerのみ削除可), got %d", rec.Code)
	}
}

// --- URL permission handler tests ------------------------------------------

func TestHandleListURLPermissions_OwnerCanListEditorCannot(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	editor, _ := d.authStore.CreateUser(ctx, "editor@example.com", true)
	ownerToken, _ := d.sessions.Create(ctx, owner.ID, time.Hour)
	editorToken, _ := d.sessions.Create(ctx, editor.ID, time.Hour)

	created, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com", CreatedBy: owner.ID})
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}
	d.permissions.grants[grantKey(created.ID, owner.ID)] = &permission.Grant{UserID: owner.ID, Role: permission.RoleOwner}
	d.permissions.grants[grantKey(created.ID, editor.ID)] = &permission.Grant{UserID: editor.ID, Role: permission.RoleEditor}
	d.permissions.emails[owner.ID] = owner.Email
	d.permissions.emails[editor.ID] = editor.Email

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/short-urls/"+created.ID.String()+"/permissions", nil), ownerToken)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for owner, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp []urlPermissionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 2 {
		t.Fatalf("expected 2 grants (owner+editor), got %+v", resp)
	}

	req = withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/short-urls/"+created.ID.String()+"/permissions", nil), editorToken)
	rec = httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for an editor listing permissions (owner-only), got %d", rec.Code)
	}
}

func TestHandleGrantURLPermission_OwnerInvitesNewEmail(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	token, _ := d.sessions.Create(ctx, owner.ID, time.Hour)

	created, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com", CreatedBy: owner.ID})
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}
	d.permissions.grants[grantKey(created.ID, owner.ID)] = &permission.Grant{UserID: owner.ID, Role: permission.RoleOwner}

	body, _ := json.Marshal(grantURLPermissionRequest{Email: "newinvitee@example.com", Role: "editor"})
	req := withSessionCookie(httptest.NewRequest(http.MethodPost, "/api/short-urls/"+created.ID.String()+"/permissions", bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp urlPermissionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Email != "newinvitee@example.com" || resp.Role != "editor" {
		t.Fatalf("unexpected response: %+v", resp)
	}

	invitee, err := d.authStore.FindUserByEmail(ctx, "newinvitee@example.com")
	if err != nil {
		t.Fatalf("expected a placeholder user to be created for the invitee: %v", err)
	}
	grant := d.permissions.grants[grantKey(created.ID, invitee.ID)]
	if grant == nil || grant.Role != permission.RoleEditor {
		t.Fatalf("expected an editor grant for the invitee, got %+v", grant)
	}
}

func TestHandleGrantURLPermission_InvalidRoleRejected(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	token, _ := d.sessions.Create(ctx, owner.ID, time.Hour)

	created, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com", CreatedBy: owner.ID})
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}
	d.permissions.grants[grantKey(created.ID, owner.ID)] = &permission.Grant{UserID: owner.ID, Role: permission.RoleOwner}

	body, _ := json.Marshal(grantURLPermissionRequest{Email: "someone@example.com", Role: "owner"})
	req := withSessionCookie(httptest.NewRequest(http.MethodPost, "/api/short-urls/"+created.ID.String()+"/permissions", bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 rejecting an attempt to grant co-ownership via invite (4.2節), got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleRevokeURLPermission_LastOwnerCannotBeRevoked(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	token, _ := d.sessions.Create(ctx, owner.ID, time.Hour)

	created, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com", CreatedBy: owner.ID})
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}
	d.permissions.grants[grantKey(created.ID, owner.ID)] = &permission.Grant{UserID: owner.ID, Role: permission.RoleOwner}

	req := withSessionCookie(httptest.NewRequest(http.MethodDelete, "/api/short-urls/"+created.ID.String()+"/permissions/"+owner.ID.String(), nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 refusing to orphan ownership, got %d: %s", rec.Code, rec.Body.String())
	}
	if d.permissions.grants[grantKey(created.ID, owner.ID)] == nil {
		t.Fatalf("the last owner's grant must remain after a refused revoke")
	}
}

func TestHandleRevokeURLPermission_EditorCanBeRevoked(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	editor, _ := d.authStore.CreateUser(ctx, "editor@example.com", true)
	token, _ := d.sessions.Create(ctx, owner.ID, time.Hour)

	created, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com", CreatedBy: owner.ID})
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}
	d.permissions.grants[grantKey(created.ID, owner.ID)] = &permission.Grant{UserID: owner.ID, Role: permission.RoleOwner}
	d.permissions.grants[grantKey(created.ID, editor.ID)] = &permission.Grant{UserID: editor.ID, Role: permission.RoleEditor}

	req := withSessionCookie(httptest.NewRequest(http.MethodDelete, "/api/short-urls/"+created.ID.String()+"/permissions/"+editor.ID.String(), nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
	if d.permissions.grants[grantKey(created.ID, editor.ID)] != nil {
		t.Fatalf("expected the editor's grant to be removed")
	}
}

// --- admin handler tests ----------------------------------------------------

func TestRequireSystemAdmin_RejectsNonAdmin(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	user, _ := d.authStore.CreateUser(ctx, "user@example.com", true)
	token, _ := d.sessions.Create(ctx, user.ID, time.Hour)

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/admin/users", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a non-admin hitting an admin route, got %d", rec.Code)
	}
}

func TestRequireSystemAdmin_RejectsUnauthenticated(t *testing.T) {
	d := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/api/admin/users", nil)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without a session, got %d", rec.Code)
	}
}

func TestHandleGetAuthSettings_AdminCanRead(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	admin, _ := d.authStore.CreateUser(ctx, "admin@example.com", true)
	d.permissions.admins[admin.ID] = true
	token, _ := d.sessions.Create(ctx, admin.ID, time.Hour)

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/admin/auth-settings", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp authSettingsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.LocalAuthEnabled != d.authSettings.localAuthEnabled || resp.SelfSignupEnabled != d.authSettings.selfSignupEnabled {
		t.Fatalf("unexpected settings: %+v", resp)
	}
}

func TestHandlePatchAuthSettings_MergesOnlyGivenFields(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	admin, _ := d.authStore.CreateUser(ctx, "admin@example.com", true)
	d.permissions.admins[admin.ID] = true
	token, _ := d.sessions.Create(ctx, admin.ID, time.Hour)

	originalSelfSignup := d.authSettings.selfSignupEnabled
	disableLocalAuth := false
	body, _ := json.Marshal(patchAuthSettingsRequest{LocalAuthEnabled: &disableLocalAuth})
	req := withSessionCookie(httptest.NewRequest(http.MethodPatch, "/api/admin/auth-settings", bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp authSettingsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.LocalAuthEnabled != false {
		t.Fatalf("expected local_auth_enabled to be updated to false, got %+v", resp)
	}
	if resp.SelfSignupEnabled != originalSelfSignup {
		t.Fatalf("expected self_signup_enabled to stay unchanged at %v, got %v (PATCH must not clobber unset fields)", originalSelfSignup, resp.SelfSignupEnabled)
	}

	found := false
	for _, entry := range d.authStore.audit {
		if entry.Action == "admin.auth_settings_updated" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an admin.auth_settings_updated audit entry, got %+v", d.authStore.audit)
	}
}

func TestHandleListUsers_AdminSeesAllUsers(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	admin, _ := d.authStore.CreateUser(ctx, "admin@example.com", true)
	d.permissions.admins[admin.ID] = true
	token, _ := d.sessions.Create(ctx, admin.ID, time.Hour)
	if _, err := d.authStore.CreateUser(ctx, "other@example.com", true); err != nil {
		t.Fatalf("seed create: %v", err)
	}

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/admin/users", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp []adminUserResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 2 {
		t.Fatalf("expected 2 users (admin+other), got %+v", resp)
	}
}

func TestHandlePatchUser_GrantSystemAdmin(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	admin, _ := d.authStore.CreateUser(ctx, "admin@example.com", true)
	d.permissions.admins[admin.ID] = true
	token, _ := d.sessions.Create(ctx, admin.ID, time.Hour)

	target, _ := d.authStore.CreateUser(ctx, "target@example.com", true)

	grantAdmin := true
	body, _ := json.Marshal(patchUserRequest{IsSystemAdmin: &grantAdmin})
	req := withSessionCookie(httptest.NewRequest(http.MethodPatch, "/api/admin/users/"+target.ID.String(), bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp adminUserResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.IsSystemAdmin {
		t.Fatalf("expected is_system_admin=true, got %+v", resp)
	}
	if !d.authStore.adminUsers[target.ID].IsSystemAdmin {
		t.Fatalf("expected the store's admin user record to reflect the grant")
	}

	var granted bool
	for _, entry := range d.authStore.audit {
		if entry.Action == "admin.system_admin_granted" && entry.TargetID == target.ID.String() {
			granted = true
		}
	}
	if !granted {
		t.Fatalf("expected an admin.system_admin_granted audit entry, got %+v", d.authStore.audit)
	}
}

func TestHandlePatchUser_CannotRevokeOwnSystemAdmin(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	admin, _ := d.authStore.CreateUser(ctx, "admin@example.com", true)
	d.permissions.admins[admin.ID] = true
	token, _ := d.sessions.Create(ctx, admin.ID, time.Hour)

	revokeAdmin := false
	body, _ := json.Marshal(patchUserRequest{IsSystemAdmin: &revokeAdmin})
	req := withSessionCookie(httptest.NewRequest(http.MethodPatch, "/api/admin/users/"+admin.ID.String(), bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 refusing self-lockout, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandlePatchUser_CannotSuspendSelf(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	admin, _ := d.authStore.CreateUser(ctx, "admin@example.com", true)
	d.permissions.admins[admin.ID] = true
	token, _ := d.sessions.Create(ctx, admin.ID, time.Hour)

	suspended := "suspended"
	body, _ := json.Marshal(patchUserRequest{Status: &suspended})
	req := withSessionCookie(httptest.NewRequest(http.MethodPatch, "/api/admin/users/"+admin.ID.String(), bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 refusing to suspend self, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandlePatchUser_SuspendAnotherUser(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	admin, _ := d.authStore.CreateUser(ctx, "admin@example.com", true)
	d.permissions.admins[admin.ID] = true
	token, _ := d.sessions.Create(ctx, admin.ID, time.Hour)

	target, _ := d.authStore.CreateUser(ctx, "target@example.com", true)

	suspended := "suspended"
	body, _ := json.Marshal(patchUserRequest{Status: &suspended})
	req := withSessionCookie(httptest.NewRequest(http.MethodPatch, "/api/admin/users/"+target.ID.String(), bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp adminUserResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "suspended" {
		t.Fatalf("expected status=suspended, got %+v", resp)
	}
}

func TestHandlePatchUser_InvalidStatusRejected(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	admin, _ := d.authStore.CreateUser(ctx, "admin@example.com", true)
	d.permissions.admins[admin.ID] = true
	token, _ := d.sessions.Create(ctx, admin.ID, time.Hour)

	target, _ := d.authStore.CreateUser(ctx, "target@example.com", true)

	bogus := "banned"
	body, _ := json.Marshal(patchUserRequest{Status: &bogus})
	req := withSessionCookie(httptest.NewRequest(http.MethodPatch, "/api/admin/users/"+target.ID.String(), bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an invalid status value, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandlePatchUser_UnknownUserIsNotFound(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	admin, _ := d.authStore.CreateUser(ctx, "admin@example.com", true)
	d.permissions.admins[admin.ID] = true
	token, _ := d.sessions.Create(ctx, admin.ID, time.Hour)

	grantAdmin := true
	body, _ := json.Marshal(patchUserRequest{IsSystemAdmin: &grantAdmin})
	req := withSessionCookie(httptest.NewRequest(http.MethodPatch, "/api/admin/users/"+uuid.New().String(), bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for an unknown user id, got %d", rec.Code)
	}
}
