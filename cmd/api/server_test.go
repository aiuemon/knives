package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

type fakeAuthStore struct {
	users       map[uuid.UUID]*auth.User
	usersByMail map[string]uuid.UUID
	audit       []auth.AuditLogEntry
}

func newFakeAuthStore() *fakeAuthStore {
	return &fakeAuthStore{users: map[uuid.UUID]*auth.User{}, usersByMail: map[string]uuid.UUID{}}
}

func (s *fakeAuthStore) FindAuthIdentity(context.Context, auth.ProviderType, *uuid.UUID, string) (*auth.AuthIdentity, error) {
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

func (s *fakeAuthStore) CountAuthIdentitiesForUser(context.Context, uuid.UUID) (int, error) {
	return 0, nil
}

func (s *fakeAuthStore) CreateUser(_ context.Context, email string, emailVerified bool) (*auth.User, error) {
	u := &auth.User{ID: uuid.New(), Email: email, EmailVerified: emailVerified}
	s.users[u.ID] = u
	s.usersByMail[email] = u.ID
	return u, nil
}

func (s *fakeAuthStore) CreateAuthIdentity(context.Context, uuid.UUID, auth.ProviderType, *uuid.UUID, string, string, bool) (*auth.AuthIdentity, error) {
	return nil, errors.New("fakeAuthStore: CreateAuthIdentity not needed by cmd/api tests")
}

func (s *fakeAuthStore) TouchAuthIdentity(context.Context, uuid.UUID, time.Time) error { return nil }

func (s *fakeAuthStore) CreatePendingLinkRequest(context.Context, uuid.UUID, auth.ProviderType, *uuid.UUID, string, string, time.Time) (uuid.UUID, error) {
	return uuid.Nil, errors.New("fakeAuthStore: CreatePendingLinkRequest not needed by cmd/api tests")
}

func (s *fakeAuthStore) FindPendingLinkRequestByTokenHash(context.Context, string) (*auth.PendingLinkRequest, error) {
	return nil, auth.ErrNotFound
}

func (s *fakeAuthStore) ConfirmPendingLinkRequest(context.Context, uuid.UUID, time.Time) error {
	return nil
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

// --- test harness --------------------------------------------------------

type testDeps struct {
	server      *server
	authStore   *fakeAuthStore
	credentials *fakeCredentials
	sessions    *fakeSessions
	shortURLs   *fakeShortURLStore
	permissions *fakePermissions
}

func newTestServer() *testDeps {
	d := &testDeps{
		authStore:   newFakeAuthStore(),
		credentials: newFakeCredentials(),
		sessions:    newFakeSessions(),
		shortURLs:   newFakeShortURLStore(),
		permissions: newFakePermissions(),
	}
	d.server = &server{
		sessions:          d.sessions,
		authStore:         d.authStore,
		localAuth:         &auth.LocalAuthenticator{Users: d.authStore, Credentials: d.credentials},
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
