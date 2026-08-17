package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/aiuemon/knives/internal/auth"
	"github.com/aiuemon/knives/internal/permission"
	"github.com/aiuemon/knives/internal/shorturl"
	"github.com/aiuemon/knives/internal/stats"
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
	byID          map[uuid.UUID]shorturl.ShortURL
	charset       string
	length        int
	creatorEmails map[uuid.UUID]string
	clickCounts   map[uuid.UUID]int64
}

func newFakeShortURLStore() *fakeShortURLStore {
	return &fakeShortURLStore{
		byID:          map[uuid.UUID]shorturl.ShortURL{},
		charset:       "abcdefghijklmnopqrstuvwxyz0123456789",
		length:        7,
		creatorEmails: map[uuid.UUID]string{},
		clickCounts:   map[uuid.UUID]int64{},
	}
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

func (s *fakeShortURLStore) ListForUser(_ context.Context, userID uuid.UUID, page shorturl.ListPage) ([]*shorturl.ListItem, int, error) {
	var result []*shorturl.ListItem
	for _, su := range s.byID {
		if su.CreatedBy == userID {
			result = append(result, s.toListItem(su))
		}
	}
	return s.filterSortPaginate(result, page)
}

func (s *fakeShortURLStore) ListAll(_ context.Context, page shorturl.ListPage) ([]*shorturl.ListItem, int, error) {
	var result []*shorturl.ListItem
	for _, su := range s.byID {
		result = append(result, s.toListItem(su))
	}
	return s.filterSortPaginate(result, page)
}

func (s *fakeShortURLStore) toListItem(su shorturl.ShortURL) *shorturl.ListItem {
	return &shorturl.ListItem{
		ShortURL:     su,
		CreatorEmail: s.creatorEmails[su.CreatedBy],
		ClickCount:   s.clickCounts[su.ID],
	}
}

func (s *fakeShortURLStore) filterSortPaginate(all []*shorturl.ListItem, page shorturl.ListPage) ([]*shorturl.ListItem, int, error) {
	filter := strings.ToLower(strings.TrimSpace(page.Filter))
	if filter != "" {
		filtered := all[:0]
		for _, item := range all {
			haystack := strings.ToLower(item.ShortCode + " " + item.LongURL + " " + item.Title + " " + item.CreatorEmail)
			if strings.Contains(haystack, filter) {
				filtered = append(filtered, item)
			}
		}
		all = filtered
	}

	sortBy := page.SortBy
	if sortBy == "" {
		sortBy = shorturl.SortByCreatedAt
	}
	compare := func(a, b *shorturl.ListItem) int {
		switch sortBy {
		case shorturl.SortByShortCode:
			return strings.Compare(a.ShortCode, b.ShortCode)
		case shorturl.SortByLongURL:
			return strings.Compare(a.LongURL, b.LongURL)
		case shorturl.SortByTitle:
			return strings.Compare(a.Title, b.Title)
		case shorturl.SortByClickCount:
			switch {
			case a.ClickCount < b.ClickCount:
				return -1
			case a.ClickCount > b.ClickCount:
				return 1
			default:
				return 0
			}
		case shorturl.SortByCreatorEmail:
			return strings.Compare(a.CreatorEmail, b.CreatorEmail)
		default:
			switch {
			case a.CreatedAt.Before(b.CreatedAt):
				return -1
			case a.CreatedAt.After(b.CreatedAt):
				return 1
			default:
				return 0
			}
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		c := compare(all[i], all[j])
		if page.SortDir == shorturl.SortDesc {
			return c > 0
		}
		return c < 0
	})

	total := len(all)
	limit := page.Limit
	if limit <= 0 {
		limit = 50
	}
	if page.Offset >= len(all) {
		return nil, total, nil
	}
	end := page.Offset + limit
	if end > len(all) {
		end = len(all)
	}
	return all[page.Offset:end], total, nil
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

type fakeStatsReader struct {
	daily      map[uuid.UUID][]stats.DailyCount
	hourly     map[uuid.UUID][]stats.HourlyCount
	referrers  map[uuid.UUID][]stats.ReferrerCount
	calledWith struct {
		shortURLID uuid.UUID
		from, to   time.Time
	}
}

func newFakeStatsReader() *fakeStatsReader {
	return &fakeStatsReader{
		daily:     map[uuid.UUID][]stats.DailyCount{},
		hourly:    map[uuid.UUID][]stats.HourlyCount{},
		referrers: map[uuid.UUID][]stats.ReferrerCount{},
	}
}

func (r *fakeStatsReader) DailyCounts(_ context.Context, shortURLID uuid.UUID, from, to time.Time) ([]stats.DailyCount, error) {
	r.calledWith.shortURLID = shortURLID
	r.calledWith.from = from
	r.calledWith.to = to
	return r.daily[shortURLID], nil
}

func (r *fakeStatsReader) HourlyCounts(_ context.Context, shortURLID uuid.UUID, from, to time.Time) ([]stats.HourlyCount, error) {
	r.calledWith.shortURLID = shortURLID
	r.calledWith.from = from
	r.calledWith.to = to
	return r.hourly[shortURLID], nil
}

func (r *fakeStatsReader) ReferrerCounts(_ context.Context, shortURLID uuid.UUID, _, _ time.Time) ([]stats.ReferrerCount, error) {
	return r.referrers[shortURLID], nil
}

type fakeWebAuthnCredentialStore struct {
	byUser map[uuid.UUID][]auth.WebAuthnCredential
}

func newFakeWebAuthnCredentialStore() *fakeWebAuthnCredentialStore {
	return &fakeWebAuthnCredentialStore{byUser: map[uuid.UUID][]auth.WebAuthnCredential{}}
}

func (s *fakeWebAuthnCredentialStore) FindWebAuthnCredentialsByUserID(_ context.Context, userID uuid.UUID) ([]auth.WebAuthnCredential, error) {
	return s.byUser[userID], nil
}

func (s *fakeWebAuthnCredentialStore) CreateWebAuthnCredential(_ context.Context, cred auth.WebAuthnCredential) error {
	s.byUser[cred.UserID] = append(s.byUser[cred.UserID], cred)
	return nil
}

func (s *fakeWebAuthnCredentialStore) UpdateWebAuthnCredentialSignCount(_ context.Context, _ []byte, _ uint32, _ bool) error {
	return nil
}

func (s *fakeWebAuthnCredentialStore) UpdateWebAuthnCredentialName(_ context.Context, id, userID uuid.UUID, name string) (*auth.WebAuthnCredential, error) {
	creds := s.byUser[userID]
	for i, c := range creds {
		if c.ID == id {
			creds[i].Name = name
			return &creds[i], nil
		}
	}
	return nil, auth.ErrNotFound
}

func (s *fakeWebAuthnCredentialStore) DeleteWebAuthnCredential(_ context.Context, id, userID uuid.UUID) error {
	creds := s.byUser[userID]
	for i, c := range creds {
		if c.ID == id {
			s.byUser[userID] = append(creds[:i], creds[i+1:]...)
			return nil
		}
	}
	return auth.ErrNotFound
}

type fakeWebAuthnSessionStore struct {
	data map[string][]byte
}

func newFakeWebAuthnSessionStore() *fakeWebAuthnSessionStore {
	return &fakeWebAuthnSessionStore{data: map[string][]byte{}}
}

func (s *fakeWebAuthnSessionStore) Create(_ context.Context, ceremonyID string, data []byte, _ time.Duration) error {
	s.data[ceremonyID] = data
	return nil
}

func (s *fakeWebAuthnSessionStore) Consume(_ context.Context, ceremonyID string) ([]byte, bool, error) {
	data, ok := s.data[ceremonyID]
	if !ok {
		return nil, false, nil
	}
	delete(s.data, ceremonyID)
	return data, true, nil
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

type fakeSAMLConfigStore struct {
	configs    map[uuid.UUID]*auth.SAMLConfig
	identCount map[uuid.UUID]int
}

func newFakeSAMLConfigStore() *fakeSAMLConfigStore {
	return &fakeSAMLConfigStore{configs: map[uuid.UUID]*auth.SAMLConfig{}, identCount: map[uuid.UUID]int{}}
}

func (s *fakeSAMLConfigStore) ListSAMLConfigs(context.Context) ([]*auth.SAMLConfig, error) {
	result := make([]*auth.SAMLConfig, 0, len(s.configs))
	for _, c := range s.configs {
		result = append(result, c)
	}
	return result, nil
}

func (s *fakeSAMLConfigStore) FindSAMLConfigByID(_ context.Context, id uuid.UUID) (*auth.SAMLConfig, error) {
	c, ok := s.configs[id]
	if !ok {
		return nil, auth.ErrNotFound
	}
	return c, nil
}

func (s *fakeSAMLConfigStore) CreateSAMLConfig(_ context.Context, in auth.SAMLConfigInput) (*auth.SAMLConfig, error) {
	c := &auth.SAMLConfig{
		ID: uuid.New(), Name: in.Name, IdPEntityID: in.IdPEntityID, IdPSSOURL: in.IdPSSOURL,
		IdPCertificate: in.IdPCertificate, EmailAttribute: in.EmailAttribute, Trusted: in.Trusted, Enabled: in.Enabled,
	}
	s.configs[c.ID] = c
	return c, nil
}

func (s *fakeSAMLConfigStore) UpdateSAMLConfig(_ context.Context, id uuid.UUID, in auth.SAMLConfigInput) (*auth.SAMLConfig, error) {
	if _, ok := s.configs[id]; !ok {
		return nil, auth.ErrNotFound
	}
	c := &auth.SAMLConfig{
		ID: id, Name: in.Name, IdPEntityID: in.IdPEntityID, IdPSSOURL: in.IdPSSOURL,
		IdPCertificate: in.IdPCertificate, EmailAttribute: in.EmailAttribute, Trusted: in.Trusted, Enabled: in.Enabled,
	}
	s.configs[id] = c
	return c, nil
}

func (s *fakeSAMLConfigStore) DeleteSAMLConfig(_ context.Context, id uuid.UUID) error {
	if _, ok := s.configs[id]; !ok {
		return auth.ErrNotFound
	}
	delete(s.configs, id)
	return nil
}

func (s *fakeSAMLConfigStore) CountAuthIdentitiesForSAMLConfig(_ context.Context, id uuid.UUID) (int, error) {
	return s.identCount[id], nil
}

type fakeOIDCConfigStore struct {
	configs    map[uuid.UUID]*auth.OIDCConfig
	identCount map[uuid.UUID]int
}

func newFakeOIDCConfigStore() *fakeOIDCConfigStore {
	return &fakeOIDCConfigStore{configs: map[uuid.UUID]*auth.OIDCConfig{}, identCount: map[uuid.UUID]int{}}
}

func (s *fakeOIDCConfigStore) ListOIDCConfigs(context.Context) ([]*auth.OIDCConfig, error) {
	result := make([]*auth.OIDCConfig, 0, len(s.configs))
	for _, c := range s.configs {
		result = append(result, c)
	}
	return result, nil
}

func (s *fakeOIDCConfigStore) FindOIDCConfigByID(_ context.Context, id uuid.UUID) (*auth.OIDCConfig, error) {
	c, ok := s.configs[id]
	if !ok {
		return nil, auth.ErrNotFound
	}
	return c, nil
}

func (s *fakeOIDCConfigStore) CreateOIDCConfig(_ context.Context, in auth.OIDCConfigInput) (*auth.OIDCConfig, error) {
	c := &auth.OIDCConfig{
		ID: uuid.New(), Name: in.Name, Issuer: in.Issuer, ClientID: in.ClientID,
		ClientSecret: in.ClientSecret, Scopes: in.Scopes,
		RequireEmailVerifiedClaim: in.RequireEmailVerifiedClaim, Enabled: in.Enabled,
	}
	s.configs[c.ID] = c
	return c, nil
}

func (s *fakeOIDCConfigStore) UpdateOIDCConfig(_ context.Context, id uuid.UUID, in auth.OIDCConfigInput) (*auth.OIDCConfig, error) {
	existing, ok := s.configs[id]
	if !ok {
		return nil, auth.ErrNotFound
	}
	secret := existing.ClientSecret
	if in.ClientSecret != "" {
		secret = in.ClientSecret
	}
	c := &auth.OIDCConfig{
		ID: id, Name: in.Name, Issuer: in.Issuer, ClientID: in.ClientID,
		ClientSecret: secret, Scopes: in.Scopes,
		RequireEmailVerifiedClaim: in.RequireEmailVerifiedClaim, Enabled: in.Enabled,
	}
	s.configs[id] = c
	return c, nil
}

func (s *fakeOIDCConfigStore) DeleteOIDCConfig(_ context.Context, id uuid.UUID) error {
	if _, ok := s.configs[id]; !ok {
		return auth.ErrNotFound
	}
	delete(s.configs, id)
	return nil
}

func (s *fakeOIDCConfigStore) CountAuthIdentitiesForOIDCConfig(_ context.Context, id uuid.UUID) (int, error) {
	return s.identCount[id], nil
}

// --- test harness --------------------------------------------------------

// fakeSAMLLoginService lets handler tests drive handleSAMLLoginRedirect /
// handleSAMLACS without a real crewjam/saml round trip — that protocol
// logic is tested thoroughly in internal/auth itself.
type fakeSAMLLoginService struct {
	beginLoginFunc func(ctx context.Context, configID uuid.UUID) (string, error)
	handleACSFunc  func(ctx context.Context, configID uuid.UUID, r *http.Request) (*auth.Result, error)
}

func (f *fakeSAMLLoginService) BeginLogin(ctx context.Context, configID uuid.UUID) (string, error) {
	return f.beginLoginFunc(ctx, configID)
}

func (f *fakeSAMLLoginService) HandleACS(ctx context.Context, configID uuid.UUID, r *http.Request) (*auth.Result, error) {
	return f.handleACSFunc(ctx, configID, r)
}

type fakeOIDCLoginService struct {
	beginLoginFunc     func(ctx context.Context, configID uuid.UUID) (string, error)
	handleCallbackFunc func(ctx context.Context, configID uuid.UUID, r *http.Request) (*auth.Result, error)
}

func (f *fakeOIDCLoginService) BeginLogin(ctx context.Context, configID uuid.UUID) (string, error) {
	return f.beginLoginFunc(ctx, configID)
}

func (f *fakeOIDCLoginService) HandleCallback(ctx context.Context, configID uuid.UUID, r *http.Request) (*auth.Result, error) {
	return f.handleCallbackFunc(ctx, configID, r)
}

// fakeWebAuthnAuthenticator lets handler tests drive the
// FinishRegistration/FinishLogin *success* path — something a real
// *auth.WebAuthnService can't do in a unit test without an actual FIDO2
// authenticator ceremony (see internal/auth/webauthn_test.go's scope
// note). Unset funcs panic on call, same convention as the other fakes.
type fakeWebAuthnAuthenticator struct {
	beginRegistrationFunc  func(ctx context.Context, userID uuid.UUID) (*protocol.CredentialCreation, string, error)
	finishRegistrationFunc func(ctx context.Context, userID uuid.UUID, ceremonyID, name string, r *http.Request) error
	beginLoginFunc         func(ctx context.Context) (*protocol.CredentialAssertion, string, error)
	finishLoginFunc        func(ctx context.Context, ceremonyID string, r *http.Request) (*auth.User, error)
}

func (f *fakeWebAuthnAuthenticator) BeginRegistration(ctx context.Context, userID uuid.UUID) (*protocol.CredentialCreation, string, error) {
	return f.beginRegistrationFunc(ctx, userID)
}

func (f *fakeWebAuthnAuthenticator) FinishRegistration(ctx context.Context, userID uuid.UUID, ceremonyID, name string, r *http.Request) error {
	return f.finishRegistrationFunc(ctx, userID, ceremonyID, name, r)
}

func (f *fakeWebAuthnAuthenticator) BeginLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	return f.beginLoginFunc(ctx)
}

func (f *fakeWebAuthnAuthenticator) FinishLogin(ctx context.Context, ceremonyID string, r *http.Request) (*auth.User, error) {
	return f.finishLoginFunc(ctx, ceremonyID, r)
}

type testDeps struct {
	server              *server
	authStore           *fakeAuthStore
	credentials         *fakeCredentials
	sessions            *fakeSessions
	shortURLs           *fakeShortURLStore
	statsReader         *fakeStatsReader
	webauthnCredentials *fakeWebAuthnCredentialStore
	webauthnSessions    *fakeWebAuthnSessionStore
	permissions         *fakePermissions
	cache               *fakeCacheInvalidator
	mailer              *fakeMailer
	authSettings        *fakeAuthSettings
	signupStore         *fakeSignupStore
	samlConfigs         *fakeSAMLConfigStore
	samlLogin           *fakeSAMLLoginService
	oidcConfigs         *fakeOIDCConfigStore
	oidcLogin           *fakeOIDCLoginService
}

func newTestServer() *testDeps {
	d := &testDeps{
		authStore:           newFakeAuthStore(),
		credentials:         newFakeCredentials(),
		sessions:            newFakeSessions(),
		shortURLs:           newFakeShortURLStore(),
		statsReader:         newFakeStatsReader(),
		webauthnCredentials: newFakeWebAuthnCredentialStore(),
		webauthnSessions:    newFakeWebAuthnSessionStore(),
		permissions:         newFakePermissions(),
		cache:               &fakeCacheInvalidator{},
		mailer:              &fakeMailer{},
		authSettings: &fakeAuthSettings{
			localAuthEnabled:    true,
			selfSignupEnabled:   true,
			requireConfirmation: false,
		},
		signupStore: newFakeSignupStore(),
		samlConfigs: newFakeSAMLConfigStore(),
		samlLogin: &fakeSAMLLoginService{
			beginLoginFunc: func(context.Context, uuid.UUID) (string, error) {
				return "https://idp.example.com/sso?SAMLRequest=stub", nil
			},
			handleACSFunc: func(context.Context, uuid.UUID, *http.Request) (*auth.Result, error) {
				return &auth.Result{Outcome: auth.OutcomeLoggedIn, User: &auth.User{ID: uuid.New(), Email: "saml-user@example.com"}}, nil
			},
		},
		oidcConfigs: newFakeOIDCConfigStore(),
		oidcLogin: &fakeOIDCLoginService{
			beginLoginFunc: func(context.Context, uuid.UUID) (string, error) {
				return "https://idp.example.com/auth?client_id=stub", nil
			},
			handleCallbackFunc: func(context.Context, uuid.UUID, *http.Request) (*auth.Result, error) {
				return &auth.Result{Outcome: auth.OutcomeLoggedIn, User: &auth.User{ID: uuid.New(), Email: "oidc-user@example.com"}}, nil
			},
		},
	}
	resolver := &auth.Resolver{
		Store:           d.authStore,
		Mailer:          d.mailer,
		AuthSettings:    d.authSettings,
		ConfirmBaseURL:  "http://localhost:8080/api/auth/confirm-link",
		PendingLinksURL: "http://localhost:8080/auth/pending-links",
	}
	testWebAuthn, err := webauthn.New(&webauthn.Config{
		RPID:          "localhost",
		RPDisplayName: "knives-test",
		RPOrigins:     []string{"http://localhost:5173"},
	})
	if err != nil {
		panic(err)
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
		authSettings: d.authSettings,
		permissions:  d.permissions,
		shortURLs:    &shorturl.Service{Store: d.shortURLs},
		shortURLGet:  d.shortURLs,
		stats:        &stats.Service{Reader: d.statsReader},
		cache:        d.cache,
		samlConfigs:  &auth.SAMLConfigService{Store: d.samlConfigs},
		samlLogin:    d.samlLogin,
		oidcConfigs:  &auth.OIDCConfigService{Store: d.oidcConfigs},
		oidcLogin:    d.oidcLogin,
		webauthn: &auth.WebAuthnService{
			WebAuthn:    testWebAuthn,
			Users:       d.authStore,
			Credentials: d.webauthnCredentials,
			Sessions:    d.webauthnSessions,
		},
		webauthnCredentials: d.webauthnCredentials,
		domainID:            uuid.New(),
		sessionCookieName:   "knives_session",
		sessionTTL:          time.Hour,
		secureCookies:       false,
		webPublicBaseURL:    "http://localhost:5173",
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

func TestHandleWebAuthnRegisterBegin_RequiresAuth(t *testing.T) {
	d := newTestServer()

	req := httptest.NewRequest(http.MethodPost, "/api/auth/webauthn/register/begin", nil)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestHandleWebAuthnRegisterBegin_ReturnsCeremonyScopedToTheCaller(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	user, _ := d.authStore.CreateUser(ctx, "user@example.com", true)
	token, _ := d.sessions.Create(ctx, user.ID, time.Hour)

	req := withSessionCookie(httptest.NewRequest(http.MethodPost, "/api/auth/webauthn/register/begin", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp webauthnCeremonyResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.CeremonyID == "" {
		t.Fatalf("expected a non-empty ceremony_id")
	}
	if len(d.webauthnSessions.data) != 1 {
		t.Fatalf("expected exactly one stored ceremony, got %d", len(d.webauthnSessions.data))
	}
}

func TestHandleWebAuthnRegisterFinish_MissingCeremonyIDReturns400(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	user, _ := d.authStore.CreateUser(ctx, "user@example.com", true)
	token, _ := d.sessions.Create(ctx, user.ID, time.Hour)

	req := withSessionCookie(httptest.NewRequest(http.MethodPost, "/api/auth/webauthn/register/finish", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a missing ceremony_id, got %d", rec.Code)
	}
}

func TestHandleWebAuthnRegisterFinish_UnknownCeremonyReturns400(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	user, _ := d.authStore.CreateUser(ctx, "user@example.com", true)
	token, _ := d.sessions.Create(ctx, user.ID, time.Hour)

	req := withSessionCookie(httptest.NewRequest(http.MethodPost, "/api/auth/webauthn/register/finish?ceremony_id=never-issued", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an unknown/expired ceremony, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleWebAuthnRegisterFinish_SuccessReturnsADecodableBody guards
// against a real bug found via manual browser testing: the handler wrote
// a bare 201 with no body, but web/src/api/client.ts's request() calls
// res.json() for every non-204 response — so a successful registration
// (the credential really was created) still surfaced to the user as
// "パスキーの登録に失敗しました", because the empty body failed to parse
// as JSON on the client. Every other 201 response in this codebase
// includes a JSON body (see e.g. handleCreateShortURL); this one didn't.
func TestHandleWebAuthnRegisterFinish_SuccessReturnsADecodableBody(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	user, _ := d.authStore.CreateUser(ctx, "user@example.com", true)
	token, _ := d.sessions.Create(ctx, user.ID, time.Hour)

	d.server.webauthn = &fakeWebAuthnAuthenticator{
		finishRegistrationFunc: func(context.Context, uuid.UUID, string, string, *http.Request) error {
			return nil
		},
	}

	req := withSessionCookie(httptest.NewRequest(http.MethodPost, "/api/auth/webauthn/register/finish?ceremony_id=some-ceremony", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() == 0 {
		t.Fatalf("expected a non-empty JSON body (client always calls res.json() on non-204 responses), got an empty body")
	}
	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("expected the body to be valid JSON, got decode error: %v", err)
	}
}

func TestHandleWebAuthnRegisterFinish_PassesTheNameQueryParamThrough(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	user, _ := d.authStore.CreateUser(ctx, "user@example.com", true)
	token, _ := d.sessions.Create(ctx, user.ID, time.Hour)

	var gotName string
	d.server.webauthn = &fakeWebAuthnAuthenticator{
		finishRegistrationFunc: func(_ context.Context, _ uuid.UUID, _ string, name string, _ *http.Request) error {
			gotName = name
			return nil
		},
	}

	req := withSessionCookie(httptest.NewRequest(http.MethodPost, "/api/auth/webauthn/register/finish?ceremony_id=some-ceremony&name="+url.QueryEscape("会社支給MacBook"), nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if gotName != "会社支給MacBook" {
		t.Fatalf("expected the name query param to reach FinishRegistration, got %q", gotName)
	}
}

func TestHandleWebAuthnRegisterFinish_OverlyLongNameReturns400(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	user, _ := d.authStore.CreateUser(ctx, "user@example.com", true)
	token, _ := d.sessions.Create(ctx, user.ID, time.Hour)

	tooLong := url.QueryEscape(strings.Repeat("a", 101))
	req := withSessionCookie(httptest.NewRequest(http.MethodPost, "/api/auth/webauthn/register/finish?ceremony_id=some-ceremony&name="+tooLong, nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a name over the length limit, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleListWebAuthnCredentials_IncludesNameAndTimestamps(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	user, _ := d.authStore.CreateUser(ctx, "user@example.com", true)
	token, _ := d.sessions.Create(ctx, user.ID, time.Hour)

	createdAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	lastUsedAt := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	d.webauthnCredentials.byUser[user.ID] = []auth.WebAuthnCredential{
		{ID: uuid.New(), UserID: user.ID, Name: "会社支給MacBook", CreatedAt: createdAt, LastUsedAt: &lastUsedAt},
	}

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/auth/webauthn/credentials", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp []webauthnCredentialResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 1 || resp[0].Name != "会社支給MacBook" || !resp[0].CreatedAt.Equal(createdAt) || resp[0].LastUsedAt == nil || !resp[0].LastUsedAt.Equal(lastUsedAt) {
		t.Fatalf("expected name/created_at/last_used_at to be included, got %+v", resp)
	}
}

func TestHandleListWebAuthnCredentials_NeverUsedHasNilLastUsedAt(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	user, _ := d.authStore.CreateUser(ctx, "user@example.com", true)
	token, _ := d.sessions.Create(ctx, user.ID, time.Hour)

	d.webauthnCredentials.byUser[user.ID] = []auth.WebAuthnCredential{
		{ID: uuid.New(), UserID: user.ID, CreatedAt: time.Now()},
	}

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/auth/webauthn/credentials", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	var resp []webauthnCredentialResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 1 || resp[0].LastUsedAt != nil {
		t.Fatalf("expected a never-used credential to have a nil last_used_at, got %+v", resp)
	}
}

func TestHandleUpdateWebAuthnCredentialName_RenamesTheCallersOwnCredential(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	user, _ := d.authStore.CreateUser(ctx, "user@example.com", true)
	token, _ := d.sessions.Create(ctx, user.ID, time.Hour)

	credID := uuid.New()
	d.webauthnCredentials.byUser[user.ID] = []auth.WebAuthnCredential{{ID: credID, UserID: user.ID, Name: "old name"}}

	body, _ := json.Marshal(updateWebAuthnCredentialNameRequest{Name: "new name"})
	req := withSessionCookie(httptest.NewRequest(http.MethodPatch, "/api/auth/webauthn/credentials/"+credID.String(), bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp webauthnCredentialResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Name != "new name" {
		t.Fatalf("expected the response to reflect the new name, got %+v", resp)
	}
	if d.webauthnCredentials.byUser[user.ID][0].Name != "new name" {
		t.Fatalf("expected the store to be updated, got %+v", d.webauthnCredentials.byUser[user.ID])
	}
}

func TestHandleUpdateWebAuthnCredentialName_CannotRenameAnotherUsersCredential(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	attacker, _ := d.authStore.CreateUser(ctx, "attacker@example.com", true)
	token, _ := d.sessions.Create(ctx, attacker.ID, time.Hour)

	credID := uuid.New()
	d.webauthnCredentials.byUser[owner.ID] = []auth.WebAuthnCredential{{ID: credID, UserID: owner.ID, Name: "old name"}}

	body, _ := json.Marshal(updateWebAuthnCredentialNameRequest{Name: "new name"})
	req := withSessionCookie(httptest.NewRequest(http.MethodPatch, "/api/auth/webauthn/credentials/"+credID.String(), bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when renaming another user's credential, got %d: %s", rec.Code, rec.Body.String())
	}
	if d.webauthnCredentials.byUser[owner.ID][0].Name != "old name" {
		t.Fatalf("expected the owner's credential name to remain untouched")
	}
}

func TestHandleUpdateWebAuthnCredentialName_OverlyLongNameReturns400(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	user, _ := d.authStore.CreateUser(ctx, "user@example.com", true)
	token, _ := d.sessions.Create(ctx, user.ID, time.Hour)

	credID := uuid.New()
	d.webauthnCredentials.byUser[user.ID] = []auth.WebAuthnCredential{{ID: credID, UserID: user.ID}}

	body, _ := json.Marshal(updateWebAuthnCredentialNameRequest{Name: strings.Repeat("a", 101)})
	req := withSessionCookie(httptest.NewRequest(http.MethodPatch, "/api/auth/webauthn/credentials/"+credID.String(), bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a name over the length limit, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleWebAuthnLoginBegin_IsPublic(t *testing.T) {
	d := newTestServer()

	req := httptest.NewRequest(http.MethodPost, "/api/auth/webauthn/login/begin", nil)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (login/begin must not require auth — usernameless login), got %d: %s", rec.Code, rec.Body.String())
	}
	var resp webauthnCeremonyResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.CeremonyID == "" {
		t.Fatalf("expected a non-empty ceremony_id")
	}
}

func TestHandleWebAuthnLoginFinish_MissingCeremonyIDReturns400(t *testing.T) {
	d := newTestServer()

	req := httptest.NewRequest(http.MethodPost, "/api/auth/webauthn/login/finish", nil)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a missing ceremony_id, got %d", rec.Code)
	}
}

func TestHandleWebAuthnLoginFinish_UnknownCeremonyReturns400(t *testing.T) {
	d := newTestServer()

	req := httptest.NewRequest(http.MethodPost, "/api/auth/webauthn/login/finish?ceremony_id=never-issued", nil)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an unknown/expired ceremony, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleListWebAuthnCredentials_RequiresAuthAndScopesToTheCaller(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	user, _ := d.authStore.CreateUser(ctx, "user@example.com", true)
	other, _ := d.authStore.CreateUser(ctx, "other@example.com", true)
	token, _ := d.sessions.Create(ctx, user.ID, time.Hour)

	d.webauthnCredentials.byUser[user.ID] = []auth.WebAuthnCredential{
		{ID: uuid.New(), UserID: user.ID, Transports: []string{"internal"}},
	}
	d.webauthnCredentials.byUser[other.ID] = []auth.WebAuthnCredential{
		{ID: uuid.New(), UserID: other.ID, Transports: []string{"usb"}},
	}

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/auth/webauthn/credentials", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp []webauthnCredentialResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 1 || resp[0].Transports[0] != "internal" {
		t.Fatalf("expected exactly the caller's own credential, got %+v", resp)
	}
}

func TestHandleDeleteWebAuthnCredential_CannotDeleteAnotherUsersCredential(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	attacker, _ := d.authStore.CreateUser(ctx, "attacker@example.com", true)
	token, _ := d.sessions.Create(ctx, attacker.ID, time.Hour)

	credID := uuid.New()
	d.webauthnCredentials.byUser[owner.ID] = []auth.WebAuthnCredential{{ID: credID, UserID: owner.ID}}

	req := withSessionCookie(httptest.NewRequest(http.MethodDelete, "/api/auth/webauthn/credentials/"+credID.String(), nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when deleting another user's credential, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(d.webauthnCredentials.byUser[owner.ID]) != 1 {
		t.Fatalf("expected the owner's credential to remain untouched")
	}
}

func TestHandleDeleteWebAuthnCredential_OwnerCanDeleteTheirOwn(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	user, _ := d.authStore.CreateUser(ctx, "user@example.com", true)
	token, _ := d.sessions.Create(ctx, user.ID, time.Hour)

	credID := uuid.New()
	d.webauthnCredentials.byUser[user.ID] = []auth.WebAuthnCredential{{ID: credID, UserID: user.ID}}

	req := withSessionCookie(httptest.NewRequest(http.MethodDelete, "/api/auth/webauthn/credentials/"+credID.String(), nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(d.webauthnCredentials.byUser[user.ID]) != 0 {
		t.Fatalf("expected the credential to be removed")
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
	if resp.YourRole != "owner" || !resp.CanEdit || !resp.CanDelete || !resp.CanManagePermissions {
		t.Fatalf("expected the creator to be reported as a full-access owner, got %+v", resp)
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
	if resp.YourRole != "owner" || !resp.CanEdit || !resp.CanDelete || !resp.CanManagePermissions {
		t.Fatalf("expected the owner's access flags to reflect full access, got %+v", resp)
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
	var resp shortURLResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// 4.1節: system_adminの無制限閲覧は自身のgrantが無いURLについては
	// 閲覧のみで編集・削除・権限管理はできない。フロントがボタンの
	// 出し分けに使うため、your_role/can_*がその通りに反映されている必要が
	// ある。
	if resp.YourRole != "" || resp.CanEdit || resp.CanDelete || resp.CanManagePermissions {
		t.Fatalf("expected AdminOverride access to be view-only with no role, got %+v", resp)
	}
}

func TestHandleGetShortURLStats_OwnerSeesDailyAndReferrerBreakdown(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	token, _ := d.sessions.Create(ctx, owner.ID, time.Hour)

	created, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com", CreatedBy: owner.ID})
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}
	d.permissions.grants[grantKey(created.ID, owner.ID)] = &permission.Grant{UserID: owner.ID, Role: permission.RoleOwner}
	d.statsReader.daily[created.ID] = []stats.DailyCount{
		{Date: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), ClickCount: 3},
	}
	d.statsReader.referrers[created.ID] = []stats.ReferrerCount{
		{ReferrerHost: "google.com", ClickCount: 3},
	}

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/short-urls/"+created.ID.String()+"/stats?from=2026-08-01&to=2026-08-07", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp shortURLStatsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.From != "2026-08-01" || resp.To != "2026-08-07" {
		t.Fatalf("expected the requested from/to to be echoed back, got %+v", resp)
	}
	if len(resp.Daily) != 1 || resp.Daily[0].ClickCount != 3 {
		t.Fatalf("expected the daily breakdown to pass through, got %+v", resp.Daily)
	}
	if len(resp.ByReferrer) != 1 || resp.ByReferrer[0].ReferrerHost != "google.com" {
		t.Fatalf("expected the referrer breakdown to pass through, got %+v", resp.ByReferrer)
	}
	if len(d.authStore.audit) != 0 {
		t.Fatalf("an owner viewing their own URL's stats must not write a stats.admin_view audit entry, got %+v", d.authStore.audit)
	}
}

func TestHandleGetShortURLStats_GranularityHourReturnsHourlyBreakdown(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	token, _ := d.sessions.Create(ctx, owner.ID, time.Hour)

	created, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com", CreatedBy: owner.ID})
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}
	d.permissions.grants[grantKey(created.ID, owner.ID)] = &permission.Grant{UserID: owner.ID, Role: permission.RoleOwner}
	d.statsReader.hourly[created.ID] = []stats.HourlyCount{
		{Hour: time.Date(2026, 8, 1, 14, 0, 0, 0, time.UTC), ClickCount: 2},
	}
	d.statsReader.referrers[created.ID] = []stats.ReferrerCount{
		{ReferrerHost: "google.com", ClickCount: 2},
	}

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/short-urls/"+created.ID.String()+"/stats?from=2026-08-01&to=2026-08-01&granularity=hour", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp shortURLStatsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Granularity != "hour" {
		t.Fatalf("expected granularity=hour to be echoed back, got %+v", resp)
	}
	if len(resp.Hourly) != 1 || resp.Hourly[0].ClickCount != 2 {
		t.Fatalf("expected the hourly breakdown to pass through, got %+v", resp.Hourly)
	}
	if len(resp.Daily) != 0 {
		t.Fatalf("expected daily to be empty when granularity=hour, got %+v", resp.Daily)
	}
}

func TestHandleGetShortURLStats_InvalidGranularityReturns400(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	token, _ := d.sessions.Create(ctx, owner.ID, time.Hour)

	created, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com", CreatedBy: owner.ID})
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}
	d.permissions.grants[grantKey(created.ID, owner.ID)] = &permission.Grant{UserID: owner.ID, Role: permission.RoleOwner}

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/short-urls/"+created.ID.String()+"/stats?granularity=minute", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an invalid granularity, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleGetShortURLStats_UnauthorizedUserGets404(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	stranger, _ := d.authStore.CreateUser(ctx, "stranger@example.com", true)
	token, _ := d.sessions.Create(ctx, stranger.ID, time.Hour)

	created, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com", CreatedBy: owner.ID})
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/short-urls/"+created.ID.String()+"/stats", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 to conceal the URL's existence (4.2節), got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleGetShortURLStats_NonexistentURLReturns404ForAdmin guards against
// a real bug caught by manual smoke testing: resolveAccess's AdminOverride
// is granted unconditionally from subject.IsSystemAdmin alone (it never
// checks whether the short URL row actually exists), so without an
// explicit existence check a system_admin querying a nonexistent id would
// sail straight through to GetStats and get back an empty-but-200 result
// instead of 404.
func TestHandleGetShortURLStats_NonexistentURLReturns404ForAdmin(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	admin, _ := d.authStore.CreateUser(ctx, "admin@example.com", true)
	d.permissions.admins[admin.ID] = true
	token, _ := d.sessions.Create(ctx, admin.ID, time.Hour)

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/short-urls/"+uuid.New().String()+"/stats", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for a nonexistent short URL even under AdminOverride, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleGetShortURLStats_AdminOverrideRecordsAudit(t *testing.T) {
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

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/short-urls/"+created.ID.String()+"/stats", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (system_admin override), got %d: %s", rec.Code, rec.Body.String())
	}
	if len(d.authStore.audit) != 1 || d.authStore.audit[0].Action != "stats.admin_view" {
		t.Fatalf("expected one stats.admin_view audit entry (4.1節), got %+v", d.authStore.audit)
	}
}

func TestHandleGetShortURLStats_DefaultsToTrailing30Days(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	token, _ := d.sessions.Create(ctx, owner.ID, time.Hour)

	created, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com", CreatedBy: owner.ID})
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}
	d.permissions.grants[grantKey(created.ID, owner.ID)] = &permission.Grant{UserID: owner.ID, Role: permission.RoleOwner}

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/short-urls/"+created.ID.String()+"/stats", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp shortURLStatsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	from, _ := time.Parse(statsDateLayout, resp.From)
	to, _ := time.Parse(statsDateLayout, resp.To)
	if days := to.Sub(from).Hours() / 24; days != 29 {
		t.Fatalf("expected a default 30-day window (29 days between from and to), got %v to %v (%v days)", resp.From, resp.To, days)
	}
}

func TestHandleGetShortURLStats_InvalidRangeReturns400(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	token, _ := d.sessions.Create(ctx, owner.ID, time.Hour)

	created, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com", CreatedBy: owner.ID})
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}
	d.permissions.grants[grantKey(created.ID, owner.ID)] = &permission.Grant{UserID: owner.ID, Role: permission.RoleOwner}

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/short-urls/"+created.ID.String()+"/stats?from=2026-08-10&to=2026-08-01", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for to before from, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleListShortURLs_RegularUserSeesOwnOnly(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	other, _ := d.authStore.CreateUser(ctx, "other@example.com", true)
	token, _ := d.sessions.Create(ctx, owner.ID, time.Hour)

	mine, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com/mine", CreatedBy: owner.ID})
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}
	// 本番のstorage.ShortURLStore.CreateShortURLは同一トランザクションで
	// 作成者をownerとしてurl_permissionsへ書き込む(4.2節)。fakeは別々の
	// storeなのでテスト側で対応する grant を用意する。
	d.permissions.grants[grantKey(mine.ID, owner.ID)] = &permission.Grant{UserID: owner.ID, Role: permission.RoleOwner}
	if _, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com/theirs", CreatedBy: other.ID}); err != nil {
		t.Fatalf("seed create: %v", err)
	}

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/short-urls", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp shortURLListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Total != 1 || len(resp.Items) != 1 || resp.Items[0].LongURL != "https://example.com/mine" {
		t.Fatalf("expected a regular user to see only their own short URL, got %+v", resp)
	}
	if resp.Items[0].YourRole != "owner" || !resp.Items[0].CanEdit || !resp.Items[0].CanDelete || !resp.Items[0].CanManagePermissions {
		t.Fatalf("expected the owner's role/access flags on each list item, got %+v", resp.Items[0])
	}
	if resp.Items[0].CreatorEmail != nil {
		t.Fatalf("expected creator_email to be omitted for a non-admin viewer, got %+v", resp.Items[0])
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
	d.shortURLs.creatorEmails[owner.ID] = "owner@example.com"

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/short-urls", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	var resp shortURLListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Total != 1 || len(resp.Items) != 1 {
		t.Fatalf("expected system_admin to see every short URL by default (4.1節), got %+v", resp)
	}
	if resp.Items[0].YourRole != "" || resp.Items[0].CanEdit || resp.Items[0].CanDelete || resp.Items[0].CanManagePermissions {
		t.Fatalf("expected an admin viewing a URL they hold no grant on to be view-only, got %+v", resp.Items[0])
	}
	if resp.Items[0].CreatorEmail == nil || *resp.Items[0].CreatorEmail != "owner@example.com" {
		t.Fatalf("expected creator_email to be shown to a system_admin, got %+v", resp.Items[0])
	}

	req = withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/short-urls?scope=mine", nil), token)
	rec = httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	resp = shortURLListResponse{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Items) != 0 {
		t.Fatalf("expected ?scope=mine to restrict an admin to their own short URLs, got %+v", resp)
	}
}

func TestHandleListShortURLs_FilterMatchesAnyDisplayedTextField(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	token, _ := d.sessions.Create(ctx, owner.ID, time.Hour)

	alpha, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com/alpha", Title: "Alpha Page", CreatedBy: owner.ID})
	if err != nil {
		t.Fatalf("seed create alpha: %v", err)
	}
	d.permissions.grants[grantKey(alpha.ID, owner.ID)] = &permission.Grant{UserID: owner.ID, Role: permission.RoleOwner}
	beta, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com/beta", Title: "Beta Page", CreatedBy: owner.ID})
	if err != nil {
		t.Fatalf("seed create beta: %v", err)
	}
	d.permissions.grants[grantKey(beta.ID, owner.ID)] = &permission.Grant{UserID: owner.ID, Role: permission.RoleOwner}

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/short-urls?filter=alpha", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	var resp shortURLListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Total != 1 || len(resp.Items) != 1 || resp.Items[0].Title != "Alpha Page" {
		t.Fatalf("expected filter=alpha to match only the Alpha Page row, got %+v", resp)
	}
}

func TestHandleListShortURLs_SortByClickCountDescending(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	token, _ := d.sessions.Create(ctx, owner.ID, time.Hour)

	low, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com/low", CreatedBy: owner.ID})
	if err != nil {
		t.Fatalf("seed create low: %v", err)
	}
	d.permissions.grants[grantKey(low.ID, owner.ID)] = &permission.Grant{UserID: owner.ID, Role: permission.RoleOwner}
	high, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com/high", CreatedBy: owner.ID})
	if err != nil {
		t.Fatalf("seed create high: %v", err)
	}
	d.permissions.grants[grantKey(high.ID, owner.ID)] = &permission.Grant{UserID: owner.ID, Role: permission.RoleOwner}
	d.shortURLs.clickCounts[low.ID] = 1
	d.shortURLs.clickCounts[high.ID] = 100

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/short-urls?sort_by=click_count&sort_dir=desc", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	var resp shortURLListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Items) != 2 || resp.Items[0].LongURL != "https://example.com/high" || resp.Items[1].LongURL != "https://example.com/low" {
		t.Fatalf("expected sort_by=click_count&sort_dir=desc to order high before low, got %+v", resp.Items)
	}
}

func TestHandleListShortURLs_InvalidSortReturns400(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	token, _ := d.sessions.Create(ctx, owner.ID, time.Hour)

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/short-urls?sort_by=not_a_real_field", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an invalid sort_by, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleListShortURLs_PageSizeAndOffsetAgainstTotal(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	owner, _ := d.authStore.CreateUser(ctx, "owner@example.com", true)
	token, _ := d.sessions.Create(ctx, owner.ID, time.Hour)

	for i := 0; i < 3; i++ {
		created, err := d.server.shortURLs.Create(ctx, shorturl.CreateInput{DomainID: d.server.domainID, LongURL: "https://example.com/" + string(rune('a'+i)), CreatedBy: owner.ID})
		if err != nil {
			t.Fatalf("seed create %d: %v", i, err)
		}
		d.permissions.grants[grantKey(created.ID, owner.ID)] = &permission.Grant{UserID: owner.ID, Role: permission.RoleOwner}
	}

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/short-urls?limit=2&offset=0", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	var resp shortURLListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Total != 3 || len(resp.Items) != 2 {
		t.Fatalf("expected total=3 with 2 items on the first page of limit=2, got %+v", resp)
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
	if resp.YourRole != "editor" || !resp.CanEdit || resp.CanDelete || resp.CanManagePermissions {
		t.Fatalf("expected editor access flags (can edit, cannot delete/manage), got %+v", resp)
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

// --- SAML config handler tests ----------------------------------------------

func testCertPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func validSAMLConfigRequest(t *testing.T) samlConfigRequest {
	return samlConfigRequest{
		Name:           "社内ADFS",
		IdPEntityID:    "https://adfs.example.com/adfs/services/trust",
		IdPSSOURL:      "https://adfs.example.com/adfs/ls/",
		IdPCertificate: testCertPEM(t),
		EmailAttribute: "email",
		Trusted:        true,
		Enabled:        true,
	}
}

func loginAsAdmin(t *testing.T, d *testDeps) string {
	t.Helper()
	ctx := context.Background()
	admin, err := d.authStore.CreateUser(ctx, "admin@example.com", true)
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	d.permissions.admins[admin.ID] = true
	token, err := d.sessions.Create(ctx, admin.ID, time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return token
}

func TestHandleCreateSAMLConfig_Success(t *testing.T) {
	d := newTestServer()
	token := loginAsAdmin(t, d)

	body, _ := json.Marshal(validSAMLConfigRequest(t))
	req := withSessionCookie(httptest.NewRequest(http.MethodPost, "/api/admin/saml-configs", bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp samlConfigResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Name != "社内ADFS" || !resp.Trusted {
		t.Fatalf("unexpected response: %+v", resp)
	}

	found := false
	for _, entry := range d.authStore.audit {
		if entry.Action == "admin.saml_config_created" && entry.TargetID == resp.ID.String() {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an admin.saml_config_created audit entry, got %+v", d.authStore.audit)
	}
}

func TestHandleCreateSAMLConfig_InvalidCertificateRejected(t *testing.T) {
	d := newTestServer()
	token := loginAsAdmin(t, d)

	req := validSAMLConfigRequest(t)
	req.IdPCertificate = "not a certificate"
	body, _ := json.Marshal(req)
	httpReq := withSessionCookie(httptest.NewRequest(http.MethodPost, "/api/admin/saml-configs", bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, httpReq)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an invalid certificate, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(d.samlConfigs.configs) != 0 {
		t.Fatalf("expected no config to be stored on validation failure")
	}
}

func TestHandleListSAMLConfigs_NonAdminForbidden(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()
	user, _ := d.authStore.CreateUser(ctx, "user@example.com", true)
	token, _ := d.sessions.Create(ctx, user.ID, time.Hour)

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/admin/saml-configs", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a non-admin, got %d", rec.Code)
	}
}

func TestHandleUpdateSAMLConfig_UnknownIDIsNotFound(t *testing.T) {
	d := newTestServer()
	token := loginAsAdmin(t, d)

	body, _ := json.Marshal(validSAMLConfigRequest(t))
	req := withSessionCookie(httptest.NewRequest(http.MethodPatch, "/api/admin/saml-configs/"+uuid.New().String(), bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for an unknown saml config id, got %d", rec.Code)
	}
}

func TestHandleUpdateSAMLConfig_Success(t *testing.T) {
	d := newTestServer()
	token := loginAsAdmin(t, d)
	ctx := context.Background()

	created, err := d.server.samlConfigs.Create(ctx, validSAMLConfigRequest(t).toInput())
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}

	update := validSAMLConfigRequest(t)
	update.Name = "更新後のIdP名"
	update.Enabled = false
	body, _ := json.Marshal(update)
	req := withSessionCookie(httptest.NewRequest(http.MethodPatch, "/api/admin/saml-configs/"+created.ID.String(), bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp samlConfigResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Name != "更新後のIdP名" || resp.Enabled {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestHandleDeleteSAMLConfig_RefusedWhenInUse(t *testing.T) {
	d := newTestServer()
	token := loginAsAdmin(t, d)
	ctx := context.Background()

	created, err := d.server.samlConfigs.Create(ctx, validSAMLConfigRequest(t).toInput())
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}
	d.samlConfigs.identCount[created.ID] = 1

	req := withSessionCookie(httptest.NewRequest(http.MethodDelete, "/api/admin/saml-configs/"+created.ID.String(), nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 refusing to delete a config still in use, got %d: %s", rec.Code, rec.Body.String())
	}
	if _, ok := d.samlConfigs.configs[created.ID]; !ok {
		t.Fatalf("expected the config to remain after a refused delete")
	}
}

func TestHandleDeleteSAMLConfig_Success(t *testing.T) {
	d := newTestServer()
	token := loginAsAdmin(t, d)
	ctx := context.Background()

	created, err := d.server.samlConfigs.Create(ctx, validSAMLConfigRequest(t).toInput())
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}

	req := withSessionCookie(httptest.NewRequest(http.MethodDelete, "/api/admin/saml-configs/"+created.ID.String(), nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
	if _, ok := d.samlConfigs.configs[created.ID]; ok {
		t.Fatalf("expected the config to be removed")
	}

	found := false
	for _, entry := range d.authStore.audit {
		if entry.Action == "admin.saml_config_deleted" && entry.TargetID == created.ID.String() {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an admin.saml_config_deleted audit entry, got %+v", d.authStore.audit)
	}
}

// --- SAML login/ACS handler tests ------------------------------------------

func TestHandleListSAMLIdPs_OnlyReturnsEnabledConfigsAndIsPublic(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	enabled, err := (&auth.SAMLConfigService{Store: d.samlConfigs}).Create(ctx, validSAMLConfigRequest(t).toInput())
	if err != nil {
		t.Fatalf("seed enabled config: %v", err)
	}
	disabledInput := validSAMLConfigRequest(t).toInput()
	disabledInput.Name = "Disabled IdP"
	disabledInput.Enabled = false
	if _, err := (&auth.SAMLConfigService{Store: d.samlConfigs}).Create(ctx, disabledInput); err != nil {
		t.Fatalf("seed disabled config: %v", err)
	}

	// 未認証でもアクセスできる(ログイン画面がIdP一覧を出すために必要)。
	req := httptest.NewRequest(http.MethodGet, "/api/auth/saml/idps", nil)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp []publicSAMLIdPResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 1 || resp[0].ID != enabled.ID {
		t.Fatalf("expected only the enabled config to be listed, got %+v", resp)
	}
}

func TestHandleSAMLLoginRedirect_RedirectsToTheIdP(t *testing.T) {
	d := newTestServer()
	configID := uuid.New()
	d.samlLogin.beginLoginFunc = func(_ context.Context, id uuid.UUID) (string, error) {
		if id != configID {
			t.Fatalf("expected configID %s, got %s", configID, id)
		}
		return "https://idp.example.com/sso?SAMLRequest=abc", nil
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auth/saml/"+configID.String()+"/login", nil)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://idp.example.com/sso?SAMLRequest=abc" {
		t.Fatalf("unexpected redirect location: %s", loc)
	}
}

func TestHandleSAMLLoginRedirect_UnknownConfigIs404(t *testing.T) {
	d := newTestServer()
	d.samlLogin.beginLoginFunc = func(context.Context, uuid.UUID) (string, error) {
		return "", auth.ErrNotFound
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auth/saml/"+uuid.New().String()+"/login", nil)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestHandleSAMLACS_LoggedInSetsSessionAndRedirectsHome(t *testing.T) {
	d := newTestServer()
	configID := uuid.New()
	loggedInUser := &auth.User{ID: uuid.New(), Email: "saml-user@example.com"}
	d.samlLogin.handleACSFunc = func(context.Context, uuid.UUID, *http.Request) (*auth.Result, error) {
		return &auth.Result{Outcome: auth.OutcomeLoggedIn, User: loggedInUser}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/api/auth/saml/"+configID.String()+"/acs", strings.NewReader("SAMLResponse=stub&RelayState=stub"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "http://localhost:5173/" {
		t.Fatalf("expected a redirect to the SPA home, got %s", loc)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "knives_session" || cookies[0].Value == "" {
		t.Fatalf("expected a session cookie to be set, got %+v", cookies)
	}
	if _, err := d.sessions.Find(context.Background(), cookies[0].Value); err != nil {
		t.Fatalf("expected the session to actually exist: %v", err)
	}
}

func TestHandleSAMLACS_PendingConfirmationRedirectsWithNotice(t *testing.T) {
	d := newTestServer()
	configID := uuid.New()
	d.samlLogin.handleACSFunc = func(context.Context, uuid.UUID, *http.Request) (*auth.Result, error) {
		return &auth.Result{Outcome: auth.OutcomePendingConfirmation}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/api/auth/saml/"+configID.String()+"/acs", strings.NewReader("SAMLResponse=stub&RelayState=stub"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "http://localhost:5173/login?notice=saml_pending_confirmation" {
		t.Fatalf("unexpected redirect location: %s", loc)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatalf("expected no session cookie for a pending-confirmation outcome")
	}
}

func TestHandleSAMLACS_InvalidResponseRedirectsWithErrorNotFound(t *testing.T) {
	d := newTestServer()
	configID := uuid.New()
	d.samlLogin.handleACSFunc = func(context.Context, uuid.UUID, *http.Request) (*auth.Result, error) {
		return nil, auth.ErrSAMLResponseInvalid
	}

	req := httptest.NewRequest(http.MethodPost, "/api/auth/saml/"+configID.String()+"/acs", strings.NewReader("SAMLResponse=stub&RelayState=stub"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	// SAMLは全画面遷移のフローなので、失敗もJSONの4xxではなく
	// ログイン画面へのリダイレクトで表現する。理由の詳細はcrientに
	// 漏らさない(汎用エラーのみ)。
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "http://localhost:5173/login?error=saml_failed" {
		t.Fatalf("unexpected redirect location: %s", loc)
	}
}

// --- OIDC config handler tests ----------------------------------------------

func validOIDCConfigRequest() oidcConfigRequest {
	return oidcConfigRequest{
		Name:                      "社内Entra ID",
		Issuer:                    "https://login.microsoftonline.com/tenant-id/v2.0",
		ClientID:                  "client-abc",
		ClientSecret:              "s3cr3t",
		Scopes:                    []string{"openid", "email", "profile"},
		RequireEmailVerifiedClaim: true,
		Enabled:                   true,
	}
}

func TestHandleCreateOIDCConfig_Success(t *testing.T) {
	d := newTestServer()
	token := loginAsAdmin(t, d)

	body, _ := json.Marshal(validOIDCConfigRequest())
	req := withSessionCookie(httptest.NewRequest(http.MethodPost, "/api/admin/oidc-configs", bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "s3cr3t") {
		t.Fatalf("expected the client_secret to never appear in the response, got %s", rec.Body.String())
	}
	var resp oidcConfigResponse
	if err := json.NewDecoder(bytes.NewReader(rec.Body.Bytes())).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Name != "社内Entra ID" || resp.ClientID != "client-abc" {
		t.Fatalf("unexpected response: %+v", resp)
	}

	found := false
	for _, entry := range d.authStore.audit {
		if entry.Action == "admin.oidc_config_created" && entry.TargetID == resp.ID.String() {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an admin.oidc_config_created audit entry, got %+v", d.authStore.audit)
	}
}

func TestHandleCreateOIDCConfig_MissingSecretRejected(t *testing.T) {
	d := newTestServer()
	token := loginAsAdmin(t, d)

	req := validOIDCConfigRequest()
	req.ClientSecret = ""
	body, _ := json.Marshal(req)
	httpReq := withSessionCookie(httptest.NewRequest(http.MethodPost, "/api/admin/oidc-configs", bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, httpReq)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a missing client_secret on create, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleCreateOIDCConfig_ScopesWithoutOpenIDRejected(t *testing.T) {
	d := newTestServer()
	token := loginAsAdmin(t, d)

	req := validOIDCConfigRequest()
	req.Scopes = []string{"email", "profile"}
	body, _ := json.Marshal(req)
	httpReq := withSessionCookie(httptest.NewRequest(http.MethodPost, "/api/admin/oidc-configs", bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, httpReq)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for scopes missing openid, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleListOIDCConfigs_NonAdminForbidden(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()
	user, _ := d.authStore.CreateUser(ctx, "user@example.com", true)
	token, _ := d.sessions.Create(ctx, user.ID, time.Hour)

	req := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/admin/oidc-configs", nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a non-admin, got %d", rec.Code)
	}
}

func TestHandleUpdateOIDCConfig_WithoutSecretKeepsExisting(t *testing.T) {
	d := newTestServer()
	token := loginAsAdmin(t, d)
	ctx := context.Background()

	created, err := d.server.oidcConfigs.Create(ctx, validOIDCConfigRequest().toInput())
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}

	update := validOIDCConfigRequest()
	update.Name = "更新後の名前"
	update.ClientSecret = ""
	body, _ := json.Marshal(update)
	req := withSessionCookie(httptest.NewRequest(http.MethodPatch, "/api/admin/oidc-configs/"+created.ID.String(), bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp oidcConfigResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Name != "更新後の名前" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if d.oidcConfigs.configs[created.ID].ClientSecret != "s3cr3t" {
		t.Fatalf("expected the client secret to be preserved when not resent, got %q", d.oidcConfigs.configs[created.ID].ClientSecret)
	}
}

func TestHandleUpdateOIDCConfig_UnknownIDIsNotFound(t *testing.T) {
	d := newTestServer()
	token := loginAsAdmin(t, d)

	body, _ := json.Marshal(validOIDCConfigRequest())
	req := withSessionCookie(httptest.NewRequest(http.MethodPatch, "/api/admin/oidc-configs/"+uuid.New().String(), bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for an unknown oidc config id, got %d", rec.Code)
	}
}

func TestHandleDeleteOIDCConfig_RefusedWhenInUse(t *testing.T) {
	d := newTestServer()
	token := loginAsAdmin(t, d)
	ctx := context.Background()

	created, err := d.server.oidcConfigs.Create(ctx, validOIDCConfigRequest().toInput())
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}
	d.oidcConfigs.identCount[created.ID] = 1

	req := withSessionCookie(httptest.NewRequest(http.MethodDelete, "/api/admin/oidc-configs/"+created.ID.String(), nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 refusing to delete a config still in use, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleDeleteOIDCConfig_Success(t *testing.T) {
	d := newTestServer()
	token := loginAsAdmin(t, d)
	ctx := context.Background()

	created, err := d.server.oidcConfigs.Create(ctx, validOIDCConfigRequest().toInput())
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}

	req := withSessionCookie(httptest.NewRequest(http.MethodDelete, "/api/admin/oidc-configs/"+created.ID.String(), nil), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
	if _, ok := d.oidcConfigs.configs[created.ID]; ok {
		t.Fatalf("expected the config to be removed")
	}

	found := false
	for _, entry := range d.authStore.audit {
		if entry.Action == "admin.oidc_config_deleted" && entry.TargetID == created.ID.String() {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an admin.oidc_config_deleted audit entry, got %+v", d.authStore.audit)
	}
}

// --- OIDC login/callback handler tests --------------------------------------

func TestHandleListOIDCIdPs_OnlyReturnsEnabledConfigsAndIsPublic(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	enabled, err := (&auth.OIDCConfigService{Store: d.oidcConfigs}).Create(ctx, validOIDCConfigRequest().toInput())
	if err != nil {
		t.Fatalf("seed enabled config: %v", err)
	}
	disabledInput := validOIDCConfigRequest().toInput()
	disabledInput.Name = "Disabled IdP"
	disabledInput.Enabled = false
	if _, err := (&auth.OIDCConfigService{Store: d.oidcConfigs}).Create(ctx, disabledInput); err != nil {
		t.Fatalf("seed disabled config: %v", err)
	}

	// 未認証でもアクセスできる(ログイン画面がIdP一覧を出すために必要)。
	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/idps", nil)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp []publicOIDCIdPResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 1 || resp[0].ID != enabled.ID {
		t.Fatalf("expected only the enabled config to be listed, got %+v", resp)
	}
}

func TestHandleOIDCLoginRedirect_RedirectsToTheIdP(t *testing.T) {
	d := newTestServer()
	configID := uuid.New()
	d.oidcLogin.beginLoginFunc = func(_ context.Context, id uuid.UUID) (string, error) {
		if id != configID {
			t.Fatalf("expected configID %s, got %s", configID, id)
		}
		return "https://idp.example.com/auth?client_id=abc", nil
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/"+configID.String()+"/login", nil)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://idp.example.com/auth?client_id=abc" {
		t.Fatalf("unexpected redirect location: %s", loc)
	}
}

func TestHandleOIDCLoginRedirect_UnknownConfigIs404(t *testing.T) {
	d := newTestServer()
	d.oidcLogin.beginLoginFunc = func(context.Context, uuid.UUID) (string, error) {
		return "", auth.ErrNotFound
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/"+uuid.New().String()+"/login", nil)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestHandleOIDCCallback_LoggedInSetsSessionAndRedirectsHome(t *testing.T) {
	d := newTestServer()
	configID := uuid.New()
	loggedInUser := &auth.User{ID: uuid.New(), Email: "oidc-user@example.com"}
	d.oidcLogin.handleCallbackFunc = func(context.Context, uuid.UUID, *http.Request) (*auth.Result, error) {
		return &auth.Result{Outcome: auth.OutcomeLoggedIn, User: loggedInUser}, nil
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/"+configID.String()+"/callback?code=stub&state=stub", nil)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "http://localhost:5173/" {
		t.Fatalf("expected a redirect to the SPA home, got %s", loc)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "knives_session" || cookies[0].Value == "" {
		t.Fatalf("expected a session cookie to be set, got %+v", cookies)
	}
	if _, err := d.sessions.Find(context.Background(), cookies[0].Value); err != nil {
		t.Fatalf("expected the session to actually exist: %v", err)
	}
}

func TestHandleOIDCCallback_PendingConfirmationRedirectsWithNotice(t *testing.T) {
	d := newTestServer()
	configID := uuid.New()
	d.oidcLogin.handleCallbackFunc = func(context.Context, uuid.UUID, *http.Request) (*auth.Result, error) {
		return &auth.Result{Outcome: auth.OutcomePendingConfirmation}, nil
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/"+configID.String()+"/callback?code=stub&state=stub", nil)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "http://localhost:5173/login?notice=oidc_pending_confirmation" {
		t.Fatalf("unexpected redirect location: %s", loc)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatalf("expected no session cookie for a pending-confirmation outcome")
	}
}

func TestHandleOIDCCallback_InvalidResponseRedirectsWithError(t *testing.T) {
	d := newTestServer()
	configID := uuid.New()
	d.oidcLogin.handleCallbackFunc = func(context.Context, uuid.UUID, *http.Request) (*auth.Result, error) {
		return nil, auth.ErrOIDCResponseInvalid
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/"+configID.String()+"/callback?code=stub&state=stub", nil)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	// OIDCも全画面遷移のフローなので、失敗もJSONの4xxではなく
	// ログイン画面へのリダイレクトで表現する。理由の詳細はクライアントに
	// 漏らさない(汎用エラーのみ)。
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "http://localhost:5173/login?error=oidc_failed" {
		t.Fatalf("unexpected redirect location: %s", loc)
	}
}
