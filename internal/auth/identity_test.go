package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fakeStore struct {
	users       map[uuid.UUID]*User
	usersByMail map[string]uuid.UUID
	identities  map[string]*AuthIdentity
	identCount  map[uuid.UUID]int
	pending     map[string]*PendingLinkRequest
	audit       []AuditLogEntry
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		users:       map[uuid.UUID]*User{},
		usersByMail: map[string]uuid.UUID{},
		identities:  map[string]*AuthIdentity{},
		identCount:  map[uuid.UUID]int{},
		pending:     map[string]*PendingLinkRequest{},
	}
}

func identKey(pt ProviderType, pcID *uuid.UUID, subject string) string {
	cfg := ""
	if pcID != nil {
		cfg = pcID.String()
	}
	return string(pt) + "|" + cfg + "|" + subject
}

func (s *fakeStore) FindAuthIdentity(_ context.Context, providerType ProviderType, providerConfigID *uuid.UUID, subject string) (*AuthIdentity, error) {
	if id, ok := s.identities[identKey(providerType, providerConfigID, subject)]; ok {
		return id, nil
	}
	return nil, ErrNotFound
}

func (s *fakeStore) FindUserByEmail(_ context.Context, email string) (*User, error) {
	if id, ok := s.usersByMail[email]; ok {
		return s.users[id], nil
	}
	return nil, ErrNotFound
}

func (s *fakeStore) FindUserByID(_ context.Context, id uuid.UUID) (*User, error) {
	if u, ok := s.users[id]; ok {
		return u, nil
	}
	return nil, ErrNotFound
}

func (s *fakeStore) CountAuthIdentitiesForUser(_ context.Context, userID uuid.UUID) (int, error) {
	return s.identCount[userID], nil
}

func (s *fakeStore) CreateUser(_ context.Context, email string, emailVerified bool) (*User, error) {
	u := &User{ID: uuid.New(), Email: email, EmailVerified: emailVerified}
	s.users[u.ID] = u
	s.usersByMail[email] = u.ID
	return u, nil
}

func (s *fakeStore) CreateAuthIdentity(_ context.Context, userID uuid.UUID, providerType ProviderType, providerConfigID *uuid.UUID, subject, emailAtLink string, _ bool) (*AuthIdentity, error) {
	ident := &AuthIdentity{ID: uuid.New(), UserID: userID, EmailAtLink: emailAtLink}
	s.identities[identKey(providerType, providerConfigID, subject)] = ident
	s.identCount[userID]++
	return ident, nil
}

func (s *fakeStore) TouchAuthIdentity(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return nil
}

func (s *fakeStore) CreatePendingLinkRequest(_ context.Context, existingUserID uuid.UUID, providerType ProviderType, providerConfigID *uuid.UUID, subject, tokenHash string, expiresAt time.Time) (uuid.UUID, error) {
	id := uuid.New()
	s.pending[tokenHash] = &PendingLinkRequest{
		ID:               id,
		ExistingUserID:   existingUserID,
		ProviderType:     providerType,
		ProviderConfigID: providerConfigID,
		Subject:          subject,
		ExpiresAt:        expiresAt,
	}
	return id, nil
}

func (s *fakeStore) FindPendingLinkRequestByTokenHash(_ context.Context, tokenHash string) (*PendingLinkRequest, error) {
	if p, ok := s.pending[tokenHash]; ok {
		return p, nil
	}
	return nil, ErrNotFound
}

func (s *fakeStore) FindPendingLinkRequestByID(_ context.Context, id uuid.UUID) (*PendingLinkRequest, error) {
	for _, p := range s.pending {
		if p.ID == id {
			return p, nil
		}
	}
	return nil, ErrNotFound
}

func (s *fakeStore) FindPendingLinkRequestsForUser(_ context.Context, userID uuid.UUID) ([]*PendingLinkRequest, error) {
	var result []*PendingLinkRequest
	for _, p := range s.pending {
		if p.ExistingUserID == userID && p.ConfirmedAt == nil {
			result = append(result, p)
		}
	}
	return result, nil
}

func (s *fakeStore) ConfirmPendingLinkRequest(_ context.Context, id uuid.UUID, at time.Time) error {
	for _, p := range s.pending {
		if p.ID == id {
			t := at
			p.ConfirmedAt = &t
			return nil
		}
	}
	return ErrNotFound
}

func (s *fakeStore) RecordAuditLog(_ context.Context, entry AuditLogEntry) error {
	s.audit = append(s.audit, entry)
	return nil
}

type fakeMailer struct {
	sentTo  string
	sentURL string
	calls   int

	reviewSentTo  string
	reviewSentURL string
	reviewCalls   int
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

type fakeAuthSettingsProvider struct {
	requireReauth bool
}

func (f *fakeAuthSettingsProvider) RequireReauthForAccountLink(_ context.Context) (bool, error) {
	return f.requireReauth, nil
}

// newTestResolver defaults to legacy (one-click) confirmation so existing
// identity-resolution tests don't have to care about the approval mode;
// tests specifically about the reauth-based approval flow build their own
// Resolver with AuthSettings{requireReauth: true}.
func newTestResolver(store *fakeStore, mailer *fakeMailer) *Resolver {
	fixedNow := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	return &Resolver{
		Store:           store,
		Mailer:          mailer,
		AuthSettings:    &fakeAuthSettingsProvider{requireReauth: false},
		Now:             func() time.Time { return fixedNow },
		ConfirmBaseURL:  "https://go.example.com/auth/confirm-link",
		PendingLinksURL: "https://go.example.com/auth/pending-links",
	}
}

func extractToken(t *testing.T, confirmURL string) string {
	t.Helper()
	const marker = "?token="
	idx := strings.Index(confirmURL, marker)
	if idx < 0 {
		t.Fatalf("confirm URL missing token: %s", confirmURL)
	}
	return confirmURL[idx+len(marker):]
}

func TestResolve_NewEmailCreatesNewUser(t *testing.T) {
	store := newFakeStore()
	mailer := &fakeMailer{}
	r := newTestResolver(store, mailer)
	cfgID := uuid.New()

	res, err := r.Resolve(context.Background(), LoginAttempt{
		ProviderType:     ProviderOIDC,
		ProviderConfigID: &cfgID,
		Subject:          "sub-1",
		Email:            "new@example.com",
		EmailVerified:    true,
		Trusted:          true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Outcome != OutcomeLoggedIn {
		t.Fatalf("expected OutcomeLoggedIn, got %v", res.Outcome)
	}
	if res.User.Email != "new@example.com" {
		t.Fatalf("unexpected user email: %s", res.User.Email)
	}
	if mailer.calls != 0 {
		t.Fatalf("mailer should not be called for a brand new user")
	}
	if len(store.audit) != 1 || store.audit[0].Action != "account.link" {
		t.Fatalf("expected one account.link audit entry, got %+v", store.audit)
	}
}

func TestResolve_PlaceholderUserActivatesWithoutConfirmation(t *testing.T) {
	store := newFakeStore()
	mailer := &fakeMailer{}
	r := newTestResolver(store, mailer)
	ctx := context.Background()

	// YOURLS移行時に事前作成された、まだ誰もログインしていないユーザ(10節)を模す
	placeholder, _ := store.CreateUser(ctx, "owner@example.com", false)

	res, err := r.Resolve(ctx, LoginAttempt{
		ProviderType: ProviderLocal,
		Subject:      "owner@example.com",
		Email:        "owner@example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Outcome != OutcomeLoggedIn {
		t.Fatalf("expected OutcomeLoggedIn for placeholder activation, got %v", res.Outcome)
	}
	if res.User.ID != placeholder.ID {
		t.Fatalf("expected to log in as the placeholder user")
	}
	if mailer.calls != 0 {
		t.Fatalf("placeholder activation must not require confirmation")
	}
}

func TestResolve_TrustedSSOAutoLinksClaimedAccount(t *testing.T) {
	store := newFakeStore()
	mailer := &fakeMailer{}
	r := newTestResolver(store, mailer)
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "claimed@example.com", true)
	_, _ = store.CreateAuthIdentity(ctx, user.ID, ProviderLocal, nil, "claimed@example.com", "claimed@example.com", true)

	cfgID := uuid.New()
	res, err := r.Resolve(ctx, LoginAttempt{
		ProviderType:     ProviderOIDC,
		ProviderConfigID: &cfgID,
		Subject:          "sub-2",
		Email:            "claimed@example.com",
		Trusted:          true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Outcome != OutcomeLoggedIn {
		t.Fatalf("trusted SSO should bypass confirmation, got %v", res.Outcome)
	}
	if mailer.calls != 0 {
		t.Fatalf("trusted SSO must not trigger a confirmation email")
	}
}

func TestResolve_UntrustedCrossProviderLinkRequiresConfirmation(t *testing.T) {
	store := newFakeStore()
	mailer := &fakeMailer{}
	r := newTestResolver(store, mailer)
	ctx := context.Background()

	// victim は信頼済みOIDCでアカウントを既にクレーム済み
	user, _ := store.CreateUser(ctx, "victim@example.com", true)
	oidcCfg := uuid.New()
	_, _ = store.CreateAuthIdentity(ctx, user.ID, ProviderOIDC, &oidcCfg, "victim-sub", "victim@example.com", true)

	// 攻撃者が victim のメールアドレスでローカルセルフサインアップを試みる
	res, err := r.Resolve(ctx, LoginAttempt{
		ProviderType: ProviderLocal,
		Subject:      "victim@example.com",
		Email:        "victim@example.com",
		Trusted:      false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Outcome != OutcomePendingConfirmation {
		t.Fatalf("expected OutcomePendingConfirmation, got %v", res.Outcome)
	}
	if mailer.calls != 1 || mailer.sentTo != "victim@example.com" {
		t.Fatalf("confirmation email must go to the account's real registered address, got %+v", mailer)
	}
	if store.identCount[user.ID] != 1 {
		t.Fatalf("no new identity should be attached before confirmation")
	}
}

func TestResolve_ReturningSSOLoginReusesIdentity(t *testing.T) {
	store := newFakeStore()
	mailer := &fakeMailer{}
	r := newTestResolver(store, mailer)
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "returning@example.com", true)
	cfgID := uuid.New()
	_, _ = store.CreateAuthIdentity(ctx, user.ID, ProviderOIDC, &cfgID, "sub-3", "returning@example.com", true)
	auditBefore := len(store.audit)

	res, err := r.Resolve(ctx, LoginAttempt{
		ProviderType:     ProviderOIDC,
		ProviderConfigID: &cfgID,
		Subject:          "sub-3",
		Email:            "returning@example.com",
		Trusted:          true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Outcome != OutcomeLoggedIn || res.User.ID != user.ID {
		t.Fatalf("expected returning login to log in as the same user, got %+v", res)
	}
	if len(store.audit) != auditBefore {
		t.Fatalf("returning login must not create a new account.link audit entry")
	}
	if mailer.calls != 0 {
		t.Fatalf("returning login must not trigger a confirmation email")
	}
}

func TestResolve_EmailReassignmentTriggersReconfirmation(t *testing.T) {
	store := newFakeStore()
	mailer := &fakeMailer{}
	r := newTestResolver(store, mailer)
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "canonical@example.com", true)
	cfgID := uuid.New()
	_, _ = store.CreateAuthIdentity(ctx, user.ID, ProviderOIDC, &cfgID, "sub-4", "old-claim@example.com", true)

	res, err := r.Resolve(ctx, LoginAttempt{
		ProviderType:     ProviderOIDC,
		ProviderConfigID: &cfgID,
		Subject:          "sub-4",
		Email:            "attacker-controlled@example.com",
		Trusted:          true, // IdPの信頼設定だけでは再割当ての自動許可にはならない
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Outcome != OutcomePendingConfirmation {
		t.Fatalf("expected reconfirmation on email reassignment, got %v", res.Outcome)
	}
	if mailer.sentTo != "canonical@example.com" {
		t.Fatalf("confirmation must go to the account's current canonical email, got %s", mailer.sentTo)
	}
	if store.identCount[user.ID] != 1 {
		t.Fatalf("identity must not change until the reassignment is confirmed")
	}
}

func TestConfirmPendingLink_Success(t *testing.T) {
	store := newFakeStore()
	mailer := &fakeMailer{}
	r := newTestResolver(store, mailer)
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "victim@example.com", true)
	oidcCfg := uuid.New()
	_, _ = store.CreateAuthIdentity(ctx, user.ID, ProviderOIDC, &oidcCfg, "victim-sub", "victim@example.com", true)

	if _, err := r.Resolve(ctx, LoginAttempt{
		ProviderType: ProviderLocal,
		Subject:      "victim@example.com",
		Email:        "victim@example.com",
	}); err != nil {
		t.Fatalf("unexpected error requesting confirmation: %v", err)
	}
	token := extractToken(t, mailer.sentURL)

	res, err := r.ConfirmPendingLink(ctx, token)
	if err != nil {
		t.Fatalf("unexpected error confirming: %v", err)
	}
	if res.Outcome != OutcomeLoggedIn || res.User.ID != user.ID {
		t.Fatalf("expected confirmation to log in as the existing user, got %+v", res)
	}
	if store.identCount[user.ID] != 2 {
		t.Fatalf("expected the local identity to be attached after confirmation")
	}

	if _, err := r.ConfirmPendingLink(ctx, token); !errors.Is(err, ErrTokenAlreadyUsed) {
		t.Fatalf("expected ErrTokenAlreadyUsed on reuse, got %v", err)
	}
}

func TestConfirmPendingLink_Expired(t *testing.T) {
	store := newFakeStore()
	mailer := &fakeMailer{}
	current := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	r := &Resolver{
		Store:          store,
		Mailer:         mailer,
		AuthSettings:   &fakeAuthSettingsProvider{requireReauth: false},
		Now:            func() time.Time { return current },
		ConfirmBaseURL: "https://go.example.com/auth/confirm-link",
		TokenTTL:       time.Minute,
	}
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "victim@example.com", true)
	oidcCfg := uuid.New()
	_, _ = store.CreateAuthIdentity(ctx, user.ID, ProviderOIDC, &oidcCfg, "victim-sub", "victim@example.com", true)

	if _, err := r.Resolve(ctx, LoginAttempt{
		ProviderType: ProviderLocal,
		Subject:      "victim@example.com",
		Email:        "victim@example.com",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	token := extractToken(t, mailer.sentURL)

	current = current.Add(2 * time.Minute)

	if _, err := r.ConfirmPendingLink(ctx, token); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestResolve_ReauthMode_SendsReviewNoticeInsteadOfOneClickLink(t *testing.T) {
	store := newFakeStore()
	mailer := &fakeMailer{}
	r := newTestResolver(store, mailer)
	r.AuthSettings = &fakeAuthSettingsProvider{requireReauth: true}
	ctx := context.Background()

	victim, _ := store.CreateUser(ctx, "victim@example.com", true)
	oidcCfg := uuid.New()
	_, _ = store.CreateAuthIdentity(ctx, victim.ID, ProviderOIDC, &oidcCfg, "victim-sub", "victim@example.com", true)

	res, err := r.Resolve(ctx, LoginAttempt{
		ProviderType: ProviderLocal,
		Subject:      "victim@example.com",
		Email:        "victim@example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Outcome != OutcomePendingConfirmation {
		t.Fatalf("expected OutcomePendingConfirmation, got %v", res.Outcome)
	}
	if mailer.reviewCalls != 1 || mailer.reviewSentTo != "victim@example.com" {
		t.Fatalf("expected a review-notice email in reauth mode, got %+v", mailer)
	}
	if mailer.calls != 0 {
		t.Fatalf("reauth mode must not send the one-click confirmation email, got %d calls", mailer.calls)
	}
}

func TestResolver_ApprovePendingLink_Success(t *testing.T) {
	store := newFakeStore()
	mailer := &fakeMailer{}
	r := newTestResolver(store, mailer)
	r.AuthSettings = &fakeAuthSettingsProvider{requireReauth: true}
	ctx := context.Background()

	victim, _ := store.CreateUser(ctx, "victim@example.com", true)
	oidcCfg := uuid.New()
	_, _ = store.CreateAuthIdentity(ctx, victim.ID, ProviderOIDC, &oidcCfg, "victim-sub", "victim@example.com", true)
	auditBefore := len(store.audit)

	if _, err := r.Resolve(ctx, LoginAttempt{
		ProviderType: ProviderLocal,
		Subject:      "victim@example.com",
		Email:        "victim@example.com",
	}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	pending, err := r.ListPendingLinks(ctx, victim.ID)
	if err != nil {
		t.Fatalf("ListPendingLinks: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected exactly one pending link for the victim, got %d", len(pending))
	}

	res, err := r.ApprovePendingLink(ctx, victim.ID, pending[0].ID)
	if err != nil {
		t.Fatalf("ApprovePendingLink: %v", err)
	}
	if res.Outcome != OutcomeLoggedIn || res.User.ID != victim.ID {
		t.Fatalf("expected the approver to be logged in as themselves, got %+v", res)
	}
	if store.identCount[victim.ID] != 2 {
		t.Fatalf("expected the local identity to be attached after approval")
	}
	if len(store.audit) != auditBefore+1 {
		t.Fatalf("expected an account.link audit entry to be recorded")
	}

	// 再承認はエラーになる。
	if _, err := r.ApprovePendingLink(ctx, victim.ID, pending[0].ID); !errors.Is(err, ErrTokenAlreadyUsed) {
		t.Fatalf("expected ErrTokenAlreadyUsed on re-approval, got %v", err)
	}
}

func TestResolver_ApprovePendingLink_RejectsWrongApprover(t *testing.T) {
	store := newFakeStore()
	mailer := &fakeMailer{}
	r := newTestResolver(store, mailer)
	r.AuthSettings = &fakeAuthSettingsProvider{requireReauth: true}
	ctx := context.Background()

	victim, _ := store.CreateUser(ctx, "victim@example.com", true)
	oidcCfg := uuid.New()
	_, _ = store.CreateAuthIdentity(ctx, victim.ID, ProviderOIDC, &oidcCfg, "victim-sub", "victim@example.com", true)
	bystander, _ := store.CreateUser(ctx, "bystander@example.com", true)

	if _, err := r.Resolve(ctx, LoginAttempt{
		ProviderType: ProviderLocal,
		Subject:      "victim@example.com",
		Email:        "victim@example.com",
	}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	pending, err := r.ListPendingLinks(ctx, victim.ID)
	if err != nil || len(pending) != 1 {
		t.Fatalf("ListPendingLinks: %v, %+v", err, pending)
	}

	// bystanderが他人の保留リクエストIDを知っていても承認できない
	// (存在自体もErrNotFoundとして秘匿する)。
	if _, err := r.ApprovePendingLink(ctx, bystander.ID, pending[0].ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for a non-owning approver, got %v", err)
	}
	if store.identCount[victim.ID] != 1 {
		t.Fatalf("victim's identity count must be unaffected by the rejected approval attempt")
	}
}

func TestResolver_ApprovePendingLink_ExpiredIsRejected(t *testing.T) {
	store := newFakeStore()
	mailer := &fakeMailer{}
	current := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	r := &Resolver{
		Store:           store,
		Mailer:          mailer,
		AuthSettings:    &fakeAuthSettingsProvider{requireReauth: true},
		Now:             func() time.Time { return current },
		PendingLinksURL: "https://go.example.com/auth/pending-links",
		TokenTTL:        time.Minute,
	}
	ctx := context.Background()

	victim, _ := store.CreateUser(ctx, "victim@example.com", true)
	oidcCfg := uuid.New()
	_, _ = store.CreateAuthIdentity(ctx, victim.ID, ProviderOIDC, &oidcCfg, "victim-sub", "victim@example.com", true)

	if _, err := r.Resolve(ctx, LoginAttempt{
		ProviderType: ProviderLocal,
		Subject:      "victim@example.com",
		Email:        "victim@example.com",
	}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	var pendingID uuid.UUID
	for _, p := range store.pending {
		pendingID = p.ID
	}

	current = current.Add(2 * time.Minute)

	if _, err := r.ApprovePendingLink(ctx, victim.ID, pendingID); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestResolver_ListPendingLinks_OnlyReturnsThatUsersUnconfirmedRequests(t *testing.T) {
	store := newFakeStore()
	mailer := &fakeMailer{}
	r := newTestResolver(store, mailer)
	r.AuthSettings = &fakeAuthSettingsProvider{requireReauth: true}
	ctx := context.Background()

	userA, _ := store.CreateUser(ctx, "a@example.com", true)
	cfgA := uuid.New()
	_, _ = store.CreateAuthIdentity(ctx, userA.ID, ProviderOIDC, &cfgA, "a-sub", "a@example.com", true)

	userB, _ := store.CreateUser(ctx, "b@example.com", true)
	cfgB := uuid.New()
	_, _ = store.CreateAuthIdentity(ctx, userB.ID, ProviderOIDC, &cfgB, "b-sub", "b@example.com", true)

	if _, err := r.Resolve(ctx, LoginAttempt{ProviderType: ProviderLocal, Subject: "a@example.com", Email: "a@example.com"}); err != nil {
		t.Fatalf("Resolve A: %v", err)
	}
	if _, err := r.Resolve(ctx, LoginAttempt{ProviderType: ProviderLocal, Subject: "b@example.com", Email: "b@example.com"}); err != nil {
		t.Fatalf("Resolve B: %v", err)
	}

	pendingA, err := r.ListPendingLinks(ctx, userA.ID)
	if err != nil || len(pendingA) != 1 {
		t.Fatalf("expected exactly one pending link for userA, got err=%v pending=%+v", err, pendingA)
	}

	if _, err := r.ApprovePendingLink(ctx, userA.ID, pendingA[0].ID); err != nil {
		t.Fatalf("ApprovePendingLink: %v", err)
	}

	afterApproval, err := r.ListPendingLinks(ctx, userA.ID)
	if err != nil {
		t.Fatalf("ListPendingLinks after approval: %v", err)
	}
	if len(afterApproval) != 0 {
		t.Fatalf("a confirmed request must not be listed as pending anymore, got %+v", afterApproval)
	}

	pendingB, err := r.ListPendingLinks(ctx, userB.ID)
	if err != nil || len(pendingB) != 1 {
		t.Fatalf("expected userB's pending link to be unaffected, got err=%v pending=%+v", err, pendingB)
	}
}
