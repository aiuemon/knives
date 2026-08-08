package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aiuemon/knives/internal/auth"
	"github.com/google/uuid"
)

func extractToken(t *testing.T, confirmURL string) string {
	t.Helper()
	const marker = "?token="
	idx := strings.Index(confirmURL, marker)
	if idx < 0 {
		t.Fatalf("confirm URL missing token: %s", confirmURL)
	}
	return confirmURL[idx+len(marker):]
}

func TestHandleLocalSignup_NewUserLogsInImmediately(t *testing.T) {
	d := newTestServer()

	body, _ := json.Marshal(localSignupRequest{Email: "new@example.com", Password: "correct horse battery staple"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/local/signup", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp localSignupResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "logged_in" {
		t.Fatalf("expected status 'logged_in', got %q", resp.Status)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value == "" {
		t.Fatalf("expected a session cookie, got %+v", cookies)
	}
	if d.mailer.calls != 0 {
		t.Fatalf("a brand new signup must not trigger a confirmation email")
	}

	// 設定したパスワードで実際にログインできることを確認する。
	user, err := d.server.localAuth.Login(context.Background(), "new@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("expected the signup password to work for login: %v", err)
	}
	if _, err := d.sessions.Find(context.Background(), cookies[0].Value); err != nil {
		t.Fatalf("issued cookie should resolve to a live session: %v", err)
	}
	_ = user
}

func TestHandleLocalSignup_DisabledReturns403(t *testing.T) {
	d := newTestServer()
	d.authSettings.selfSignupEnabled = false

	body, _ := json.Marshal(localSignupRequest{Email: "new@example.com", Password: "correct horse battery staple"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/local/signup", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestHandleLocalSignup_WeakPasswordRejectedBeforeCreatingUser(t *testing.T) {
	d := newTestServer()

	body, _ := json.Marshal(localSignupRequest{Email: "new@example.com", Password: "short"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/local/signup", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	if _, err := d.authStore.FindUserByEmail(context.Background(), "new@example.com"); err == nil {
		t.Fatalf("a rejected signup must not have created a user")
	}
}

func TestHandleLocalSignup_CollidingEmailSendsConfirmationInsteadOfLoggingIn(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	// victimは信頼済みOIDCで既にアカウントをクレーム済み。
	victim, err := d.authStore.CreateUser(ctx, "victim@example.com", true)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	cfgID := uuid.New()
	if _, err := d.authStore.CreateAuthIdentity(ctx, victim.ID, auth.ProviderOIDC, &cfgID, "victim-sub", "victim@example.com", true); err != nil {
		t.Fatalf("CreateAuthIdentity: %v", err)
	}

	body, _ := json.Marshal(localSignupRequest{Email: "victim@example.com", Password: "attacker-chosen-password"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/local/signup", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp localSignupResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "verification_pending" {
		t.Fatalf("expected status 'verification_pending', got %q", resp.Status)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatalf("a pending signup must not issue a session cookie")
	}
	if d.mailer.calls != 1 || d.mailer.sentTo != "victim@example.com" {
		t.Fatalf("expected the confirmation email to go to the real account owner, got %+v", d.mailer)
	}
}

func TestHandleConfirmLink_AttachesIdentityAndLogsInAsExistingOwner(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	victim, err := d.authStore.CreateUser(ctx, "victim@example.com", true)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	cfgID := uuid.New()
	if _, err := d.authStore.CreateAuthIdentity(ctx, victim.ID, auth.ProviderOIDC, &cfgID, "victim-sub", "victim@example.com", true); err != nil {
		t.Fatalf("CreateAuthIdentity: %v", err)
	}

	signupBody, _ := json.Marshal(localSignupRequest{Email: "victim@example.com", Password: "attacker-chosen-password"})
	signupReq := httptest.NewRequest(http.MethodPost, "/api/auth/local/signup", bytes.NewReader(signupBody))
	signupRec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(signupRec, signupReq)
	if signupRec.Code != http.StatusAccepted {
		t.Fatalf("seed signup: expected 202, got %d", signupRec.Code)
	}
	token := extractToken(t, d.mailer.sentURL)

	confirmReq := httptest.NewRequest(http.MethodGet, "/api/auth/confirm-link?token="+token, nil)
	confirmRec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(confirmRec, confirmReq)

	if confirmRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", confirmRec.Code, confirmRec.Body.String())
	}
	cookies := confirmRec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value == "" {
		t.Fatalf("expected a session cookie to be issued, got %+v", cookies)
	}
	session, err := d.sessions.Find(ctx, cookies[0].Value)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if session.UserID != victim.ID {
		t.Fatalf("expected the confirmer to log in as the existing owner %s, got %s", victim.ID, session.UserID)
	}
}

func TestHandleConfirmLink_MissingTokenReturns400(t *testing.T) {
	d := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/api/auth/confirm-link", nil)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHandleSetPassword_RequiresAuth(t *testing.T) {
	d := newTestServer()

	body, _ := json.Marshal(setPasswordRequest{NewPassword: "another-strong-password"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/local/password", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestHandleSetPassword_Success(t *testing.T) {
	d := newTestServer()
	ctx := context.Background()

	user, err := d.authStore.CreateUser(ctx, "person@example.com", true)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	token, err := d.sessions.Create(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}

	body, _ := json.Marshal(setPasswordRequest{NewPassword: "another-strong-password"})
	req := withSessionCookie(httptest.NewRequest(http.MethodPost, "/api/auth/local/password", bytes.NewReader(body)), token)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := d.server.localAuth.Login(ctx, "person@example.com", "another-strong-password"); err != nil {
		t.Fatalf("expected the newly set password to work for login: %v", err)
	}
}

func TestHandleLocalSignup_ConfirmationRequired_NoAccountUntilVerified(t *testing.T) {
	d := newTestServer()
	d.authSettings.requireConfirmation = true

	body, _ := json.Marshal(localSignupRequest{Email: "new@example.com", Password: "correct horse battery staple"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/local/signup", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp localSignupResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "verification_pending" {
		t.Fatalf("expected status 'verification_pending', got %q", resp.Status)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatalf("an unverified signup must not issue a session cookie")
	}
	if d.mailer.verifyCalls != 1 || d.mailer.verifySentTo != "new@example.com" {
		t.Fatalf("expected one signup-verification email, got %+v", d.mailer)
	}
	if _, err := d.authStore.FindUserByEmail(context.Background(), "new@example.com"); err == nil {
		t.Fatalf("no user must exist before the email is verified (local-auth専用の登録前ゲート)")
	}
}

func TestHandleVerifyEmail_CompletesSignupAndLogsIn(t *testing.T) {
	d := newTestServer()
	d.authSettings.requireConfirmation = true

	signupBody, _ := json.Marshal(localSignupRequest{Email: "new@example.com", Password: "correct horse battery staple"})
	signupRec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(signupRec, httptest.NewRequest(http.MethodPost, "/api/auth/local/signup", bytes.NewReader(signupBody)))
	if signupRec.Code != http.StatusAccepted {
		t.Fatalf("seed signup: expected 202, got %d", signupRec.Code)
	}
	token := extractToken(t, d.mailer.verifySentURL)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/local/verify-email?token="+token, nil)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value == "" {
		t.Fatalf("expected a session cookie to be issued, got %+v", cookies)
	}
	user, err := d.authStore.FindUserByEmail(context.Background(), "new@example.com")
	if err != nil {
		t.Fatalf("expected the user to exist after verification: %v", err)
	}
	session, err := d.sessions.Find(context.Background(), cookies[0].Value)
	if err != nil || session.UserID != user.ID {
		t.Fatalf("expected the issued session to belong to the newly verified user, err=%v session=%+v", err, session)
	}
}

func TestHandleVerifyEmail_MissingTokenReturns400(t *testing.T) {
	d := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/api/auth/local/verify-email", nil)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHandleVerifyEmail_UnknownTokenReturns404(t *testing.T) {
	d := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/api/auth/local/verify-email?token=does-not-exist", nil)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestHandleVerifyEmail_ExpiredTokenReturns410(t *testing.T) {
	d := newTestServer()
	d.authSettings.requireConfirmation = true

	current := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	d.server.localSignup.Now = func() time.Time { return current }
	d.server.localSignup.TokenTTL = time.Minute

	signupBody, _ := json.Marshal(localSignupRequest{Email: "new@example.com", Password: "correct horse battery staple"})
	signupRec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(signupRec, httptest.NewRequest(http.MethodPost, "/api/auth/local/signup", bytes.NewReader(signupBody)))
	if signupRec.Code != http.StatusAccepted {
		t.Fatalf("seed signup: expected 202, got %d", signupRec.Code)
	}
	token := extractToken(t, d.mailer.verifySentURL)

	current = current.Add(2 * time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/local/verify-email?token="+token, nil)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusGone {
		t.Fatalf("expected 410, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleListPendingLinks_RequiresAuth(t *testing.T) {
	d := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/api/auth/pending-links", nil)
	rec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestReauthAccountLinkFlow_ListAndApprove(t *testing.T) {
	d := newTestServer()
	d.authSettings.requireReauthForAccountLink = true
	ctx := context.Background()

	// victimは信頼済みOIDCで既にアカウントをクレーム済み。
	victim, err := d.authStore.CreateUser(ctx, "victim@example.com", true)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	cfgID := uuid.New()
	if _, err := d.authStore.CreateAuthIdentity(ctx, victim.ID, auth.ProviderOIDC, &cfgID, "victim-sub", "victim@example.com", true); err != nil {
		t.Fatalf("CreateAuthIdentity: %v", err)
	}

	// 攻撃者がvictimのメールでローカルサインアップを試みる
	// (require_email_confirmation_for_signup=falseなので、直接衝突判定に入る)。
	signupBody, _ := json.Marshal(localSignupRequest{Email: "victim@example.com", Password: "attacker-chosen-password"})
	signupRec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(signupRec, httptest.NewRequest(http.MethodPost, "/api/auth/local/signup", bytes.NewReader(signupBody)))
	if signupRec.Code != http.StatusAccepted {
		t.Fatalf("seed signup: expected 202, got %d: %s", signupRec.Code, signupRec.Body.String())
	}
	if d.mailer.reviewCalls != 1 || d.mailer.reviewSentTo != "victim@example.com" {
		t.Fatalf("expected a review-notice email to the real owner, got %+v", d.mailer)
	}
	if d.mailer.calls != 0 {
		t.Fatalf("reauth mode must not send the one-click confirmation email")
	}

	// victimが自分の既存ログイン方法(ここではセッションを直接発行して模す)で
	// ログインした上で、保留リクエストを一覧・承認する。
	victimToken, err := d.sessions.Create(ctx, victim.ID, time.Hour)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}

	listReq := withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/auth/pending-links", nil), victimToken)
	listRec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", listRec.Code, listRec.Body.String())
	}
	var pending []pendingLinkResponse
	if err := json.NewDecoder(listRec.Body).Decode(&pending); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected exactly one pending link for victim, got %+v", pending)
	}

	approveReq := withSessionCookie(httptest.NewRequest(http.MethodPost, "/api/auth/pending-links/"+pending[0].ID.String()+"/approve", nil), victimToken)
	approveRec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(approveRec, approveReq)
	if approveRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", approveRec.Code, approveRec.Body.String())
	}

	// 承認後は一覧から消える。
	listAgainRec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(listAgainRec, withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/auth/pending-links", nil), victimToken))
	var pendingAfter []pendingLinkResponse
	if err := json.NewDecoder(listAgainRec.Body).Decode(&pendingAfter); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(pendingAfter) != 0 {
		t.Fatalf("expected the approved request to no longer be listed, got %+v", pendingAfter)
	}
}

func TestHandleApprovePendingLink_RejectsOtherUsersRequest(t *testing.T) {
	d := newTestServer()
	d.authSettings.requireReauthForAccountLink = true
	ctx := context.Background()

	victim, _ := d.authStore.CreateUser(ctx, "victim@example.com", true)
	cfgID := uuid.New()
	if _, err := d.authStore.CreateAuthIdentity(ctx, victim.ID, auth.ProviderOIDC, &cfgID, "victim-sub", "victim@example.com", true); err != nil {
		t.Fatalf("CreateAuthIdentity: %v", err)
	}
	bystander, _ := d.authStore.CreateUser(ctx, "bystander@example.com", true)

	signupBody, _ := json.Marshal(localSignupRequest{Email: "victim@example.com", Password: "attacker-chosen-password"})
	d.server.routes().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/auth/local/signup", bytes.NewReader(signupBody)))

	victimToken, _ := d.sessions.Create(ctx, victim.ID, time.Hour)
	listRec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(listRec, withSessionCookie(httptest.NewRequest(http.MethodGet, "/api/auth/pending-links", nil), victimToken))
	var pending []pendingLinkResponse
	if err := json.NewDecoder(listRec.Body).Decode(&pending); err != nil || len(pending) != 1 {
		t.Fatalf("expected exactly one pending link, err=%v pending=%+v", err, pending)
	}

	bystanderToken, _ := d.sessions.Create(ctx, bystander.ID, time.Hour)
	approveReq := withSessionCookie(httptest.NewRequest(http.MethodPost, "/api/auth/pending-links/"+pending[0].ID.String()+"/approve", nil), bystanderToken)
	approveRec := httptest.NewRecorder()
	d.server.routes().ServeHTTP(approveRec, approveReq)

	if approveRec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for a non-owning approver, got %d", approveRec.Code)
	}
}
