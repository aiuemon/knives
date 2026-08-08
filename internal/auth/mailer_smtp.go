package auth

import (
	"context"
	"fmt"
	"time"

	gomail "github.com/wneessen/go-mail"
)

// SMTPMailerConfig configures SMTPMailer from the SMTP_* / MAIL_FROM
// environment variables (.env.example).
type SMTPMailerConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

// SMTPMailer is the production ConfirmationMailer implementation
// (3.4節-4: 確認メール送信).
type SMTPMailer struct {
	client *gomail.Client
	from   string
}

var (
	_ ConfirmationMailer       = (*SMTPMailer)(nil)
	_ SignupVerificationMailer = (*SMTPMailer)(nil)
)

func NewSMTPMailer(cfg SMTPMailerConfig) (*SMTPMailer, error) {
	opts := []gomail.Option{
		gomail.WithPort(cfg.Port),
		gomail.WithTimeout(10 * time.Second),
	}
	if cfg.Username != "" {
		opts = append(opts,
			gomail.WithSMTPAuth(gomail.SMTPAuthPlain),
			gomail.WithUsername(cfg.Username),
			gomail.WithPassword(cfg.Password),
		)
	}
	client, err := gomail.NewClient(cfg.Host, opts...)
	if err != nil {
		return nil, err
	}
	return &SMTPMailer{client: client, from: cfg.From}, nil
}

// SendAccountLinkConfirmation is the legacy one-click flow
// (auth_settings.require_reauth_for_account_link = false): opening the
// link immediately approves the link, so the copy says so explicitly.
func (m *SMTPMailer) SendAccountLinkConfirmation(ctx context.Context, toEmail, confirmURL string) error {
	msg := gomail.NewMsg()
	if err := msg.From(m.from); err != nil {
		return err
	}
	if err := msg.To(toEmail); err != nil {
		return err
	}
	msg.Subject("【knives】ログイン方法の追加を確認してください")
	msg.SetBodyString(gomail.TypeTextPlain, fmt.Sprintf(
		"このメールアドレスに新しいログイン方法を追加するリクエストがありました。\n"+
			"心当たりがある場合は、%d分以内に以下のリンクを開いて承認してください。\n\n"+
			"%s\n\n"+
			"心当たりがない場合は、このメールを無視してください。アカウントに変更は加えられません。",
		int(DefaultPendingLinkTTL.Minutes()), confirmURL,
	))
	return m.client.DialAndSendWithContext(ctx, msg)
}

// SendAccountLinkReviewNotice is the secure, reauth-required flow
// (auth_settings.require_reauth_for_account_link = true, default): opening
// the link does NOT approve anything by itself — it only takes the
// recipient to a page where they must first log in with their existing
// method before they can review and approve the request.
func (m *SMTPMailer) SendAccountLinkReviewNotice(ctx context.Context, toEmail, reviewURL string) error {
	msg := gomail.NewMsg()
	if err := msg.From(m.from); err != nil {
		return err
	}
	if err := msg.To(toEmail); err != nil {
		return err
	}
	msg.Subject("【knives】ログイン方法の追加リクエストがあります")
	msg.SetBodyString(gomail.TypeTextPlain, fmt.Sprintf(
		"このメールアドレスに新しいログイン方法を追加するリクエストがありました。\n"+
			"心当たりがある場合は、いつも通りログインした上で、以下のページから承認してください\n"+
			"(このメール内のリンクだけでは承認は完了しません)。\n\n"+
			"%s\n\n"+
			"心当たりがない場合は、このメールを無視してください。ログインしない限りアカウントに変更は加えられません。",
		reviewURL,
	))
	return m.client.DialAndSendWithContext(ctx, msg)
}

func (m *SMTPMailer) SendSignupVerification(ctx context.Context, toEmail, verifyURL string) error {
	msg := gomail.NewMsg()
	if err := msg.From(m.from); err != nil {
		return err
	}
	if err := msg.To(toEmail); err != nil {
		return err
	}
	msg.Subject("【knives】メールアドレスの確認")
	msg.SetBodyString(gomail.TypeTextPlain, fmt.Sprintf(
		"このメールアドレスでアカウント登録のリクエストがありました。\n"+
			"%d分以内に以下のリンクを開いて登録を完了してください。\n\n"+
			"%s\n\n"+
			"心当たりがない場合は、このメールを無視してください。登録は完了しません。",
		int(DefaultPendingLinkTTL.Minutes()), verifyURL,
	))
	return m.client.DialAndSendWithContext(ctx, msg)
}
