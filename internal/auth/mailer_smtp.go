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

var _ ConfirmationMailer = (*SMTPMailer)(nil)

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
