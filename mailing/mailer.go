package mailing

import (
	"fmt"
	"io/fs"
	"strings"
	"time"

	"html/template"

	"github.com/eisenwinter/gotrxx/config"
	"github.com/eisenwinter/gotrxx/i18n"
	"github.com/eisenwinter/gotrxx/pkg/logging"
	"github.com/go-mail/mail"
	"github.com/jaytaylor/html2text"
)

type Mailer struct {
	noop          bool
	client        *mail.Dialer
	log           logging.Logger
	cfg           *config.Configuration
	registry      *i18n.TranslationRegistry
	emailTemplate *template.Template
}

func (m *Mailer) baseModel(title string, message string) map[string]interface{} {
	b := make(map[string]interface{})
	b["service_name"] = m.cfg.Behaviour.Name
	b["date"] = time.Now().Format("2006-01-02 15:04")
	b["site"] = m.cfg.Behaviour.Site
	b["title"] = title
	b["message"] = message
	return b
}

func (m *Mailer) SendInviteMail(email string, code string, language string) error {
	if m.noop {
		m.log.Info("skipping email `Invite` because noop is configured", "code", code)
		return nil
	}
	t, err := m.registry.TranslatorFor(language, "email.invite")
	if err != nil {
		t = m.registry.CreateVoidTranslator(language, "email.invite")
	}
	base := m.baseModel(t.T("title"), t.T("message"))
	base["link_text"] = t.T("link_text")
	base["link"] = fmt.Sprintf(
		"%s/account/signup?invite_code=%s",
		m.cfg.Behaviour.ServiceDomain,
		code,
	)
	base["token_text"] = t.T("token_text")
	base["token"] = code
	base["subject"] = t.T("subject")
	return m.send(email, t.T("subject"), base)
}

func (m *Mailer) SendConfirmMail(email string, code string, language string) error {
	if m.noop {
		m.log.Info("skipping email `Confirm` because noop is configured", "code", code)
		return nil
	}
	t, err := m.registry.TranslatorFor(language, "email.confirm")
	if err != nil {
		m.log.Error(
			"[i18n] unable to load translation for `email.confirm`",
			"ressource", "email.confirm",
			"language", language,
		)
		t = m.registry.CreateVoidTranslator(language, "email.confirm")
	}
	base := m.baseModel(t.T("title"), t.T("message"))
	base["link_text"] = t.T("link_text")
	base["link"] = fmt.Sprintf(
		"%s/account/confirm?confirm_token=%s",
		m.cfg.Behaviour.ServiceDomain,
		code,
	)
	base["token_text"] = t.T("token_text")
	base["token"] = code
	base["subject"] = t.T("subject")
	return m.send(email, t.T("subject"), base)
}

func (m *Mailer) SendPasswordRecoverMail(email string, code string, language string) error {
	if m.noop {
		m.log.Info(
			"skipping email `PasswordRecovery` because noop is configured",
			"code", code,
		)
		return nil
	}
	t, err := m.registry.TranslatorFor(language, "email.reset_password")
	if err != nil {
		t = m.registry.CreateVoidTranslator(language, "email.reset_password")
	}
	base := m.baseModel(t.T("title"), t.T("message"))
	base["link_text"] = t.T("link_text")
	base["link"] = fmt.Sprintf(
		"%s/account/recover?recovery_code=%s",
		m.cfg.Behaviour.ServiceDomain,
		code,
	)
	base["token_text"] = t.T("token_text")
	base["token"] = code
	base["subject"] = t.T("subject")
	return m.send(email, t.T("subject"), base)
}

func (m *Mailer) SendTestEmail(email string) error {
	base := m.baseModel("This is a test", "hey your email confirugation seems to be fine.")
	base["subject"] = "Your test email is here!"
	base["token"] = "test"
	base["token_text"] = "test"
	base["link"] = "w"
	base["link_text"] = "test"
	return m.send(email, "Your test email is here!", base)
}

func (m *Mailer) send(email string, subject string, viewModel map[string]interface{}) error {
	buffer := new(strings.Builder)
	err := m.emailTemplate.Execute(buffer, viewModel)
	if err != nil {
		return err
	}
	html := buffer.String()
	text, err := html2text.FromString(html, html2text.Options{PrettyTables: true})
	if err != nil {
		return err
	}
	msg := mail.NewMessage()
	msg.SetAddressHeader("From", m.cfg.SMTP.Address, m.cfg.SMTP.DisplayName)
	msg.SetAddressHeader("To", email, "")
	msg.SetHeader("Subject", subject)
	msg.SetBody("text/plain", text)
	msg.AddAlternative("text/html", html)
	return m.client.DialAndSend(msg)
}

func NewMailer(
	log logging.Logger,
	cfg *config.Configuration,
	registry *i18n.TranslationRegistry,
	files fs.FS,
) (*Mailer, error) {

	t, err := template.ParseFS(files, "template.html")
	if err != nil {
		return nil, err
	}
	s := &Mailer{
		noop:          cfg.SMTP.Enable,
		log:           log,
		registry:      registry,
		emailTemplate: t,
		cfg:           cfg,
	}
	if !s.noop {
		s.client = mail.NewDialer(
			cfg.SMTP.Host,
			cfg.SMTP.Port,
			cfg.SMTP.Username,
			cfg.SMTP.Password,
		)
	}
	return s, nil
}

func NewNoOpMailer() *Mailer {
	s := &Mailer{
		noop: true,
	}
	return s
}
