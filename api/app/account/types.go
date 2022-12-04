package account

import (
	"github.com/google/safehtml"
	"github.com/google/safehtml/template"
	"github.com/gorilla/csrf"
)

var csrfTokenField = template.Must(template.New("csrfToken").Parse(`<input type="hidden" name="gorilla.csrf.Token" value="{{.}}">`))

func csfrTokenTag(token string) safehtml.HTML {
	field, err := csrfTokenField.ExecuteToHTML(token)
	if err != nil {
		return template.MustParseAndExecuteToHTML(``)
	}
	return field
}

type viewModeler interface {
	ViewData() map[string]interface{}
}

type signinViewModel struct {
	ReturnURL string
	Error     string
	Otp       bool
	Email     string
	CsrfToken string
	Password  string
}

func (s *signinViewModel) ViewData() map[string]interface{} {
	return map[string]interface{}{
		"returnUrl":      s.ReturnURL,
		"otp":            s.Otp,
		"error":          s.Error,
		"email":          s.Email,
		"password":       s.Password,
		csrf.TemplateTag: csfrTokenTag(s.CsrfToken),
	}
}

type signupViewModel struct {
	Error          string
	Successful     bool
	SuccessMessage string
	Email          string
	Password       string
	CsrfToken      string
	ShowInviteCode bool
	InviteCode     string
}

func (s *signupViewModel) ViewData() map[string]interface{} {
	return map[string]interface{}{
		csrf.TemplateTag:   csfrTokenTag(s.CsrfToken),
		"successful":       s.Successful,
		"success_message":  s.SuccessMessage,
		"error":            s.Error,
		"email":            s.Email,
		"password":         s.Password,
		"invite_code":      s.InviteCode,
		"show_invite_code": s.ShowInviteCode,
	}
}

type triggerPasswordRecoveryViewModel struct {
	CsrfToken      string
	Error          string
	Email          string
	Successful     bool
	SuccessMessage string
}

func (t *triggerPasswordRecoveryViewModel) ViewData() map[string]interface{} {
	return map[string]interface{}{
		csrf.TemplateTag:  csfrTokenTag(t.CsrfToken),
		"successful":      t.Successful,
		"success_message": t.SuccessMessage,
		"error":           t.Error,
		"email":           t.Email,
	}
}

type recoverPasswordViewModel struct {
	CsrfToken      string
	RecoveryToken  string
	Error          string
	Email          string
	Successful     bool
	SuccessMessage string
}

func (r *recoverPasswordViewModel) ViewData() map[string]interface{} {
	return map[string]interface{}{
		csrf.TemplateTag:  csfrTokenTag(r.CsrfToken),
		"successful":      r.Successful,
		"success_message": r.SuccessMessage,
		"error":           r.Error,
		"recovery_token":  r.RecoveryToken,
		"email":           r.Email,
	}
}

type changeMFAViewModel struct {
	CsrfToken      string
	MFAEnabled     bool
	Error          string
	Successful     bool
	SuccessMessage string
}

func (c *changeMFAViewModel) ViewData() map[string]interface{} {
	return map[string]interface{}{
		csrf.TemplateTag:  csfrTokenTag(c.CsrfToken),
		"successful":      c.Successful,
		"success_message": c.SuccessMessage,
		"error":           c.Error,
		"mfa_enabled":     c.MFAEnabled,
	}
}

type setupMFAViewModel struct {
	CsrfToken      string
	Error          string
	Secret         string
	Successful     bool
	SuccessMessage string
	RecoveryKey    string
	QR             string
}

func (s *setupMFAViewModel) ViewData() map[string]interface{} {
	return map[string]interface{}{
		csrf.TemplateTag:  csfrTokenTag(s.CsrfToken),
		"successful":      s.Successful,
		"success_message": s.SuccessMessage,
		"error":           s.Error,
		"qr":              s.QR,
		"secret":          s.Secret,
		"recovery_key":    s.RecoveryKey,
	}
}

type sendInviteViewModel struct {
	CsrfToken      string
	Email          string
	Error          string
	Successful     bool
	SuccessMessage string
}

func (s *sendInviteViewModel) ViewData() map[string]interface{} {
	return map[string]interface{}{
		csrf.TemplateTag:  csfrTokenTag(s.CsrfToken),
		"successful":      s.Successful,
		"success_message": s.SuccessMessage,
		"error":           s.Error,
		"email":           s.Email,
	}
}

type confirmViewModel struct {
	Error string
}

func (c *confirmViewModel) ViewData() map[string]interface{} {
	return map[string]interface{}{
		"error": c.Error,
	}
}

type changeEmailViewModel struct {
	CsrfToken      string
	Email          string
	Error          string
	Successful     bool
	SuccessMessage string
}

func (c *changeEmailViewModel) ViewData() map[string]interface{} {
	return map[string]interface{}{
		csrf.TemplateTag:  csfrTokenTag(c.CsrfToken),
		"successful":      c.Successful,
		"success_message": c.SuccessMessage,
		"error":           c.Error,
		"email":           c.Email,
	}
}

type changePasswordViewModel struct {
	CsrfToken      string
	Email          string
	Error          string
	Successful     bool
	SuccessMessage string
}

func (c *changePasswordViewModel) ViewData() map[string]interface{} {
	return map[string]interface{}{
		csrf.TemplateTag:  csfrTokenTag(c.CsrfToken),
		"successful":      c.Successful,
		"success_message": c.SuccessMessage,
		"error":           c.Error,
		"email":           c.Email,
	}
}

type userPageViewModel struct {
	CsrfToken string
	Email     string
	CanInvite bool
}

func (u *userPageViewModel) ViewData() map[string]interface{} {
	return map[string]interface{}{
		csrf.TemplateTag: csfrTokenTag(u.CsrfToken),
		"email":          u.Email,
		"can_invite":     u.CanInvite,
	}
}

type fourOFourViewModel struct {
}

func (f *fourOFourViewModel) ViewData() map[string]interface{} {
	return map[string]interface{}{}
}

type forgottenPasswordViewModel struct {
	CsrfToken string
	Email     string
}

func (f *forgottenPasswordViewModel) ViewData() map[string]interface{} {
	return map[string]interface{}{
		csrf.TemplateTag: csfrTokenTag(f.CsrfToken),
		"email":          f.Email,
	}
}
