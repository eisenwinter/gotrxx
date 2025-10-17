package account

import (
	"fmt"

	"github.com/google/safehtml"
	"github.com/google/safehtml/template"
)

var qrCodeField = template.Must(
	template.New("qrCode").Parse(`<img  width="256" height="256" src="{{.}}" />`),
)

func qrCodeTag(qr string) safehtml.HTML {
	if qr == "" {
		return template.MustParseAndExecuteToHTML(``)
	}
	field, err := qrCodeField.ExecuteToHTML(fmt.Sprintf("data:image/png;base64,%s", qr))
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
	Password  string
}

func (s *signinViewModel) ViewData() map[string]interface{} {
	return map[string]interface{}{
		"returnUrl": s.ReturnURL,
		"otp":       s.Otp,
		"error":     s.Error,
		"email":     s.Email,
		"password":  s.Password,
	}
}

type signupViewModel struct {
	Error          string
	Successful     bool
	SuccessMessage string
	Email          string
	Password       string
	ShowInviteCode bool
	InviteCode     string
}

func (s *signupViewModel) ViewData() map[string]interface{} {
	return map[string]interface{}{
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
	Error          string
	Email          string
	Successful     bool
	SuccessMessage string
}

func (t *triggerPasswordRecoveryViewModel) ViewData() map[string]interface{} {
	return map[string]interface{}{
		"successful":      t.Successful,
		"success_message": t.SuccessMessage,
		"error":           t.Error,
		"email":           t.Email,
	}
}

type recoverPasswordViewModel struct {
	RecoveryToken  string
	Error          string
	Email          string
	Successful     bool
	SuccessMessage string
}

func (r *recoverPasswordViewModel) ViewData() map[string]interface{} {
	return map[string]interface{}{
		"successful":      r.Successful,
		"success_message": r.SuccessMessage,
		"error":           r.Error,
		"recovery_token":  r.RecoveryToken,
		"email":           r.Email,
	}
}

type changeMFAViewModel struct {
	MFAEnabled     bool
	Error          string
	Successful     bool
	SuccessMessage string
}

func (c *changeMFAViewModel) ViewData() map[string]interface{} {
	return map[string]interface{}{
		"successful":      c.Successful,
		"success_message": c.SuccessMessage,
		"error":           c.Error,
		"mfa_enabled":     c.MFAEnabled,
	}
}

type setupMFAViewModel struct {
	Error          string
	Secret         string
	Successful     bool
	SuccessMessage string
	RecoveryKey    string
	QR             string
}

func (s *setupMFAViewModel) ViewData() map[string]interface{} {
	return map[string]interface{}{
		"successful":      s.Successful,
		"success_message": s.SuccessMessage,
		"error":           s.Error,
		"qr":              qrCodeTag(s.QR),
		"secret":          s.Secret,
		"recovery_key":    s.RecoveryKey,
		"password":        "",
	}
}

type sendInviteViewModel struct {
	Email          string
	Error          string
	Successful     bool
	SuccessMessage string
}

func (s *sendInviteViewModel) ViewData() map[string]interface{} {
	return map[string]interface{}{
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
	Email          string
	Error          string
	Successful     bool
	SuccessMessage string
}

func (c *changeEmailViewModel) ViewData() map[string]interface{} {
	return map[string]interface{}{
		"successful":      c.Successful,
		"success_message": c.SuccessMessage,
		"error":           c.Error,
		"email":           c.Email,
	}
}

type changePasswordViewModel struct {
	Email          string
	Error          string
	Successful     bool
	SuccessMessage string
}

func (c *changePasswordViewModel) ViewData() map[string]interface{} {
	return map[string]interface{}{
		"successful":      c.Successful,
		"success_message": c.SuccessMessage,
		"error":           c.Error,
		"email":           c.Email,
	}
}

type userPageViewModel struct {
	Email     string
	CanInvite bool
}

func (u *userPageViewModel) ViewData() map[string]interface{} {
	return map[string]interface{}{
		"email":      u.Email,
		"can_invite": u.CanInvite,
	}
}

type fourOFourViewModel struct {
}

func (*fourOFourViewModel) ViewData() map[string]interface{} {
	return map[string]interface{}{}
}

type forgottenPasswordViewModel struct {
	Email string
}

func (f *forgottenPasswordViewModel) ViewData() map[string]interface{} {
	return map[string]interface{}{
		"email": f.Email,
	}
}
