package account

import (
	"net/http"

	"github.com/gorilla/csrf"
	"go.uber.org/zap"
)

func (a *AccountRessource) forgottenPassword(w http.ResponseWriter, r *http.Request) {
	a.view(r.Context(), a.requestRecoverTmpl, map[string]interface{}{
		csrf.TemplateTag: csrf.TemplateField(r),
	}, w)
}

func (a *AccountRessource) triggerPasswordRecovery(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		a.log.Error("triggerPasswordRecovery: ParseForm failed", zap.Error(err))
	}
	email := r.FormValue("email")
	if email == "" {
		a.view(r.Context(), a.requestRecoverTmpl, map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"error":          "unknown_or_invalid_email",
		}, w)
		return
	}
	id, found := a.userService.EmailToID(r.Context(), email)
	if !found {
		a.view(r.Context(), a.requestRecoverTmpl, map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"error":          "unknown_or_invalid_email",
		}, w)
		return
	}
	err = a.userService.TriggerPasswordRecovery(r.Context(), id)
	if err != nil {
		a.log.Error("TriggerPasswordRecovery failed", zap.Error(err))
		a.view(r.Context(), a.requestRecoverTmpl, map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"error":          "unknown",
			"email":          email,
		}, w)
		return
	}

	a.view(r.Context(), a.requestRecoverTmpl, map[string]interface{}{
		csrf.TemplateTag:  csrf.TemplateField(r),
		"success_message": "password_recovery_sent",
		"successful":      true,
		"email":           email,
	}, w)

}

func (a *AccountRessource) recover(w http.ResponseWriter, r *http.Request) {
	codes, ok := r.URL.Query()["recovery_code"]
	recoverCode := ""
	if ok && len(codes) > 0 {
		recoverCode = codes[0]
	}
	if recoverCode == "" {
		a.view(r.Context(), a.recoverTemplate, map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"error":          "no_token",
		}, w)
		return
	}
	a.view(r.Context(), a.recoverTemplate, map[string]interface{}{
		csrf.TemplateTag: csrf.TemplateField(r),
		"recovery_token": recoverCode,
	}, w)
}

func (a *AccountRessource) recoverPassword(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		a.log.Error("recoverPassword: ParseForm failed", zap.Error(err))
	}
	rtoken := r.FormValue("recovery_token")
	email := r.FormValue("email")
	if rtoken == "" {
		a.view(r.Context(), a.recoverTemplate, map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"error":          "no_token",
			"email":          email,
		}, w)

		return
	}

	if email == "" {
		a.view(r.Context(), a.recoverTemplate, map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"error":          "invalid_email",
			"recovery_token": rtoken,
		}, w)
		return
	}
	password := r.FormValue("password")

	if password == "" || len(password) < a.cfg.PasswordMinLength {
		a.view(r.Context(), a.recoverTemplate, map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"error":          "invalid_password",
			"recovery_token": rtoken,
		}, w)
		return
	}

	id, err := a.userService.RecoverPassword(r.Context(), email, rtoken)
	if err != nil {
		a.view(r.Context(), a.recoverTemplate, map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"error":          "invalid_token",
		}, w)
		return
	}
	err = a.userService.ChangePassword(r.Context(), id, password)
	if err != nil {
		a.view(r.Context(), a.recoverTemplate, map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"error":          "unknown",
			"recovery_token": rtoken,
		}, w)
		return
	}

	a.view(r.Context(), a.recoverTemplate, map[string]interface{}{
		csrf.TemplateTag:  csrf.TemplateField(r),
		"success_message": "password_changed",
		"successful":      true,
	}, w)
}
