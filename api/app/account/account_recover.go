package account

import (
	"net/http"

	"github.com/gorilla/csrf"
	"go.uber.org/zap"
)

func (a *AccountRessource) forgottenPassword(w http.ResponseWriter, r *http.Request) {
	err := a.requestRecoverTmpl.Execute(w, map[string]interface{}{
		"i18n":           a.getTranslatorFor(r.Context(), "request_password_recovery"),
		csrf.TemplateTag: csrf.TemplateField(r),
	})
	if err != nil {
		a.log.Error("unable to render template for login page", zap.Error(err))
	}
}

func (a *AccountRessource) triggerPasswordRecovery(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		a.log.Error("triggerPasswordRecovery: ParseForm failed", zap.Error(err))
	}
	email := r.FormValue("email")
	if email == "" {
		err := a.requestRecoverTmpl.Execute(w, map[string]interface{}{
			"i18n":           a.getTranslatorFor(r.Context(), "request_password_recovery"),
			csrf.TemplateTag: csrf.TemplateField(r),
			"error":          "unknown_or_invalid_email",
		})
		if err != nil {
			a.log.Error("unable to render template for page", zap.Error(err))
		}
		return
	}
	id, found := a.userService.EmailToID(r.Context(), email)
	if !found {
		err := a.requestRecoverTmpl.Execute(w, map[string]interface{}{
			"i18n":           a.getTranslatorFor(r.Context(), "request_password_recovery"),
			csrf.TemplateTag: csrf.TemplateField(r),
			"error":          "unknown_or_invalid_email",
		})
		if err != nil {
			a.log.Error("unable to render template for page", zap.Error(err))
		}
		return
	}
	err = a.userService.TriggerPasswordRecovery(r.Context(), id)
	if err != nil {
		a.log.Error("TriggerPasswordRecovery failed", zap.Error(err))
		err := a.requestRecoverTmpl.Execute(w, map[string]interface{}{
			"i18n":           a.getTranslatorFor(r.Context(), "request_password_recovery"),
			csrf.TemplateTag: csrf.TemplateField(r),
			"error":          "unknown",
			"email":          email,
		})
		if err != nil {
			a.log.Error("unable to render template for page", zap.Error(err))
		}
		return
	}
	err = a.requestRecoverTmpl.Execute(w, map[string]interface{}{
		"i18n":            a.getTranslatorFor(r.Context(), "request_password_recovery"),
		csrf.TemplateTag:  csrf.TemplateField(r),
		"success_message": "password_recovery_sent",
		"successful":      true,
		"email":           email,
	})
	if err != nil {
		a.log.Error("unable to render template for page", zap.Error(err))
	}
}

func (a *AccountRessource) recover(w http.ResponseWriter, r *http.Request) {
	codes, ok := r.URL.Query()["recovery_code"]
	recoverCode := ""
	if ok && len(codes) > 0 {
		recoverCode = codes[0]
	}
	if recoverCode == "" {
		err := a.recoverTemplate.Execute(w, map[string]interface{}{
			"i18n":           a.getTranslatorFor(r.Context(), "recover_password"),
			"error":          "no_token",
			csrf.TemplateTag: csrf.TemplateField(r),
		})
		if err != nil {
			a.log.Error("unable to render template for confirm page", zap.Error(err))
		}
		return
	}

	err := a.recoverTemplate.Execute(w, map[string]interface{}{
		"i18n":           a.getTranslatorFor(r.Context(), "recover_password"),
		"recovery_token": recoverCode,
		csrf.TemplateTag: csrf.TemplateField(r),
	})
	if err != nil {
		a.log.Error("unable to render template for confirm page", zap.Error(err))
	}
}

func (a *AccountRessource) recoverPassword(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		a.log.Error("recoverPassword: ParseForm failed", zap.Error(err))
	}
	rtoken := r.FormValue("recovery_token")
	email := r.FormValue("email")
	if rtoken == "" {
		err := a.recoverTemplate.Execute(w, map[string]interface{}{
			"i18n":  a.getTranslatorFor(r.Context(), "recover_password"),
			"error": "no_token",
			"email": email,
		})
		if err != nil {
			a.log.Error("unable to render template for confirm page", zap.Error(err))
		}
		return
	}

	if email == "" {
		err := a.recoverTemplate.Execute(w, map[string]interface{}{
			"i18n":           a.getTranslatorFor(r.Context(), "recover_password"),
			"error":          "invalid_email",
			"recovery_token": rtoken,
			csrf.TemplateTag: csrf.TemplateField(r),
		})
		if err != nil {
			a.log.Error("unable to render template for page", zap.Error(err))
		}
		return
	}
	password := r.FormValue("password")

	if password == "" || len(password) < a.cfg.PasswordMinLength {
		err := a.recoverTemplate.Execute(w, map[string]interface{}{
			"i18n":           a.getTranslatorFor(r.Context(), "recover_password"),
			"error":          "invalid_password",
			"recovery_token": rtoken,
			csrf.TemplateTag: csrf.TemplateField(r),
		})
		if err != nil {
			a.log.Error("unable to render template for page", zap.Error(err))
		}
		return
	}

	id, err := a.userService.RecoverPassword(r.Context(), email, rtoken)
	if err != nil {
		err := a.recoverTemplate.Execute(w, map[string]interface{}{
			"i18n":           a.getTranslatorFor(r.Context(), "recover_password"),
			"error":          "invalid_token",
			csrf.TemplateTag: csrf.TemplateField(r),
		})
		if err != nil {
			a.log.Error("unable to render template for page", zap.Error(err))
		}
		return
	}
	err = a.userService.ChangePassword(r.Context(), id, password)
	if err != nil {
		err := a.recoverTemplate.Execute(w, map[string]interface{}{
			"i18n":           a.getTranslatorFor(r.Context(), "recover_password"),
			"error":          "unknown",
			"recovery_token": rtoken,
			csrf.TemplateTag: csrf.TemplateField(r),
		})
		if err != nil {
			a.log.Error("unable to render template for page", zap.Error(err))
		}
		return
	}
	err = a.recoverTemplate.Execute(w, map[string]interface{}{
		"i18n":            a.getTranslatorFor(r.Context(), "recover_password"),
		"success_message": "password_changed",
		"successful":      true,
		csrf.TemplateTag:  csrf.TemplateField(r),
	})
	if err != nil {
		a.log.Error("unable to render template for page", zap.Error(err))
	}

}
