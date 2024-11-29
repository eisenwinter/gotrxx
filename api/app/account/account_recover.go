package account

import (
	"net/http"

	"github.com/gorilla/csrf"
)

func (a *AccountRessource) forgottenPassword(w http.ResponseWriter, r *http.Request) {
	a.view(r.Context(), a.requestRecoverTmpl, &forgottenPasswordViewModel{
		CsrfToken: csrf.Token(r),
	}, w)
}

func (a *AccountRessource) triggerPasswordRecovery(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		a.log.Error("triggerPasswordRecovery: ParseForm failed", "err", err)
	}
	email := r.FormValue("email")
	if email == "" {
		a.view(r.Context(), a.requestRecoverTmpl, &triggerPasswordRecoveryViewModel{
			CsrfToken: csrf.Token(r),
			Error:     "unknown_or_invalid_email",
		}, w)
		return
	}
	id, found := a.userService.EmailToID(r.Context(), email)
	if !found {
		a.view(r.Context(), a.requestRecoverTmpl, &triggerPasswordRecoveryViewModel{
			CsrfToken: csrf.Token(r),
			Error:     "unknown_or_invalid_email",
		}, w)
		return
	}
	err = a.userService.TriggerPasswordRecovery(r.Context(), id)
	if err != nil {
		a.log.Error("`TriggerPasswordRecovery` failed", "err", err)
		a.view(r.Context(), a.requestRecoverTmpl, &triggerPasswordRecoveryViewModel{
			CsrfToken: csrf.Token(r),
			Error:     "unknown",
			Email:     email,
		}, w)
		return
	}

	a.view(r.Context(), a.requestRecoverTmpl, &triggerPasswordRecoveryViewModel{
		CsrfToken:      csrf.Token(r),
		SuccessMessage: "password_recovery_sent",
		Successful:     true,
		Email:          email,
	}, w)

}

func (a *AccountRessource) recover(w http.ResponseWriter, r *http.Request) {
	codes, ok := r.URL.Query()["recovery_code"]
	recoverCode := ""
	if ok && len(codes) > 0 {
		recoverCode = codes[0]
	}
	if recoverCode == "" {
		a.view(r.Context(), a.recoverTemplate, &recoverPasswordViewModel{
			CsrfToken: csrf.Token(r),
			Error:     "no_token",
		}, w)
		return
	}
	a.view(r.Context(), a.recoverTemplate, &recoverPasswordViewModel{
		CsrfToken:     csrf.Token(r),
		RecoveryToken: recoverCode,
	}, w)
}

func (a *AccountRessource) recoverPassword(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		a.log.Error("recoverPassword: ParseForm failed", "err", err)
	}
	rtoken := r.FormValue("recovery_token")
	email := r.FormValue("email")
	if rtoken == "" {
		a.view(r.Context(), a.recoverTemplate, &recoverPasswordViewModel{
			CsrfToken: csrf.Token(r),
			Error:     "no_token",
			Email:     email,
		}, w)

		return
	}

	if email == "" {
		a.view(r.Context(), a.recoverTemplate, &recoverPasswordViewModel{
			CsrfToken:     csrf.Token(r),
			Error:         "invalid_email",
			RecoveryToken: rtoken,
		}, w)
		return
	}
	password := r.FormValue("password")

	if password == "" || len(password) < a.cfg.PasswordMinLength {
		a.view(r.Context(), a.recoverTemplate, &recoverPasswordViewModel{
			CsrfToken:     csrf.Token(r),
			Error:         "invalid_password",
			RecoveryToken: rtoken,
		}, w)
		return
	}

	id, err := a.userService.RecoverPassword(r.Context(), email, rtoken)
	if err != nil {
		a.view(r.Context(), a.recoverTemplate, &recoverPasswordViewModel{
			CsrfToken: csrf.Token(r),
			Error:     "invalid_token",
		}, w)
		return
	}
	err = a.userService.ChangePassword(r.Context(), id, password)
	if err != nil {
		a.view(r.Context(), a.recoverTemplate, &recoverPasswordViewModel{
			CsrfToken:     csrf.Token(r),
			Error:         "unknown",
			RecoveryToken: rtoken,
		}, w)
		return
	}

	a.view(r.Context(), a.recoverTemplate, &recoverPasswordViewModel{
		CsrfToken:      csrf.Token(r),
		SuccessMessage: "password_changed",
		Successful:     true,
	}, w)
}
