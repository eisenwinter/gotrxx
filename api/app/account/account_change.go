package account

import (
	"errors"
	"net/http"
	"regexp"

	"github.com/eisenwinter/gotrxx/tokens"
	"github.com/eisenwinter/gotrxx/user"
	"github.com/google/uuid"
	"github.com/gorilla/csrf"
)

// https://www.w3.org/TR/2016/REC-html51-20161101/sec-forms.html#email-state-typeemail
var emailRegex = regexp.MustCompile(
	"^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
)

func (a *AccountRessource) changeEmail(w http.ResponseWriter, r *http.Request) {
	ok, token := a.signedInUser(w, r)
	if !ok {
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}
	email, _ := token.Get(tokens.ClaimEmail)

	a.view(r.Context(), a.changeEmailTemplate, &changeEmailViewModel{
		CsrfToken: csrf.Token(r),
		Email:     email.(string),
	}, w)
}

func (a *AccountRessource) updateEmail(w http.ResponseWriter, r *http.Request) {
	ok, token := a.signedInUser(w, r)
	if !ok {
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}

	email := r.FormValue("email")
	if email == "" || !emailRegex.MatchString(email) {
		a.view(r.Context(), a.changeEmailTemplate, &changeEmailViewModel{
			CsrfToken: csrf.Token(r),
			Email:     email,
			Error:     "invalid_email",
		}, w)

		return
	}
	id, err := uuid.Parse(token.Subject())
	if err != nil {
		a.view(r.Context(), a.changeEmailTemplate, &changeEmailViewModel{
			CsrfToken: csrf.Token(r),
			Email:     email,
			Error:     "unknown",
		}, w)
		return
	}
	password := r.FormValue("password")

	err = a.userSignIn.Validate(r.Context(), id, password)
	if err != nil {
		a.view(r.Context(), a.changeEmailTemplate, &changePasswordViewModel{
			CsrfToken: csrf.Token(r),
			Email:     email,
			Error:     "invalid_password",
		}, w)

		return
	}

	err = a.userService.ChangeEmail(r.Context(), id, email)
	if err != nil {
		if errors.Is(user.ErrEntityInvalidTransition, err) {
			a.view(r.Context(), a.changeEmailTemplate, &changeEmailViewModel{
				CsrfToken: csrf.Token(r),
				Email:     email,
				Error:     "email_already_in_use",
			}, w)

			return
		}
		a.view(r.Context(), a.changeEmailTemplate, &changeEmailViewModel{
			CsrfToken: csrf.Token(r),
			Email:     email,
			Error:     "unknown",
		}, w)
		return
	}
	user, err := a.userSignIn.UserFromSubject(r.Context(), id)
	if err != nil {
		a.log.Error("could not get user from subject", "err", err)
	} else {
		auth, err := a.autService.VerifyUserAuthorization(r.Context(), id, gotrxxClientID)
		if err != nil {
			a.log.Error("could not get user auth for gotrxx", "err", err)
			return
		}
		_, err = a.issueUserCookie(r.Context(), user, auth, false, w)
		if err != nil {
			a.log.Error("could not reissue user cookie", "err", err)
		}

	}

	a.view(r.Context(), a.changeEmailTemplate, &changeEmailViewModel{
		CsrfToken:      csrf.Token(r),
		Email:          email,
		SuccessMessage: "email_changed",
		Successful:     true,
	}, w)

}

func (a *AccountRessource) changePassword(w http.ResponseWriter, r *http.Request) {
	ok, _ := a.signedInUser(w, r)
	if !ok {
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}
	a.view(r.Context(), a.changePasswordTemplate, &changePasswordViewModel{
		CsrfToken: csrf.Token(r),
	}, w)
}

func (a *AccountRessource) updatePassword(w http.ResponseWriter, r *http.Request) {
	ok, token := a.signedInUser(w, r)
	if !ok {
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}
	oldPassword := r.FormValue("old_password")
	if oldPassword == "" {
		a.view(r.Context(), a.changePasswordTemplate, &changePasswordViewModel{
			CsrfToken: csrf.Token(r),
			Error:     "invalid_old_password",
		}, w)

		return
	}

	id, err := uuid.Parse(token.Subject())
	if err != nil {
		a.log.Error("unable to parse user id", "err", err)
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}

	err = a.userSignIn.Validate(r.Context(), id, oldPassword)
	if err != nil {
		a.view(r.Context(), a.changePasswordTemplate, &changePasswordViewModel{
			CsrfToken: csrf.Token(r),
			Error:     "invalid_old_password",
		}, w)

		return
	}

	password := r.FormValue("new_password")
	passwordAgain := r.FormValue("new_password_again")
	if password != passwordAgain {
		a.view(r.Context(), a.changePasswordTemplate, &changePasswordViewModel{
			CsrfToken: csrf.Token(r),
			Error:     "passwords_do_not_match",
		}, w)

		return
	}
	if password == "" || len(password) < a.cfg.PasswordMinLength {
		a.view(r.Context(), a.changePasswordTemplate, &changePasswordViewModel{
			CsrfToken: csrf.Token(r),
			Error:     "password_guidlines",
		}, w)

		return
	}

	err = a.userService.ChangePassword(r.Context(), id, password)
	if err != nil {
		a.view(r.Context(), a.changePasswordTemplate, &changePasswordViewModel{
			CsrfToken: csrf.Token(r),
			Error:     "unknown",
		}, w)
		return
	}

	a.view(r.Context(), a.changePasswordTemplate, &changePasswordViewModel{
		CsrfToken:      csrf.Token(r),
		SuccessMessage: "password_changed",
		Successful:     true,
	}, w)
}
