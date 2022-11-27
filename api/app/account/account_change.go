package account

import (
	"errors"
	"net/http"
	"regexp"

	"github.com/eisenwinter/gotrxx/tokens"
	"github.com/eisenwinter/gotrxx/user"
	"github.com/google/uuid"
	"github.com/gorilla/csrf"
	"go.uber.org/zap"
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

	a.view(r.Context(), a.changeEmailTemplate, map[string]interface{}{
		csrf.TemplateTag: csrf.TemplateField(r),
		"email":          email.(string),
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
		a.view(r.Context(), a.changeEmailTemplate, map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"email":          email,
			"error":          "invalid_email",
		}, w)

		return
	}
	id, err := uuid.Parse(token.Subject())
	if err != nil {
		a.view(r.Context(), a.changeEmailTemplate, map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"email":          email,
			"error":          "unknown",
		}, w)
		return
	}
	err = a.userService.ChangeEmail(r.Context(), id, email)
	if err != nil {
		if errors.Is(user.ErrEntityInvalidTransition, err) {
			a.view(r.Context(), a.changeEmailTemplate, map[string]interface{}{
				csrf.TemplateTag: csrf.TemplateField(r),
				"email":          email,
				"error":          "email_already_in_use",
			}, w)

			return
		}
		a.view(r.Context(), a.changeEmailTemplate, map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"email":          email,
			"error":          "unknown",
		}, w)
		return
	}
	user, err := a.userSignIn.UserFromSubject(r.Context(), id)
	if err != nil {
		a.log.Error("could not get user from subject", zap.Error(err))
	} else {
		auth, err := a.autService.VerifyUserAuthorization(r.Context(), id, gotrxxClientID)
		if err != nil {
			a.log.Error("could not get user auth for gotrxx", zap.Error(err))
			return
		}
		_, err = a.issueUserCookie(r.Context(), user, auth, false, w)
		if err != nil {
			a.log.Error("could not reissue user cookie", zap.Error(err))
		}

	}

	a.view(r.Context(), a.changeEmailTemplate, map[string]interface{}{
		csrf.TemplateTag:  csrf.TemplateField(r),
		"email":           email,
		"success_message": "email_changed",
		"successful":      true,
	}, w)

}

func (a *AccountRessource) changePassword(w http.ResponseWriter, r *http.Request) {
	ok, _ := a.signedInUser(w, r)
	if !ok {
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}
	a.view(r.Context(), a.changePasswordTemplate, map[string]interface{}{
		csrf.TemplateTag: csrf.TemplateField(r),
	}, w)
}

func (a *AccountRessource) updatePassword(w http.ResponseWriter, r *http.Request) {
	ok, token := a.signedInUser(w, r)
	if !ok {
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}
	password := r.FormValue("new_password")
	if password == "" || len(password) < a.cfg.PasswordMinLength {
		a.view(r.Context(), a.changePasswordTemplate, map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"error":          "password_guidlines",
		}, w)

		return
	}
	id, err := uuid.Parse(token.Subject())
	if err != nil {
		a.view(r.Context(), a.changePasswordTemplate, map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"error":          "unknown",
		}, w)
		return
	}
	err = a.userService.ChangePassword(r.Context(), id, password)
	if err != nil {
		a.view(r.Context(), a.changePasswordTemplate, map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"error":          "unknown",
		}, w)
		return
	}

	a.view(r.Context(), a.changePasswordTemplate, map[string]interface{}{
		csrf.TemplateTag:  csrf.TemplateField(r),
		"success_message": "password_changed",
		"successful":      true,
	}, w)
}
