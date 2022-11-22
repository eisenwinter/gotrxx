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
	err := a.changeEmailTemplate.Execute(w, map[string]interface{}{
		"i18n":           a.getTranslatorFor(r.Context(), "change_email"),
		csrf.TemplateTag: csrf.TemplateField(r),
		"email":          email.(string),
	})
	if err != nil {
		a.log.Error("unable to render template for page", zap.Error(err))
	}
}

func (a *AccountRessource) updateEmail(w http.ResponseWriter, r *http.Request) {
	ok, token := a.signedInUser(w, r)
	if !ok {
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}
	email := r.FormValue("email")
	if email == "" || !emailRegex.MatchString(email) {
		err := a.changeEmailTemplate.Execute(w, map[string]interface{}{
			"i18n":           a.getTranslatorFor(r.Context(), "change_email"),
			csrf.TemplateTag: csrf.TemplateField(r),
			"email":          email,
			"error":          "invalid_email",
		})
		if err != nil {
			a.log.Error("unable to render template for page", zap.Error(err))
		}
		return
	}
	id, err := uuid.Parse(token.Subject())
	if err != nil {
		err := a.changeEmailTemplate.Execute(w, map[string]interface{}{
			"i18n":           a.getTranslatorFor(r.Context(), "change_email"),
			csrf.TemplateTag: csrf.TemplateField(r),
			"email":          email,
			"error":          "unknown",
		})
		if err != nil {
			a.log.Error("unable to render template for page", zap.Error(err))
		}
		return
	}
	err = a.userService.ChangeEmail(r.Context(), id, email)
	if err != nil {
		if errors.Is(user.ErrEntityInvalidTransition, err) {
			err := a.changeEmailTemplate.Execute(w, map[string]interface{}{
				"i18n":           a.getTranslatorFor(r.Context(), "change_email"),
				csrf.TemplateTag: csrf.TemplateField(r),
				"email":          email,
				"error":          "email_already_in_use",
			})
			if err != nil {
				a.log.Error("unable to render template for page", zap.Error(err))
			}
			return
		}
		err := a.changeEmailTemplate.Execute(w, map[string]interface{}{
			"i18n":           a.getTranslatorFor(r.Context(), "change_email"),
			csrf.TemplateTag: csrf.TemplateField(r),
			"email":          email,
			"error":          "unknown",
		})
		if err != nil {
			a.log.Error("unable to render template for page", zap.Error(err))
		}
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
	err = a.changeEmailTemplate.Execute(w, map[string]interface{}{
		"i18n":            a.getTranslatorFor(r.Context(), "change_email"),
		csrf.TemplateTag:  csrf.TemplateField(r),
		"email":           email,
		"success_message": "email_changed",
		"successful":      true,
	})
	if err != nil {
		a.log.Error("unable to render template for page", zap.Error(err))
	}

}

func (a *AccountRessource) changePassword(w http.ResponseWriter, r *http.Request) {
	ok, _ := a.signedInUser(w, r)
	if !ok {
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}
	err := a.changePasswordTemplate.Execute(w, map[string]interface{}{
		"i18n":           a.getTranslatorFor(r.Context(), "change_password"),
		csrf.TemplateTag: csrf.TemplateField(r),
	})
	if err != nil {
		a.log.Error("unable to render template for page", zap.Error(err))
	}

}

func (a *AccountRessource) updatePassword(w http.ResponseWriter, r *http.Request) {
	ok, token := a.signedInUser(w, r)
	if !ok {
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}
	password := r.FormValue("new_password")
	if password == "" || len(password) < a.cfg.PasswordMinLength {
		err := a.changePasswordTemplate.Execute(w, map[string]interface{}{
			"i18n":           a.getTranslatorFor(r.Context(), "change_password"),
			csrf.TemplateTag: csrf.TemplateField(r),
			"error":          "password_guidlines",
		})
		if err != nil {
			a.log.Error("unable to render template for page", zap.Error(err))
		}
		return
	}
	id, err := uuid.Parse(token.Subject())
	if err != nil {
		err := a.changePasswordTemplate.Execute(w, map[string]interface{}{
			"i18n":           a.getTranslatorFor(r.Context(), "change_password"),
			csrf.TemplateTag: csrf.TemplateField(r),
			"error":          "unknown",
		})
		if err != nil {
			a.log.Error("unable to render template for page", zap.Error(err))
		}
		return
	}
	err = a.userService.ChangePassword(r.Context(), id, password)
	if err != nil {
		err := a.changePasswordTemplate.Execute(w, map[string]interface{}{
			"i18n":           a.getTranslatorFor(r.Context(), "change_password"),
			csrf.TemplateTag: csrf.TemplateField(r),
			"error":          "unknown",
		})
		if err != nil {
			a.log.Error("unable to render template for page", zap.Error(err))
		}
		return
	}
	err = a.changePasswordTemplate.Execute(w, map[string]interface{}{
		"i18n":            a.getTranslatorFor(r.Context(), "change_password"),
		csrf.TemplateTag:  csrf.TemplateField(r),
		"success_message": "password_changed",
		"successful":      true,
	})
	if err != nil {
		a.log.Error("unable to render template for page", zap.Error(err))
	}
}
