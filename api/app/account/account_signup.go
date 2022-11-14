package account

import (
	"errors"
	"net/http"

	"github.com/eisenwinter/gotrxx/user"
	"github.com/gorilla/csrf"
	"go.uber.org/zap"
)

func (a *AccountRessource) signup(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		a.log.Error("signup ParseForm failed", zap.Error(err))
	}
	invite := r.FormValue("invite_code")
	email := r.FormValue("email")
	phone := r.FormValue("phone")
	password := r.FormValue("password")
	if email == "" || !emailRegex.MatchString(email) {
		err := a.signUpTmpl.Execute(w, map[string]interface{}{
			"i18n":             a.getTranslatorFor(r.Context(), "signup"),
			"error":            "invalid_email",
			"show_invite_code": invite != "",
			"email":            email,
			"password":         password,
			"invite_code":      invite,

			csrf.TemplateTag: csrf.TemplateField(r),
		})
		if err != nil {
			a.log.Error("unable to render template for signup page", zap.Error(err))
		}
		return
	}

	if invite == "" && a.cfg.InviteOnly {
		err := a.signUpTmpl.Execute(w, map[string]interface{}{
			"i18n":             a.getTranslatorFor(r.Context(), "signup"),
			"error":            "invite_code_required",
			"show_invite_code": true,
			"email":            email,
			"password":         password,
			csrf.TemplateTag:   csrf.TemplateField(r),
		})
		if err != nil {
			a.log.Error("unable to render template for signup page", zap.Error(err))
		}
		return
	}
	var phoneNr *string
	if phone != "" {
		phoneNr = &phone
	}
	if invite != "" {
		_, err = a.userService.RegisterFromInvite(r.Context(), email, password, phoneNr, invite)
		if errors.Is(user.ErrTokenExpired, err) {
			err := a.signUpTmpl.Execute(w, map[string]interface{}{
				"i18n":             a.getTranslatorFor(r.Context(), "signup"),
				"error":            "invite_code_expired",
				"show_invite_code": true,
				"invite_code":      invite,
				"email":            email,
				"password":         password,
				csrf.TemplateTag:   csrf.TemplateField(r),
			})
			if err != nil {
				a.log.Error("unable to render template for signup page", zap.Error(err))
			}
			return
		}

	} else {
		_, err = a.userService.RegisterUser(r.Context(), email, password, phoneNr)
	}
	if err != nil {
		if errors.Is(user.ErrPasswordGuidelines, err) {
			err := a.signUpTmpl.Execute(w, map[string]interface{}{
				"i18n":             a.getTranslatorFor(r.Context(), "signup"),
				"error":            "password_guidlines",
				"show_invite_code": true,
				"invite_code":      invite,
				"email":            email,
				"password":         password,
				csrf.TemplateTag:   csrf.TemplateField(r),
			})
			if err != nil {
				a.log.Error("unable to render template for signup page", zap.Error(err))
			}
			return
		}
		if errors.Is(user.ErrEntityAlreadyExists, err) {
			err := a.signUpTmpl.Execute(w, map[string]interface{}{
				"i18n":             a.getTranslatorFor(r.Context(), "signup"),
				"error":            "email_already_used",
				"show_invite_code": true,
				"invite_code":      invite,
				"email":            email,
				"password":         password,
				csrf.TemplateTag:   csrf.TemplateField(r),
			})
			if err != nil {
				a.log.Error("unable to render template for signup page", zap.Error(err))
			}
			return
		}
		a.log.Error("unexpected user sign up error", zap.Error(err))
	}
	successMessage := "user_needs_confirm"
	if a.cfg.AutoConfirmUsers {
		successMessage = "welcome_text"
	}
	err = a.signUpTmpl.Execute(w, map[string]interface{}{
		"i18n":            a.getTranslatorFor(r.Context(), "signup"),
		"successful":      true,
		"success_message": successMessage,
		csrf.TemplateTag:  csrf.TemplateField(r),
	})
	if err != nil {
		a.log.Error("unable to render template for signup page", zap.Error(err))
	}
}

func (a *AccountRessource) signupPage(w http.ResponseWriter, r *http.Request) {
	codes, ok := r.URL.Query()["invite_code"]
	inviteCode := ""
	if ok && len(codes) > 0 {
		inviteCode = codes[0]
	}
	showInviteCode := a.cfg.InviteOnly || inviteCode != ""
	err := a.signUpTmpl.Execute(w, map[string]interface{}{
		"i18n":             a.getTranslatorFor(r.Context(), "signup"),
		"show_invite_code": showInviteCode,
		"invite_code":      inviteCode,
		csrf.TemplateTag:   csrf.TemplateField(r),
	})
	if err != nil {
		a.log.Error("unable to render template for signup page", zap.Error(err))
	}
}
