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
		a.view(r.Context(), a.signUpTmpl, map[string]interface{}{
			csrf.TemplateTag:   csrf.TemplateField(r),
			"error":            "invalid_email",
			"show_invite_code": true,
			"invite_code":      invite,
			"email":            email,
			"password":         password,
		}, w)
		return
	}

	if invite == "" && a.cfg.InviteOnly {
		a.view(r.Context(), a.signUpTmpl, map[string]interface{}{
			csrf.TemplateTag:   csrf.TemplateField(r),
			"error":            "invite_code_required",
			"show_invite_code": true,
			"invite_code":      invite,
			"email":            email,
			"password":         password,
		}, w)
		return

	}
	var phoneNr *string
	if phone != "" {
		phoneNr = &phone
	}
	if invite != "" {
		_, err = a.userService.RegisterFromInvite(r.Context(), email, password, phoneNr, invite)
		if errors.Is(user.ErrTokenExpired, err) {
			a.view(r.Context(), a.signUpTmpl, map[string]interface{}{
				csrf.TemplateTag:   csrf.TemplateField(r),
				"error":            "invite_code_expired",
				"show_invite_code": true,
				"invite_code":      invite,
				"email":            email,
				"password":         password,
			}, w)
			return
		}

	} else {
		_, err = a.userService.RegisterUser(r.Context(), email, password, phoneNr)
	}
	if err != nil {
		if errors.Is(user.ErrPasswordGuidelines, err) {
			a.view(r.Context(), a.signUpTmpl, map[string]interface{}{
				csrf.TemplateTag:   csrf.TemplateField(r),
				"error":            "password_guidlines",
				"show_invite_code": true,
				"invite_code":      invite,
				"email":            email,
				"password":         password,
			}, w)
			return
		}
		if errors.Is(user.ErrEntityAlreadyExists, err) {
			a.view(r.Context(), a.signUpTmpl, map[string]interface{}{
				csrf.TemplateTag:   csrf.TemplateField(r),
				"error":            "email_already_used",
				"show_invite_code": true,
				"invite_code":      invite,
				"email":            email,
				"password":         password,
			}, w)
			return
		}
		a.log.Error("unexpected user sign up error", zap.Error(err))
	}
	successMessage := "user_needs_confirm"
	if a.cfg.AutoConfirmUsers {
		successMessage = "welcome_text"
	}

	a.view(r.Context(), a.signUpTmpl, map[string]interface{}{
		csrf.TemplateTag:  csrf.TemplateField(r),
		"error":           "email_already_used",
		"successful":      true,
		"success_message": successMessage,
	}, w)

}

func (a *AccountRessource) signupPage(w http.ResponseWriter, r *http.Request) {
	codes, ok := r.URL.Query()["invite_code"]
	inviteCode := ""
	if ok && len(codes) > 0 {
		inviteCode = codes[0]
	}
	showInviteCode := a.cfg.InviteOnly || inviteCode != ""

	a.view(r.Context(), a.signUpTmpl, map[string]interface{}{
		csrf.TemplateTag:   csrf.TemplateField(r),
		"show_invite_code": showInviteCode,
		"invite_code":      inviteCode,
	}, w)
}
