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

		a.view(r.Context(), a.signUpTmpl, &signupViewModel{
			CsrfToken:      csrf.Token(r),
			Error:          "invalid_email",
			ShowInviteCode: true,
			InviteCode:     invite,
			Email:          email,
			Password:       password,
		}, w)
		return
	}

	if invite == "" && a.cfg.InviteOnly {
		a.view(r.Context(), a.signUpTmpl, &signupViewModel{
			CsrfToken:      csrf.Token(r),
			Error:          "invite_code_required",
			ShowInviteCode: true,
			InviteCode:     invite,
			Email:          email,
			Password:       password,
		}, w)
		return

	}
	var phoneNr *string
	if phone != "" {
		phoneNr = &phone
	}
	if invite != "" {
		_, err = a.userService.RegisterFromInvite(r.Context(), email, password, phoneNr, invite)
		if errors.Is(user.ErrEntityDoesNotExist, err) {
			a.view(r.Context(), a.signUpTmpl, &signupViewModel{
				CsrfToken:      csrf.Token(r),
				Error:          "invalid_invite_code",
				ShowInviteCode: true,
				InviteCode:     invite,
				Email:          email,
				Password:       password,
			}, w)
			return
		}
		if errors.Is(user.ErrTokenExpired, err) {
			a.view(r.Context(), a.signUpTmpl, &signupViewModel{
				CsrfToken:      csrf.Token(r),
				Error:          "invite_code_expired",
				ShowInviteCode: true,
				InviteCode:     invite,
				Email:          email,
				Password:       password,
			}, w)
			return
		}

	} else {
		_, err = a.userService.RegisterUser(r.Context(), email, password, phoneNr)
	}
	if err != nil {
		if errors.Is(user.ErrPasswordGuidelines, err) {
			a.view(r.Context(), a.signUpTmpl, &signupViewModel{
				CsrfToken:      csrf.Token(r),
				Error:          "password_guidlines",
				ShowInviteCode: true,
				InviteCode:     invite,
				Email:          email,
				Password:       password,
			}, w)
			return
		}
		if errors.Is(user.ErrEntityAlreadyExists, err) {
			a.view(r.Context(), a.signUpTmpl, &signupViewModel{
				CsrfToken:      csrf.Token(r),
				Error:          "email_already_used",
				ShowInviteCode: true,
				InviteCode:     invite,
				Email:          email,
				Password:       password,
			}, w)
			return
		}
		a.log.Error("unexpected user sign up error", zap.Error(err))
	}
	successMessage := "user_needs_confirm"
	if a.cfg.AutoConfirmUsers {
		successMessage = "welcome_text"
	}

	a.view(r.Context(), a.signUpTmpl, &signupViewModel{
		CsrfToken:      csrf.Token(r),
		Successful:     true,
		SuccessMessage: successMessage,
	}, w)

}

func (a *AccountRessource) signupPage(w http.ResponseWriter, r *http.Request) {
	codes, ok := r.URL.Query()["invite_code"]
	inviteCode := ""
	if ok && len(codes) > 0 {
		inviteCode = codes[0]
	}
	showInviteCode := a.cfg.InviteOnly || inviteCode != ""

	a.view(r.Context(), a.signUpTmpl, &signupViewModel{
		CsrfToken:      csrf.Token(r),
		ShowInviteCode: showInviteCode,
		InviteCode:     inviteCode,
	}, w)
}
