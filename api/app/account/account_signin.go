package account

import (
	"errors"
	"net/http"

	"github.com/eisenwinter/gotrxx/authorization"
	"github.com/eisenwinter/gotrxx/user"
	"github.com/go-chi/render"
	"github.com/gorilla/csrf"
	"go.uber.org/zap"
)

func (a *AccountRessource) signin(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		a.log.Error("signin: ParseForm failed", zap.Error(err))
	}
	email := r.FormValue("email")
	password := r.FormValue("password")
	otp := r.FormValue("otp")
	returnURL := r.FormValue("return_url")
	rememberMe := r.FormValue("remember_me")

	res, err := a.userSignIn.SignInMFA(r.Context(), email, password, otp)
	if err != nil {
		if errors.Is(user.ErrEntityOperationForbidden, err) {
			//locked or unconfirmed
			a.view(r.Context(), a.loginTmpl, &signinViewModel{
				CsrfToken: csrf.Token(r),
				ReturnURL: returnURL,
				Error:     "locked_user",
				Otp:       false,
				Email:     email,
			}, w)
			return
		}
		if errors.Is(user.ErrMFARequired, err) {
			err = a.userSignIn.InitializeMFA(r.Context(), email)
			if err != nil {
				a.log.Error("unable prepare MFA", zap.Error(err))
			}
			//mfa
			a.view(r.Context(), a.loginTmpl, &signinViewModel{
				CsrfToken: csrf.Token(r),
				ReturnURL: returnURL,
				Error:     "mfa",
				Otp:       true,
				Email:     email,
			}, w)
			return
		}
		if errors.Is(user.ErrInvalidOTP, err) {
			err = a.userSignIn.InitializeMFA(r.Context(), email)
			if err != nil {
				a.log.Error("unable prepare MFA", zap.Error(err))
			}
			a.view(r.Context(), a.loginTmpl, &signinViewModel{
				CsrfToken: csrf.Token(r),
				ReturnURL: returnURL,
				Error:     "invalid_otp",
				Otp:       true,
				Email:     email,
			}, w)
			return
		}
		if errors.Is(user.ErrEntityDoesNotExist, err) {
			a.view(r.Context(), a.loginTmpl, &signinViewModel{
				CsrfToken: csrf.Token(r),
				ReturnURL: returnURL,
				Error:     "unknown_or_invalid",
				Otp:       false,
				Email:     email,
			}, w)
			return
		}
		if errors.Is(user.ErrInvalidCredentials, err) {
			a.view(r.Context(), a.loginTmpl, &signinViewModel{
				CsrfToken: csrf.Token(r),
				ReturnURL: returnURL,
				Error:     "unknown_or_invalid",
				Otp:       false,
				Email:     email,
			}, w)
			return
		}
		a.view(r.Context(), a.loginTmpl, &signinViewModel{
			CsrfToken: csrf.Token(r),
			ReturnURL: returnURL,
			Error:     "unknown",
			Otp:       false,
			Email:     email,
		}, w)
		//everything below here is unexepcted
		a.log.Info("failed signin due to unexpected error", zap.Error(err))
		return
	}

	auth, err := a.autService.VerifyUserAuthorization(r.Context(), res.UserID, gotrxxClientID)
	if err != nil && errors.Is(authorization.ErrUngrantedImplicitAutoGrant, err) {
		auth, err = a.autService.ImplicitAuthorization(r.Context(), res.UserID, gotrxxClientID, "")
		if err != nil {
			a.log.Error("user login page: grantig implicit authorization failed", zap.Error(err))
			render.Respond(w, r, http.StatusInternalServerError)
			return
		}
	} else if err != nil {
		a.log.Error("user login page: verifing authorization failed", zap.Error(err))
		render.Respond(w, r, http.StatusInternalServerError)
		return
	}

	_, err = a.issueUserCookie(r.Context(), res, auth, rememberMe == "true", w)
	if err != nil {
		render.Respond(w, r, http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, sanitizeReturnURL(returnURL, "/account/"), http.StatusFound)

}

func (a *AccountRessource) signinPage(w http.ResponseWriter, r *http.Request) {
	urls, ok := r.URL.Query()["return_url"]
	returnURL := "/account/"
	if ok && len(urls) > 0 {
		returnURL = sanitizeReturnURL(urls[0], "/account/")
	}
	if ok, _ := a.signedInUser(w, r); ok {
		http.Redirect(w, r, returnURL, http.StatusFound)
		return
	}

	a.view(r.Context(), a.loginTmpl, &signinViewModel{
		ReturnURL: returnURL,
		Otp:       false,
		CsrfToken: csrf.Token(r),
	}, w)
}
