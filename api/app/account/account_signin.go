package account

import (
	"errors"
	"net/http"
	"net/url"

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
	_, err = url.ParseRequestURI(returnURL)
	if err != nil {
		returnURL = "/account/"
	}

	res, err := a.userSignIn.SignInMFA(r.Context(), email, password, otp)
	if err != nil {
		if errors.Is(user.ErrEntityOperationForbidden, err) {
			//locked or unconfirmed
			a.renderLoginErrorView(w, r, returnURL, email, "locked_user", false)
			return
		}
		if errors.Is(user.ErrMFARequired, err) {
			err = a.userSignIn.InitializeMFA(r.Context(), email)
			if err != nil {
				a.log.Error("unable prepare MFA", zap.Error(err))
			}
			//mfa
			a.renderLoginErrorView(w, r, returnURL, email, "mfa", true)
			return
		}
		if errors.Is(user.ErrInvalidOTP, err) {
			err = a.userSignIn.InitializeMFA(r.Context(), email)
			if err != nil {
				a.log.Error("unable prepare MFA", zap.Error(err))
			}
			a.renderLoginErrorView(w, r, returnURL, email, "invalid_otp", true)

			return
		}
		if errors.Is(user.ErrEntityDoesNotExist, err) {
			a.renderLoginErrorView(w, r, returnURL, email, "unknown_or_invalid", false)
			return
		}
		if errors.Is(user.ErrInvalidCredentials, err) {
			a.renderLoginErrorView(w, r, returnURL, email, "unknown_or_invalid", false)
			return
		}
		a.renderLoginErrorView(w, r, returnURL, email, "unknown", false)
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
	http.Redirect(w, r, returnURL, http.StatusFound)

}

func (a *AccountRessource) renderLoginErrorView(
	w http.ResponseWriter,
	r *http.Request,
	returnURL string,
	email string,
	errorString string,
	otp bool,
) {
	err := a.loginTmpl.Execute(w, map[string]interface{}{
		"i18n":           a.getTranslatorFor(r.Context(), "signin"),
		"returnUrl":      returnURL,
		"error":          errorString,
		"otp":            otp,
		"email":          email,
		csrf.TemplateTag: csrf.TemplateField(r),
	})
	if err != nil {
		a.log.Error("unable to render template for login page", zap.Error(err))
	}
}

func (a *AccountRessource) signinPage(w http.ResponseWriter, r *http.Request) {
	urls, ok := r.URL.Query()["return_url"]
	returnURL := "/account/"
	if ok && len(urls) > 0 {
		_, err := url.ParseRequestURI(urls[0])
		if err != nil {
			a.log.Warn("unacceptable redirect_url", zap.String("redirect_url", urls[0]))
		} else {
			returnURL = urls[0]
		}
	}
	if ok, _ := a.signedInUser(w, r); ok {
		http.Redirect(w, r, returnURL, http.StatusFound)
		return
	}

	err := a.loginTmpl.Execute(w, map[string]interface{}{
		"i18n":           a.getTranslatorFor(r.Context(), "signin"),
		"returnUrl":      returnURL,
		"otp":            false,
		csrf.TemplateTag: csrf.TemplateField(r),
	})
	if err != nil {
		a.log.Error("unable to render template for login page", zap.Error(err))
	}
}
