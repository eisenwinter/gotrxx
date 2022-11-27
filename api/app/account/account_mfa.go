package account

import (
	"encoding/base64"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"github.com/gorilla/csrf"
	qrcode "github.com/skip2/go-qrcode"
	"go.uber.org/zap"
)

func (a *AccountRessource) mfa(w http.ResponseWriter, r *http.Request) {
	ok, token := a.signedInUser(w, r)
	if !ok {
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}
	id, err := uuid.Parse(token.Subject())
	if err != nil {
		a.log.Error("unable to parse user id", zap.Error(err))
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}
	mfa := a.userService.IsMFAEnabled(r.Context(), id)

	a.view(r.Context(), a.chageMfaTmpl, map[string]interface{}{
		csrf.TemplateTag: csrf.TemplateField(r),
		"mfa_enabled":    mfa,
	}, w)
}

func (a *AccountRessource) provisionMFA(w http.ResponseWriter, r *http.Request) {
	ok, token := a.signedInUser(w, r)
	if !ok {
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}
	id, err := uuid.Parse(token.Subject())
	if err != nil {
		a.log.Error("unable to parse user id", zap.Error(err))
	}

	secret, uri, err := a.userService.ProvisionMFA(r.Context(), id)
	if err != nil {
		a.log.Error("could not provision mfa", zap.Error(err))
		a.view(r.Context(), a.mfaSetupTmpl, map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"error":          "unknown",
		}, w)
		return
	}
	//to avoid double encoding
	decodedValue, err := url.QueryUnescape(uri)
	if err != nil {
		decodedValue = uri
	}
	png, err := qrcode.Encode(decodedValue, qrcode.Medium, 256)
	if err != nil {
		a.log.Error("could not generate qr code", zap.Error(err))
		a.view(r.Context(), a.mfaSetupTmpl, map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"secret":         secret,
		}, w)
		return
	}
	qrb64 := base64.StdEncoding.EncodeToString(png)

	a.view(r.Context(), a.mfaSetupTmpl, map[string]interface{}{
		csrf.TemplateTag: csrf.TemplateField(r),
		"qr":             qrb64,
		"secret":         secret,
	}, w)

}

func (a *AccountRessource) setMFA(w http.ResponseWriter, r *http.Request) {
	ok, token := a.signedInUser(w, r)
	if !ok {
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}
	err := r.ParseForm()
	if err != nil {
		a.log.Error("setMFA: ParseForm failed", zap.Error(err))
	}

	id, err := uuid.Parse(token.Subject())
	if err != nil {
		a.log.Error("unable to parse user id", zap.Error(err))
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}
	secret := r.FormValue("secret")
	recoveryKey, err := a.userService.EnableMFA(r.Context(), id, secret)
	if err != nil {
		a.log.Error("could not enable MFA", zap.Error(err))
		a.view(r.Context(), a.mfaSetupTmpl, map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"error":          "unknown",
			"secret":         secret,
		}, w)
		return
	}

	a.view(r.Context(), a.mfaSetupTmpl, map[string]interface{}{
		csrf.TemplateTag:  csrf.TemplateField(r),
		"successful":      true,
		"success_message": "activated",
		"recovery_key":    recoveryKey,
	}, w)
}

func (a *AccountRessource) disableMFA(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		a.log.Error("disableMFA: ParseForm failed", zap.Error(err))
	}
	ok, token := a.signedInUser(w, r)
	if !ok {
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}

	pwd := r.FormValue("password")

	id, err := uuid.Parse(token.Subject())
	if err != nil {
		a.log.Error("unable to parse user id", zap.Error(err))
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}
	err = a.userSignIn.Validate(r.Context(), id, pwd)
	if err != nil {
		a.log.Debug("user failed to authenticate", zap.Error(err))
		a.view(r.Context(), a.chageMfaTmpl, map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"mfa_enabled":    true,
			"error":          "invalid_password",
		}, w)
		return
	}
	err = a.userService.DisableMFA(r.Context(), id)
	if err != nil {
		a.view(r.Context(), a.chageMfaTmpl, map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"mfa_enabled":    true,
			"error":          "unknown",
		}, w)
		return
	}
	mfa := a.userService.IsMFAEnabled(r.Context(), id)
	a.view(r.Context(), a.chageMfaTmpl, map[string]interface{}{
		csrf.TemplateTag:  csrf.TemplateField(r),
		"mfa_enabled":     mfa,
		"successful":      true,
		"success_message": "mfa_disabled",
	}, w)
}
