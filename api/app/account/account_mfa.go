package account

import (
	"encoding/base64"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	qrcode "github.com/skip2/go-qrcode"
)

func (a *AccountRessource) mfa(w http.ResponseWriter, r *http.Request) {
	ok, token := a.signedInUser(w, r)
	if !ok {
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}
	id, err := uuid.Parse(token.Subject())
	if err != nil {
		a.log.Error("unable to parse user id", "err", err)
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}
	mfa := a.userService.IsMFAEnabled(r.Context(), id)

	a.view(r.Context(), a.chageMfaTmpl, &changeMFAViewModel{
		MFAEnabled: mfa,
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
		a.log.Error("unable to parse user id", "err", err)
	}
	password := r.FormValue("password")
	err = a.userSignIn.Validate(r.Context(), id, password)
	if err != nil {
		a.view(r.Context(), a.chageMfaTmpl, &changeMFAViewModel{
			Error: "invalid_password",
		}, w)

		return
	}

	secret, uri, err := a.userService.ProvisionMFA(r.Context(), id)
	if err != nil {
		a.log.Error("could not provision mfa", "err", err)
		a.view(r.Context(), a.mfaSetupTmpl, &setupMFAViewModel{
			Error: "unknown",
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
		a.log.Error("could not generate qr code", "err", err)
		a.view(r.Context(), a.mfaSetupTmpl, &setupMFAViewModel{
			Secret: secret,
		}, w)
		return
	}
	qrb64 := base64.StdEncoding.EncodeToString(png)

	a.view(r.Context(), a.mfaSetupTmpl, &setupMFAViewModel{
		QR:     qrb64,
		Secret: secret,
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
		a.log.Error("setMFA: ParseForm failed", "err", err)
	}

	id, err := uuid.Parse(token.Subject())
	if err != nil {
		a.log.Error("unable to parse user id", "err", err)
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}

	secret := r.FormValue("secret")
	recoveryKey, err := a.userService.EnableMFA(r.Context(), id, secret)
	if err != nil {
		a.log.Error("could not enable MFA", "err", err)
		a.view(r.Context(), a.mfaSetupTmpl, &setupMFAViewModel{
			Error:  "unknown",
			Secret: secret,
		}, w)
		return
	}

	a.view(r.Context(), a.mfaSetupTmpl, &setupMFAViewModel{
		Successful:     true,
		SuccessMessage: "activated",
		RecoveryKey:    recoveryKey,
	}, w)
}

func (a *AccountRessource) disableMFA(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		a.log.Error("disableMFA: ParseForm failed", "err", err)
	}
	ok, token := a.signedInUser(w, r)
	if !ok {
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}

	pwd := r.FormValue("password")

	id, err := uuid.Parse(token.Subject())
	if err != nil {
		a.log.Error("unable to parse user id", "err", err)
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}
	err = a.userSignIn.Validate(r.Context(), id, pwd)
	if err != nil {
		a.log.Debug("user failed to authenticate", "err", err)
		a.view(r.Context(), a.chageMfaTmpl, &changeMFAViewModel{
			MFAEnabled: true,
			Error:      "invalid_password",
		}, w)
		return
	}
	err = a.userService.DisableMFA(r.Context(), id)
	if err != nil {
		a.view(r.Context(), a.chageMfaTmpl, &changeMFAViewModel{
			MFAEnabled: true,
			Error:      "unknown",
		}, w)
		return
	}
	mfa := a.userService.IsMFAEnabled(r.Context(), id)
	a.view(r.Context(), a.chageMfaTmpl, &changeMFAViewModel{
		MFAEnabled:     mfa,
		Successful:     true,
		SuccessMessage: "mfa_disabled",
	}, w)
}
