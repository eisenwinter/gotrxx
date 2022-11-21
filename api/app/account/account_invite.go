package account

import (
	"net/http"

	"github.com/gorilla/csrf"
	"go.uber.org/zap"
)

func (a *AccountRessource) sendInvite(w http.ResponseWriter, r *http.Request) {
	ok, token := a.signedInUser(w, r)
	if !ok {
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}
	if !a.canUserInvite(r.Context(), token) {
		http.Redirect(w, r, "/account", http.StatusFound)
		return
	}

	email := r.FormValue("email")
	if email == "" || !emailRegex.MatchString(email) {
		err := a.inviteTmpl.Execute(w, map[string]interface{}{
			"i18n":           a.getTranslatorFor(r.Context(), "invite"),
			csrf.TemplateTag: csrf.TemplateField(r),
			"email":          email,
			"error":          "invalid_email",
		})
		if err != nil {
			a.log.Error("unable to render template for page", zap.Error(err))
		}
		return
	}
	err := a.userService.InviteUser(r.Context(), email)
	if err != nil {
		a.log.Error("could not invite user", zap.Error(err))
		err = a.mfaSetupTmpl.Execute(w, map[string]interface{}{
			"i18n":           a.getTranslatorFor(r.Context(), "invite"),
			csrf.TemplateTag: csrf.TemplateField(r),
			"error":          "unknown",
		})
		if err != nil {
			a.log.Error("unable to render template page", zap.Error(err))
		}
		return
	}

	//successfull
	err = a.inviteTmpl.Execute(w, map[string]interface{}{
		"i18n":            a.getTranslatorFor(r.Context(), "invite"),
		csrf.TemplateTag:  csrf.TemplateField(r),
		"successful":      true,
		"success_message": "invite_sent",
	})
	if err != nil {
		a.log.Error("unable to render template page", zap.Error(err))
	}
}

func (a *AccountRessource) invitePage(w http.ResponseWriter, r *http.Request) {
	ok, token := a.signedInUser(w, r)
	if !ok {
		http.Redirect(w, r, "/account/signin", http.StatusFound)
		return
	}
	if !a.canUserInvite(r.Context(), token) {
		http.Redirect(w, r, "/account", http.StatusFound)
		return
	}
	err := a.inviteTmpl.Execute(w, map[string]interface{}{
		"i18n":           a.getTranslatorFor(r.Context(), "invite"),
		csrf.TemplateTag: csrf.TemplateField(r),
	})
	if err != nil {
		a.log.Error("unable to render template for invite page", zap.Error(err))
	}
}
