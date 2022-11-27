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
		a.view(r.Context(), a.inviteTmpl, map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"email":          email,
			"error":          "invalid_email",
		}, w)
		return
	}
	err := a.userService.InviteUser(r.Context(), email)
	if err != nil {
		a.log.Error("could not invite user", zap.Error(err))
		a.view(r.Context(), a.inviteTmpl, map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"error":          "unknown",
		}, w)

		return
	}

	//successfull
	a.view(r.Context(), a.inviteTmpl, map[string]interface{}{
		csrf.TemplateTag:  csrf.TemplateField(r),
		"successful":      true,
		"success_message": "invite_sent",
	}, w)
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

	a.view(r.Context(), a.inviteTmpl, map[string]interface{}{
		csrf.TemplateTag: csrf.TemplateField(r),
	}, w)
}
