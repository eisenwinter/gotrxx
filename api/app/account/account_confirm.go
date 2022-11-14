package account

import (
	"errors"
	"net/http"

	"github.com/eisenwinter/gotrxx/user"
	"go.uber.org/zap"
)

func (a *AccountRessource) confirm(w http.ResponseWriter, r *http.Request) {
	codes, ok := r.URL.Query()["confirm_token"]
	confirmToken := ""
	if ok && len(codes) > 0 {
		confirmToken = codes[0]
	}
	if confirmToken == "" {
		err := a.confirmTemplate.Execute(w, map[string]interface{}{
			"i18n":  a.getTranslatorFor(r.Context(), "confirm"),
			"error": "no_token",
		})
		if err != nil {
			a.log.Error("unable to render template for confirm page", zap.Error(err))
		}
		return
	}
	err := a.userService.ConfirmUser(r.Context(), confirmToken)
	if err != nil {
		if errors.Is(user.ErrEntityDoesNotExist, err) {
			err := a.confirmTemplate.Execute(w, map[string]interface{}{
				"i18n":  a.getTranslatorFor(r.Context(), "confirm"),
				"error": "does_not_exists_or_already_consumed",
			})
			if err != nil {
				a.log.Error("unable to render template for confirm page", zap.Error(err))
			}
			return
		}
		a.log.Error("confirm user: unexpected error on conrfirm", zap.Error(err))
		err := a.errorTemplate.Execute(w, map[string]interface{}{
			"i18n":  a.getTranslatorFor(r.Context(), "error"),
			"error": "unknown",
		})
		if err != nil {
			a.log.Error("unable to render template for confirm page", zap.Error(err))
		}
		return
	}

	err = a.confirmTemplate.Execute(w, map[string]interface{}{
		"i18n": a.getTranslatorFor(r.Context(), "confirm"),
	})
	if err != nil {
		a.log.Error("unable to render template for confirm page", zap.Error(err))
	}
}
