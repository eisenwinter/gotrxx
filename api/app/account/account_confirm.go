package account

import (
	"errors"
	"net/http"

	"github.com/eisenwinter/gotrxx/user"
)

func (a *AccountRessource) confirm(w http.ResponseWriter, r *http.Request) {
	codes, ok := r.URL.Query()["confirm_token"]
	confirmToken := ""
	if ok && len(codes) > 0 {
		confirmToken = codes[0]
	}
	if confirmToken == "" {
		a.view(r.Context(), a.confirmTemplate, &confirmViewModel{Error: "no_token"}, w)

		return
	}
	err := a.userService.ConfirmUser(r.Context(), confirmToken)
	if err != nil {
		if errors.Is(user.ErrEntityDoesNotExist, err) {
			a.view(
				r.Context(),
				a.confirmTemplate,
				&confirmViewModel{Error: "does_not_exists_or_already_consumed"},
				w,
			)
			return
		}
		a.log.Error("confirm user: unexpected error on conrfirm", "err", err)
		a.view(r.Context(), a.confirmTemplate, &confirmViewModel{Error: "unknown"}, w)
		return
	}

	a.view(r.Context(), a.confirmTemplate, &confirmViewModel{}, w)
}
