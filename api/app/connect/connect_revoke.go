package connect

import (
	"net/http"

	"github.com/eisenwinter/gotrxx/tokens"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func (c *ConnnectRessource) revoke(w http.ResponseWriter, r *http.Request) {
	j, _, err := jwtauth.FromContext(r.Context())
	if err != nil {
		err = render.Render(w, r, createStdError(stdInvalidRequest, http.StatusBadRequest, ""))
		if err != nil {
			c.logger.Error("unable to render response", zap.Error(err))
		}
		c.logger.Error("errors getting jwt in revoke endpoint")
		return
	}
	err = r.ParseForm()
	//we gonna look for https://datatracker.ietf.org/doc/html/rfc7009#section-2.1
	if err != nil {
		c.logger.Error("error on parsing form in revoke endpoint", zap.Error(err))
		err = render.Render(w, r, createStdError(stdInvalidRequest, http.StatusBadRequest, ""))
		if err != nil {
			c.logger.Error("unable to render response", zap.Error(err))
		}
		return
	}
	clientID, ok := j.Get(tokens.ClaimClientID)
	if !ok {
		err = render.Render(w, r, createStdError(stdInvalidRequest, http.StatusBadRequest, ""))
		if err != nil {
			c.logger.Error("unable to render response", zap.Error(err))
		}
		c.logger.Error("no client_id in JWT")
		return
	}
	app, err := c.appService.ApplicationByClientID(r.Context(), clientID.(string))
	if err != nil {
		err = render.Render(w, r, createStdError(stdInvalidRequest, http.StatusBadRequest, ""))
		if err != nil {
			c.logger.Error("unable to render response", zap.Error(err))
		}
		c.logger.Error("unable to get app from client_id")
		return
	}
	if app.IsRetired() {
		render.Respond(w, r, createStdError(stdInvalidClient, http.StatusBadRequest, "invalid application"))
		return
	}
	if app.HasSecret() {
		clientSecret := r.FormValue("client_secret")
		if !app.ValidateClientSecret(clientSecret) {
			render.Respond(w, r, createStdError(stdInvalidRequest, http.StatusBadRequest, ""))
			return
		}
	}
	token := r.FormValue("token")
	if token == "" {
		err = render.Render(w, r, createStdError(stdInvalidRequest, http.StatusBadRequest, "client_id field not supplied"))
		if err != nil {
			c.logger.Error("unable to render response", zap.Error(err))
		}
		return
	}
	tokenTypeHint := r.FormValue("token_type_hint")
	if tokenTypeHint != "refresh_token" {

		err = render.Render(w, r, createStdError(stdUnspportedTokenType, http.StatusBadRequest, ""))
		if err != nil {
			c.logger.Error("unable to render response", zap.Error(err))
		}
		return
	}
	autId, ok := j.Get(tokens.ClaimAuthorization)
	if !ok {
		err = render.Render(w, r, createStdError(stdInvalidRequest, http.StatusBadRequest, ""))
		if err != nil {
			c.logger.Error("unable to render response", zap.Error(err))
		}
		c.logger.Error("no authorization id in JWT")
		return
	}
	id, err := uuid.Parse(autId.(string))
	if err != nil {
		err = render.Render(w, r, createStdError(stdInvalidRequest, http.StatusBadRequest, ""))
		if err != nil {
			c.logger.Error("unable to render response", zap.Error(err))
		}
		c.logger.Error("malformed authorization id in JWT")
		return
	}
	err = c.rotator.RevokeCommonToken(r.Context(), tokens.RefreshTokenType, token, id)
	if err != nil {
		err = render.Render(w, r, createStdError(stdInvalidRequest, http.StatusBadRequest, "invalid revocation"))
		if err != nil {
			c.logger.Error("unable to render response", zap.Error(err))
		}
		return
	}

	w.WriteHeader(200)
}
