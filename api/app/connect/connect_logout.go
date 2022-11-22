package connect

import (
	"errors"
	"net/http"
	"time"

	"github.com/eisenwinter/gotrxx/application"
	"github.com/eisenwinter/gotrxx/tokens"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func (c *ConnnectRessource) logout(w http.ResponseWriter, r *http.Request) {
	suppliedJwt, _, err := jwtauth.FromContext(r.Context())
	if err != nil {
		err = render.Render(w, r, createStdError(stdInvalidRequest, http.StatusBadRequest, ""))
		if err != nil {
			c.logger.Error("unable to render response", zap.Error(err))
		}
		c.logger.Error("errors getting jwt in logout endpoint")
		return
	}
	autID, ok := suppliedJwt.Get(tokens.ClaimAuthorization)
	if !ok {
		err = render.Render(w, r, createStdError(stdInvalidRequest, http.StatusBadRequest, ""))
		if err != nil {
			c.logger.Error("unable to render response", zap.Error(err))
		}
		c.logger.Error("no authorization id in JWT")
		return
	}
	id, err := uuid.Parse(autID.(string))
	if err != nil {
		err = render.Render(w, r, createStdError(stdInvalidRequest, http.StatusBadRequest, ""))
		if err != nil {
			c.logger.Error("unable to render response", zap.Error(err))
		}
		c.logger.Error("malformed authorization id in JWT")
		return
	}

	err = r.ParseForm()
	if err != nil {
		c.logger.Error("error on parsing form in logout endpoint", zap.Error(err))
	}
	clientID := r.FormValue("client_id")
	if clientID == "" {
		err = render.Render(
			w,
			r,
			createStdError(
				stdInvalidRequest,
				http.StatusBadRequest,
				"client_id field not supplied",
			),
		)
		if err != nil {
			c.logger.Error("unable to render response", zap.Error(err))
		}
		return
	}
	logoutURI := r.FormValue("logout_uri")
	app, err := c.appService.ApplicationByClientID(r.Context(), clientID)
	if err != nil {
		if errors.Is(application.ErrNotFound, err) {
			render.Respond(
				w,
				r,
				createStdError(stdInvalidClient, http.StatusBadRequest, "invalid client_id"),
			)
			return
		}
		c.logger.Error("logout: unexpected error getting application", zap.Error(err))
		render.Respond(
			w,
			r,
			createStdError(stdInternalServerError, http.StatusInternalServerError, ""),
		)
		return
	}
	if logoutURI != "" {
		if !app.IsAllowedRedirectURI(logoutURI) {
			render.Respond(
				w,
				r,
				createStdError(stdInvalidRequest, http.StatusBadRequest, "invalid logout_uri"),
			)
			return
		}
	} else {
		logoutURI = "/account/signin"
	}
	err = c.rotator.RevokeCommonTokensForAuthorization(r.Context(), id)
	if err != nil {
		c.logger.Error(
			"Could not revoked all common tokens for authorization",
			zap.Error(err),
			zap.String("authorization_id", id.String()),
		)
	}
	co := &http.Cookie{
		Name:     "__gotrxx",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(w, co)

	rc := &http.Cookie{
		Name:     "_gotrxx",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(w, rc)

	http.Redirect(w, r, logoutURI, http.StatusFound)
}
