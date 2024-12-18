package connect

import (
	"net/http"
	"strings"
	"time"

	"github.com/eisenwinter/gotrxx/application"
	"github.com/go-chi/render"
)

func (c *ConnnectRessource) clientCredentialsGrant(
	req *clientCredentialsTokenRequest,
	w http.ResponseWriter,
	r *http.Request,
) {
	if req.clientID == "" {
		render.Respond(
			w,
			r,
			createStdError(stdInvalidRequest, http.StatusBadRequest, "client_id missing."),
		)
		return
	}
	if req.clientSecret == "" {
		render.Respond(
			w,
			r,
			createStdError(stdInvalidRequest, http.StatusBadRequest, "client_secret missing."),
		)
		return
	}
	app, err := c.appService.ApplicationByClientID(r.Context(), req.clientID)
	if err != nil {
		c.logger.Error("client credentials flow: failed to get application", "err", err)
		render.Respond(
			w,
			r,
			createStdError(stdInternalServerError, http.StatusInternalServerError, ""),
		)
	}
	if app.IsRetired() {
		render.Respond(
			w,
			r,
			createStdError(stdInvalidClient, http.StatusBadRequest, "Application does not exist."),
		)
		return
	}
	if !app.IsFlowAllowed(application.ClientCredentialsFlow) {
		render.Respond(w, r, createStdError(stdUnauthorziedClient, http.StatusBadRequest, ""))
		return
	}
	if !app.ValidateClientSecret(req.clientSecret) {
		render.Respond(w, r, createStdError(stdInvalidClient, http.StatusBadRequest, ""))
		return
	}
	if !app.AreScopesCoveredByApplication(req.scope) {
		render.Respond(w, r, createStdError(stdInvalidScope, http.StatusBadRequest, ""))
		return
	}

	scopes := []string{}
	if req.scope != "" {
		scopes = strings.Split(req.scope, " ")
	}
	t, err := c.issuer.IssueAccessTokenForMachineClient(app.ClientID(), scopes)
	if err != nil {
		c.logger.Error(
			"client credentials flow: failed to issue a new access token",
			"err", err,
		)
		render.Respond(
			w,
			r,
			createStdError(stdInternalServerError, http.StatusInternalServerError, ""),
		)
		return
	}
	signed, err := c.issuer.Sign(t)
	if err != nil {
		c.logger.Error("client credentials flow: failed to sign a access token", "err", err)
		render.Respond(
			w,
			r,
			createStdError(stdInternalServerError, http.StatusInternalServerError, ""),
		)
		return
	}
	expires := int(t.Expiration().Sub(time.Now().UTC()).Seconds())
	response := &accessTokenResponse{
		AccessToken: string(signed),
		TokenType:   bearerTokenType,
		ExpiresIn:   &expires,
	}
	render.Respond(w, r, response)
}
