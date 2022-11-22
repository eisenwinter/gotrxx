package connect

import (
	"errors"
	"net/http"
	"time"

	"github.com/eisenwinter/gotrxx/application"
	"github.com/eisenwinter/gotrxx/tokens"
	"github.com/go-chi/render"
	"go.uber.org/zap"
)

func (c *ConnnectRessource) refreshTokenGrant(
	req *refreshTokenTokenRequest,
	w http.ResponseWriter,
	r *http.Request,
) {
	auth, err := c.autService.AuthorizationByCommonToken(
		r.Context(),
		string(tokens.RefreshTokenType),
		req.refreshToken,
	)
	if err != nil {
		c.logger.Error("refresh token flow: failed to get application", zap.Error(err))
		render.Respond(
			w,
			r,
			createStdError(stdInternalServerError, http.StatusInternalServerError, ""),
		)
	}
	if auth.IsRevoked() {
		render.Respond(w, r, createStdError(stdUnauthorziedClient, http.StatusBadRequest, ""))
		return
	}
	app := auth.Application()
	if app.IsRetired() {
		render.Respond(
			w,
			r,
			createStdError(stdInvalidClient, http.StatusBadRequest, "Application does not exist."),
		)
		return
	}
	if !app.IsFlowAllowed(application.RefreshTokenFlow) {
		render.Respond(w, r, createStdError(stdInvalidGrant, http.StatusBadRequest, ""))
		return
	}

	// client_id is NOT required for a refresh_token grant unless the client requires auth
	if app.HasSecret() && req.clientID == "" {
		render.Respond(
			w,
			r,
			createStdError(
				stdInvalidClient,
				http.StatusBadRequest,
				"this client requires client_id",
			),
		)
		return
	}
	if req.clientID != "" && app.ClientID() != req.clientID {
		render.Respond(
			w,
			r,
			createStdError(
				stdInvalidClient,
				http.StatusUnauthorized,
				"Client authentication failed, due to missing or invalid client credentials.",
			),
		)
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

	err = c.rotator.RotateCommonToken(
		r.Context(),
		tokens.RefreshTokenType,
		req.refreshToken,
		app.ClientID(),
	)
	if err != nil {
		if errors.Is(tokens.ErrTokenInvalidClientId, err) {
			c.logger.Error("refresh token flow: failed to rotate refresh token", zap.Error(err))
			render.Respond(w, r, createStdError(stdInvalidClient, http.StatusBadRequest, ""))
		}
		c.logger.Error("refresh token flow: failed to rotate refresh token", zap.Error(err))
		render.Respond(
			w,
			r,
			createStdError(stdInternalServerError, http.StatusInternalServerError, ""),
		)
		return
	}
	user, err := c.userSignIn.SignInByIDFromToken(
		r.Context(),
		auth.UserID(),
		string(tokens.RefreshTokenType),
	)
	if err != nil {
		c.logger.Error("refresh token flow: failed to sign in user", zap.Error(err))
		render.Respond(
			w,
			r,
			createStdError(stdInternalServerError, http.StatusInternalServerError, ""),
		)
		return
	}
	t, err := c.issuer.IssueAccessTokenForUser(
		user,
		auth.ID(),
		auth.Application().ClientID(),
		auth.Scopes(),
	)
	if err != nil {
		c.logger.Error("refresh token flow: failed to issue a new access token", zap.Error(err))
		render.Respond(
			w,
			r,
			createStdError(stdInternalServerError, http.StatusInternalServerError, ""),
		)
		return
	}
	signed, err := c.issuer.Sign(t)
	if err != nil {
		c.logger.Error("refresh token flow: failed to sign a access token", zap.Error(err))
		render.Respond(
			w,
			r,
			createStdError(stdInternalServerError, http.StatusInternalServerError, ""),
		)
		return
	}
	refresh, err := c.issuer.IssueRefreshToken(r.Context(), auth.ID())
	if err != nil {
		c.logger.Error("refresh token flow: failed to issue a new refresh token", zap.Error(err))
		render.Respond(
			w,
			r,
			createStdError(stdInternalServerError, http.StatusInternalServerError, ""),
		)
		return
	}
	expires := int(t.Expiration().Sub(time.Now().UTC()).Seconds())
	response := &accessTokenResponse{
		AccessToken:  string(signed),
		TokenType:    "bearer_token",
		ExpiresIn:    &expires,
		RefreshToken: refresh,
	}
	render.Respond(w, r, response)
}
