package connect

import (
	"errors"
	"net/http"
	"time"

	"github.com/eisenwinter/gotrxx/application"
	"github.com/eisenwinter/gotrxx/tokens"
	"github.com/go-chi/render"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"go.uber.org/zap"
)

// RefreshTokenGrant handles the refresh_token grant, public because it used in netlify api as well
func (c *ConnnectRessource) RefreshTokenGrant(
	req *RefreshTokenTokenRequest,
	w http.ResponseWriter,
	r *http.Request,
) {
	auth, err := c.autService.AuthorizationByCommonToken(
		r.Context(),
		string(tokens.RefreshTokenType),
		req.RefreshToken,
	)
	if err != nil {
		c.logger.Error("refresh token flow: failed to get application", zap.Error(err))
		render.Status(r, http.StatusInternalServerError)
		render.Respond(
			w,
			r,
			createStdError(stdInternalServerError, http.StatusInternalServerError, ""),
		)
		return
	}
	if auth.IsRevoked() {
		render.Status(r, http.StatusBadRequest)
		render.Respond(w, r, createStdError(stdUnauthorziedClient, http.StatusBadRequest, ""))
		return
	}
	app := auth.Application()
	if app.IsRetired() {
		render.Status(r, http.StatusBadRequest)
		render.Respond(
			w,
			r,
			createStdError(stdInvalidClient, http.StatusBadRequest, "Application does not exist."),
		)
		return
	}
	if !app.IsFlowAllowed(application.RefreshTokenFlow) {
		render.Status(r, http.StatusBadRequest)
		render.Respond(w, r, createStdError(stdInvalidGrant, http.StatusBadRequest, ""))
		return
	}

	// client_id is NOT required for a refresh_token grant unless the client requires auth
	if app.HasSecret() && req.ClientID == "" {
		render.Status(r, http.StatusBadRequest)
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
	if req.ClientID != "" && app.ClientID() != req.ClientID {
		render.Status(r, http.StatusUnauthorized)
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
	if !app.ValidateClientSecret(req.ClientSecret) {
		render.Status(r, http.StatusBadRequest)
		render.Respond(w, r, createStdError(stdInvalidClient, http.StatusBadRequest, ""))
		return
	}
	if !app.AreScopesCoveredByApplication(req.Scope) {
		render.Status(r, http.StatusBadRequest)
		render.Respond(w, r, createStdError(stdInvalidScope, http.StatusBadRequest, ""))
		return
	}

	err = c.rotator.RotateCommonToken(
		r.Context(),
		tokens.RefreshTokenType,
		req.RefreshToken,
		app.ClientID(),
	)
	if err != nil {
		if errors.Is(tokens.ErrTokenInvalidClientId, err) {
			c.logger.Error("refresh token flow: failed to rotate refresh token", zap.Error(err))
			render.Status(r, http.StatusBadRequest)
			render.Respond(w, r, createStdError(stdInvalidClient, http.StatusBadRequest, ""))
			return
		}
		c.logger.Error("refresh token flow: failed to rotate refresh token", zap.Error(err))
		render.Status(r, http.StatusInternalServerError)
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
		render.Status(r, http.StatusInternalServerError)
		render.Respond(
			w,
			r,
			createStdError(stdInternalServerError, http.StatusInternalServerError, ""),
		)
		return
	}

	var t jwt.Token
	if req.IssueNetlifyToken {
		t, err = c.issuer.IssueNetlifyAccessTokenForUser(
			user,
			auth.ID(),
			auth.Application().ClientID(),
			auth.Scopes(),
		)
	} else {
		t, err = c.issuer.IssueAccessTokenForUser(
			user,
			auth.ID(),
			auth.Application().ClientID(),
			auth.Scopes(),
		)
	}

	if err != nil {
		c.logger.Error("refresh token flow: failed to issue a new access token", zap.Error(err))
		render.Status(r, http.StatusInternalServerError)
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
		render.Status(r, http.StatusInternalServerError)
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
		render.Status(r, http.StatusInternalServerError)
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
