package connect

import (
	"errors"
	"net/http"
	"time"

	"github.com/eisenwinter/gotrxx/application"
	"github.com/eisenwinter/gotrxx/authorization"
	"github.com/eisenwinter/gotrxx/user"
	"github.com/go-chi/render"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"go.uber.org/zap"
)

//password grant flow

// PasswordGrant is public so we can re-use this flow for the netlify wrapper
func (c *ConnnectRessource) PasswordGrant(req *PasswordGrantTokenRequest, w http.ResponseWriter, r *http.Request) {
	app, err := c.appService.ApplicationByClientID(r.Context(), req.ClientID)
	if err != nil {
		c.logger.Error("password flow: failed to get application", zap.Error(err))
		render.Status(r, http.StatusInternalServerError)
		render.Respond(w, r, createStdError(stdInternalServerError, http.StatusInternalServerError, "Internal server error"))
		return
	}
	if app.IsRetired() {
		render.Status(r, http.StatusBadRequest)
		render.Respond(w, r, createStdError(stdInvalidClient, http.StatusBadRequest, "Application does not exist."))
		return
	}
	if !app.IsFlowAllowed(application.PasswordFlow) {
		render.Status(r, http.StatusBadRequest)
		render.Respond(w, r, createStdError(stdUnauthorziedClient, http.StatusBadRequest, "Bad request"))
		return
	}
	if !app.ValidateClientSecret(req.ClientSecret) {
		render.Status(r, http.StatusBadRequest)
		render.Respond(w, r, createStdError(stdInvalidClient, http.StatusBadRequest, "Bad request"))
		return
	}
	if !app.AreScopesCoveredByApplication(req.Scope) {
		render.Status(r, http.StatusBadRequest)
		render.Respond(w, r, createStdError(stdInvalidScope, http.StatusBadRequest, "Bad request"))
		return
	}
	res, err := c.userSignIn.SignIn(r.Context(), req.Username, req.Password)
	if err != nil {
		c.logger.Debug("password flow: login failed", zap.Error(err))
		if errors.Is(err, user.ErrEntityDoesNotExist) || errors.Is(err, user.ErrInvalidCredentials) {
			render.Status(r, http.StatusBadRequest)
			render.Respond(w, r, createStdError(stdInvalidGrant, http.StatusBadRequest, "No user found with that email, or password invalid."))
			return
		}
		if errors.Is(err, user.ErrEntityOperationForbidden) {
			render.Status(r, http.StatusUnauthorized)
			render.Respond(w, r, createStdError(stdInvalidClient, http.StatusUnauthorized, "No user found with that email, or password invalid."))
			return
		}
		c.logger.Error("password flow: login failed due to unexpected error", zap.Error(err))
		return
	}

	auth, err := c.autService.VerifyUserAuthorization(r.Context(), res.UserID, req.ClientID)
	if err != nil && errors.Is(authorization.ErrUngrantedImplicitAutoGrant, err) {
		auth, err = c.autService.ImplicitAuthorization(r.Context(), res.UserID, req.ClientID, req.Scope)
		if err != nil {
			c.logger.Error("password flow: grantig implicit authorization failed", zap.Error(err))
			render.Status(r, http.StatusInternalServerError)
			render.Respond(w, r, createStdError(stdInternalServerError, http.StatusInternalServerError, ""))
			return
		}
	} else if err != nil {
		c.logger.Error("password flow: verifing authorization failed", zap.Error(err))
		render.Status(r, http.StatusInternalServerError)
		render.Respond(w, r, createStdError(stdInternalServerError, http.StatusInternalServerError, ""))
		return
	}

	var t jwt.Token
	if req.IssueNetlifyToken {
		t, err = c.issuer.IssueNetlifyAccessTokenForUser(res, auth.ID(), auth.Application().ClientID(), auth.Scopes())
		if err != nil {
			c.logger.Error("password flow: failed to issue a new netlify access token", zap.Error(err))
			render.Status(r, http.StatusInternalServerError)
			render.Respond(w, r, createStdError(stdInternalServerError, http.StatusInternalServerError, ""))
			return
		}

	} else {
		t, err = c.issuer.IssueAccessTokenForUser(res, auth.ID(), auth.Application().ClientID(), auth.Scopes())
		if err != nil {
			c.logger.Error("password flow: failed to issue a new access token", zap.Error(err))
			render.Status(r, http.StatusInternalServerError)
			render.Respond(w, r, createStdError(stdInternalServerError, http.StatusInternalServerError, ""))
			return
		}
	}

	signed, err := c.issuer.Sign(t)
	if err != nil {
		c.logger.Error("password flow: failed to sign a access token", zap.Error(err))
		render.Status(r, http.StatusInternalServerError)
		render.Respond(w, r, createStdError(stdInternalServerError, http.StatusInternalServerError, ""))
		return
	}
	var refreshToken string
	if app.IsFlowAllowed(application.RefreshTokenFlow) {
		refreshToken, err = c.issuer.IssueRefreshToken(r.Context(), auth.ID())
		if err != nil {
			c.logger.Error("password flow: failed to issue refresh token", zap.Error(err))
			render.Status(r, http.StatusInternalServerError)
			render.Respond(w, r, createStdError(stdInternalServerError, http.StatusInternalServerError, ""))
			return
		}
	}

	expires := int(t.Expiration().Sub(time.Now().UTC()).Seconds())
	response := &accessTokenResponse{
		AccessToken:  string(signed),
		TokenType:    "bearer_token",
		ExpiresIn:    &expires,
		RefreshToken: refreshToken,
	}
	render.Respond(w, r, response)
}
