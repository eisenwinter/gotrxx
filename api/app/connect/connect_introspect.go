package connect

import (
	"net/http"
	"time"

	"github.com/eisenwinter/gotrxx/api/auth"
	"github.com/eisenwinter/gotrxx/tokens"
	"github.com/go-chi/render"
	"go.uber.org/zap"
)

// https://datatracker.ietf.org/doc/html/rfc7662
func (c *ConnnectRessource) introspect(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		c.logger.Error("error on parsing form in retrospection endpoint", zap.Error(err))
		err = render.Render(w, r, createStdError(stdInvalidRequest, http.StatusBadRequest, ""))
		if err != nil {
			c.logger.Error("unable to render response", zap.Error(err))
		}
		return
	}
	ai, err := auth.FromContext(r.Context())
	if err != nil {
		err = render.Render(
			w,
			r,
			createStdError(stdUnauthorziedClient, http.StatusUnauthorized, ""),
		)
		if err != nil {
			c.logger.Error("unable to render response", zap.Error(err))
		}
		return
	}

	isEligble := func(common *tokens.CommonToken) bool {
		if ai.Source == auth.AuthorizationSourceBearer {
			return common.AuthorizationID() == *ai.AuthorizationID
		} else if ai.Source == auth.AuthorizationSourceBasic {
			return common.ClientID() == ai.ClientID
		}
		return false
	}

	// https://datatracker.ietf.org/doc/html/rfc7662#section-2.1

	// To prevent token scanning attacks, the endpoint MUST also require
	// some form of authorization to access this endpoint, such as client
	// authentication as described in OAuth 2.0 [RFC6749] or a separate
	// OAuth 2.0 access token such as the bearer token described in OAuth
	// 2.0 Bearer Token Usage [RFC6750].  The methods of managing and
	// validating these authentication credentials are out of scope of this
	// specification.

	tokenTypeHint := r.FormValue("token_type_hint")
	token := r.FormValue("token")
	if tokenTypeHint == "refresh_token" {
		refreshToken, err := c.verifier.ValidateRefreshTokenDetails(r.Context(), token)
		if err != nil {
			jwtoken, err := c.verifier.ValidateAccessTokenDetails(r.Context(), token)
			if err != nil {
				err = render.Render(w, r, &introspectionResponse{
					Active: false,
				})
				if err != nil {
					c.logger.Error("unable to render introspectionResponse", zap.Error(err))
				}
				return
			}
			if !isEligble(jwtoken) {
				err = render.Render(
					w,
					r,
					createStdError(stdInvalidRequest, http.StatusBadRequest, ""),
				)
				if err != nil {
					c.logger.Error("unable to render response", zap.Error(err))
				}
				return
			}
			c.renderIntrospectResult(w, r, "access_token", jwtoken)
			return
		}
		if !isEligble(refreshToken) {
			err = render.Render(w, r, createStdError(stdInvalidRequest, http.StatusBadRequest, ""))
			if err != nil {
				c.logger.Error("unable to render response", zap.Error(err))
			}
			return
		}
		c.renderIntrospectResult(w, r, "refresh_token", refreshToken)
		return
	}
	jwtoken, err := c.verifier.ValidateAccessTokenDetails(r.Context(), token)
	if err != nil {
		refreshToken, err := c.verifier.ValidateRefreshTokenDetails(r.Context(), token)
		if err != nil {
			err = render.Render(w, r, &introspectionResponse{
				Active: false,
			})
			if err != nil {
				c.logger.Error("unable to render introspectionResponse", zap.Error(err))
			}
			return
		}
		if !isEligble(refreshToken) {
			err = render.Render(w, r, createStdError(stdInvalidRequest, http.StatusBadRequest, ""))
			if err != nil {
				c.logger.Error("unable to render response", zap.Error(err))
			}
			return
		}
		c.renderIntrospectResult(w, r, "refresh_token", refreshToken)
		return
	}
	if !isEligble(jwtoken) {
		err = render.Render(w, r, createStdError(stdInvalidRequest, http.StatusBadRequest, ""))
		if err != nil {
			c.logger.Error("unable to render response", zap.Error(err))
		}
		return
	}
	c.renderIntrospectResult(w, r, "access_token", jwtoken)
}

func (c *ConnnectRessource) renderIntrospectResult(
	w http.ResponseWriter,
	r *http.Request,
	tokentype string,
	jwtoken *tokens.CommonToken,
) {

	nilTime := func(t time.Time) *int64 {
		x := t.Unix()
		if x == 0 {
			return nil
		}
		return &x
	}

	err := render.Render(w, r, &introspectionResponse{
		Active:          true,
		IssuedAt:        nilTime(jwtoken.IssuedAt()),
		Subject:         jwtoken.Subject(),
		TokenType:       tokentype,
		Expiration:      nilTime(jwtoken.Expiration()),
		Audience:        jwtoken.Audience()[0],
		Issuer:          jwtoken.Issuer(),
		Scope:           jwtoken.Scope(),
		ClientID:        jwtoken.ClientID(),
		Roles:           jwtoken.Roles(),
		AuthorizationID: jwtoken.AuthorizationID(),
	})
	if err != nil {
		c.logger.Error("unable to render introspectionResponse", zap.Error(err))
	}

}
