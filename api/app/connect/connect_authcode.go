package connect

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/google/safehtml/template"

	"github.com/eisenwinter/gotrxx/application"
	"github.com/eisenwinter/gotrxx/authorization"
	"github.com/eisenwinter/gotrxx/pkg/sanitize"
	"github.com/eisenwinter/gotrxx/tokens"
	"github.com/go-chi/render"
	"github.com/google/uuid"
)

func (c *ConnnectRessource) authorizeAuthorizationCode(
	req *authorizeAuthorizationCodeRequest,
	w http.ResponseWriter,
	r *http.Request,
) {
	if !validateRequiredField(req.clientID, "client_id", w, r) {
		return
	}
	ok, redirectToUse := c.authorizeAuthorizationCodeCheckApplication(r, req, w)
	if !ok {
		return
	}
	c.logger.Debug("using redirect_uri", "redirect_uri", sanitize.UserInputString(redirectToUse))

	redirect := func() {
		// Query params
		params := url.Values{}
		params.Add("response_type", "code")
		params.Add("client_id", req.clientID)
		params.Add("redirect_uri", redirectToUse)
		params.Add("scope", req.scope)
		params.Add("state", req.state)
		params.Add("code_challenge_method", req.codeChallengeMethod)
		params.Add("code_challenge", req.codeChallenge)
		params.Add("response_mode", req.responseMode)

		returnParam := url.Values{}
		returnParam.Add("return_url", fmt.Sprintf("/connect/authorize?%s", params.Encode()))
		http.Redirect(
			w,
			r,
			fmt.Sprintf("/account/signin?%s", returnParam.Encode()),
			http.StatusFound,
		)
	}

	tokenCookie, err := r.Cookie("__gotrxx")
	if err != nil {
		if errors.Is(http.ErrNoCookie, err) {
			redirect()
			return
		}
		c.logger.Error(
			"authorization code flow: (authorize) unexpected cookie error",
			"err", err,
		)
		render.Respond(
			w,
			r,
			createStdError(stdInternalServerError, http.StatusInternalServerError, ""),
		)
		return
	}

	t, err := c.verifier.ParseAndValidateAccessToken(tokenCookie.Value)
	if err != nil {
		c.logger.Debug("authorization code flow: (authorize) invalid access token", "err", err)
		c := &http.Cookie{
			Name:     "__gotrxx",
			Value:    "",
			Path:     "/",
			Expires:  time.Unix(0, 0),
			HttpOnly: true,
			Secure:   true,
		}
		http.SetCookie(w, c)
		redirect()
		return
	}
	userID, err := uuid.Parse(t.Subject())
	if err != nil {
		c.logger.Error(
			"authorization code flow: (authorize) invalid user id issued",
			"err", err,
		)
		render.Respond(
			w,
			r,
			createStdError(stdInternalServerError, http.StatusInternalServerError, ""),
		)
		return
	}
	auth, err := c.autService.VerifyUserAuthorization(r.Context(), userID, req.clientID)
	if err != nil && errors.Is(authorization.ErrUngrantedImplicitAutoGrant, err) {
		c.logger.Debug("authorization code flow: (authorize) grantig implicit authorization")
		auth, err = c.autService.ImplicitAuthorization(r.Context(), userID, req.clientID, req.scope)
		if err != nil {
			c.logger.Error(
				"authorization code flow: (authorize) grantig implicit authorization failed",
				"err", err,
			)
			render.Respond(
				w,
				r,
				createStdError(stdInternalServerError, http.StatusInternalServerError, ""),
			)
			return
		}
	} else if err != nil {
		c.logger.Error("authorization code flow: (authorize) verifing authorization failed", "err", err)
		render.Respond(w, r, createStdError(stdInternalServerError, http.StatusInternalServerError, ""))
		return
	}

	code, err := c.issuer.IssueAuthorizationCode(
		r.Context(),
		auth.ID(),
		req.codeChallenge,
		req.codeChallengeMethod,
	)
	if err != nil {
		c.logger.Error("authorization code flow: (authorize) unable to issue authorization code")
		render.Respond(
			w,
			r,
			createStdError(stdInternalServerError, http.StatusInternalServerError, ""),
		)
		return
	}

	switch req.responseMode {
	case "query":
		c.authorizeAuthorizationCodeQuery(req, w, r, code)
		return
	case "fragment":
		c.authorizeAuthorizationCodeFragment(req, w, r, code)
		return
	case "form_post":
		c.authorizeAuthorizationCodeFormPost(req, w, r, code)
		return
	default:
		response := &authorizedAuthorizationCodeResponse{
			Code:  code,
			State: req.state,
		}
		render.Respond(w, r, response)
	}
}

func (c *ConnnectRessource) authorizeAuthorizationCodeCheckApplication(
	r *http.Request,
	req *authorizeAuthorizationCodeRequest,
	w http.ResponseWriter,
) (bool, string) {
	app, err := c.appService.ApplicationByClientID(r.Context(), req.clientID)
	if err != nil {
		if errors.Is(application.ErrNotFound, err) {
			render.Respond(
				w,
				r,
				createStdError(stdInvalidClient, http.StatusBadRequest, "invalid client_id"),
			)
			return false, ""
		}
		c.logger.Error(
			"authorization code flow: (authorize) unexpected error getting application",
			"err", err,
		)
		render.Respond(
			w,
			r,
			createStdError(stdInternalServerError, http.StatusInternalServerError, ""),
		)
		return false, ""
	}
	if app.IsRetired() {
		render.Respond(
			w,
			r,
			createStdError(stdInvalidClient, http.StatusBadRequest, "invalid client_id"),
		)
		return false, ""
	}
	if !app.IsFlowAllowed(application.AuthorizationCodeFlow) {
		render.Respond(w, r, createStdError(stdInvalidGrant, http.StatusBadRequest, ""))
		return false, ""
	}
	if !app.AreScopesCoveredByApplication(req.scope) {
		render.Respond(w, r, createStdError(stdInvalidScope, http.StatusBadRequest, ""))
		return false, ""
	}

	if app.Properties().PKCE() {
		if !validateRequiredField(req.codeChallenge, "code_challenge", w, r) {
			return false, ""
		}
		if req.codeChallengeMethod != "S256" {
			render.Respond(
				w,
				r,
				createStdError(
					stdInvalidRequest,
					http.StatusBadRequest,
					"PKCE: unsuported code_challenge_method, plain is not supported",
				),
			)
			return false, ""
		}
	}
	redirectToUse := ""
	if req.redirectURI != "" {
		if !app.IsAllowedRedirectURI(req.redirectURI) {
			render.Respond(
				w,
				r,
				createStdError(stdInvalidRequest, http.StatusBadRequest, "invalid redirect_uri"),
			)
			return false, ""
		}
		redirectToUse = req.redirectURI
	} else if len(app.Properties().RedirectURIs()) > 0 {
		redirectToUse = app.Properties().RedirectURIs()[0]
	} else {
		c.logger.Error("authorization code flow: (authorize) no redirect uri aborting", "client_id", sanitize.UserInputString(req.clientID))
		render.Respond(w, r, createStdError(stdInvalidRequest, http.StatusBadRequest, "no redirect_uri"))
		return false, ""
	}
	return true, redirectToUse
}

func (c *ConnnectRessource) authorizeAuthorizationCodeFormPost(
	req *authorizeAuthorizationCodeRequest,
	w http.ResponseWriter,
	r *http.Request,
	code string,
) {
	if req.redirectURI == "" {
		c.logger.Error(
			"authorization code flow: (authorize) form_post is only supported with supplied return url",
		)
		render.Respond(
			w,
			r,
			createStdError(
				stdInvalidRequest,
				http.StatusBadRequest,
				"redirect_uri is needed when using response_mode=query",
			),
		)
		return
	}
	postData := &authorizedAuthorizationCodeResponse{
		Code:     code,
		State:    req.state,
		Callback: req.redirectURI,
	}
	t := template.New("form_post")
	t, err := t.Parse(`<html>
		<head><title>Please wait</title></head>
		<body onload="javascript:document.forms[0].submit()">
		 <form method="post" action="{{.Callback}}">
		   <input type="hidden" name="state"
			value="{{.State}}"/>
		   <input type="hidden" name="code"
			value="{{.Code}}"/>
		 </form>
		</body>
	   </html>`)
	if err != nil {
		c.logger.Error("authorization code flow: (authorize) invalid form_post template")
		render.Respond(
			w,
			r,
			createStdError(stdInternalServerError, http.StatusInternalServerError, ""),
		)
		return
	}
	err = t.Execute(w, postData)
	if err != nil {
		c.logger.Error("authorization code flow: unable to execute form template")
	}
}

func (c *ConnnectRessource) authorizeAuthorizationCodeFragment(
	req *authorizeAuthorizationCodeRequest,
	w http.ResponseWriter,
	r *http.Request,
	code string,
) {
	if req.redirectURI == "" {
		c.logger.Error(
			"authorization code flow: (authorize) fragment is only supported with supplied return url",
		)
		render.Respond(
			w,
			r,
			createStdError(
				stdInvalidRequest,
				http.StatusBadRequest,
				"redirect_uri is needed when using response_mode=fragment",
			),
		)
		return
	}
	rurl, err := url.Parse(req.redirectURI)
	if err != nil {
		c.logger.Error("authorization code flow: (authorize) invalid return url")
		render.Respond(
			w,
			r,
			createStdError(stdInvalidRequest, http.StatusBadRequest, "redirect_uri invalid"),
		)
		return
	}
	fp := url.Values{}
	fp.Add("code", code)
	fp.Add("state", req.state)
	rurl.Fragment = fp.Encode()
	res := rurl.String()
	http.Redirect(w, r, res, http.StatusFound)
}

func (c *ConnnectRessource) authorizeAuthorizationCodeQuery(
	req *authorizeAuthorizationCodeRequest,
	w http.ResponseWriter,
	r *http.Request,
	code string,
) {
	if req.redirectURI == "" {
		c.logger.Error(
			"authorization code flow: (authorize) query is only supported with supplied return url",
		)
		render.Respond(
			w,
			r,
			createStdError(
				stdInvalidRequest,
				http.StatusBadRequest,
				"redirect_uri is needed when using response_mode=query",
			),
		)
		return
	}
	rurl, err := url.Parse(req.redirectURI)
	if err != nil {
		c.logger.Error("authorization code flow: (authorize) invalid return url")
		render.Respond(
			w,
			r,
			createStdError(stdInvalidRequest, http.StatusBadRequest, "redirect_uri invalid"),
		)
		return
	}
	qs := rurl.Query()
	qs.Add("code", code)
	qs.Add("state", req.state)
	rurl.RawQuery = qs.Encode()
	res := rurl.String()
	c.logger.Debug("query mode redirect", "url", sanitize.UserInputString(res))
	http.Redirect(w, r, res, http.StatusFound)
}

func (c *ConnnectRessource) authorizationCodeGrant(
	req *authorizationCodeTokenRequest,
	w http.ResponseWriter,
	r *http.Request,
) {
	if !validateRequiredField(req.clientID, "client_id", w, r) {
		return
	}

	ok, auth := c.authorizationCodeGrantCheckAuth(r, req, w)
	if !ok {
		return
	}

	user, err := c.userSignIn.SignInByIDFromToken(
		r.Context(),
		auth.UserID(),
		string(tokens.AuthorizationCodeType),
	)
	if err != nil {
		c.logger.Error("authorization code flow: failed to sign in user", "err", err)
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
		c.logger.Error(
			"authorization code flow: failed to issue a new access token",
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
		c.logger.Error("authorization code flow: failed to sign a access token", "err", err)
		render.Respond(
			w,
			r,
			createStdError(stdInternalServerError, http.StatusInternalServerError, ""),
		)
		return
	}
	refresh := ""
	if auth.Application().IsFlowAllowed(application.RefreshTokenFlow) {
		refresh, err = c.issuer.IssueRefreshToken(r.Context(), auth.ID())
		if err != nil {
			c.logger.Error(
				"authorization code flow: failed to issue a new refresh token",
				"err", err,
			)
			render.Respond(
				w,
				r,
				createStdError(stdInternalServerError, http.StatusInternalServerError, ""),
			)
			return
		}
	}

	expires := int(t.Expiration().Sub(time.Now().UTC()).Seconds())
	response := &accessTokenResponse{
		AccessToken:  string(signed),
		TokenType:    bearerTokenType,
		ExpiresIn:    &expires,
		RefreshToken: refresh,
	}
	render.Respond(w, r, response)
}

func (c *ConnnectRessource) authorizationCodeGrantCheckAuth(
	r *http.Request,
	req *authorizationCodeTokenRequest,
	w http.ResponseWriter,
) (bool, *authorization.Authorization) {
	auth, err := c.autService.AuthorizationByCommonToken(
		r.Context(),
		string(tokens.AuthorizationCodeType),
		req.code,
	)
	if err != nil {
		c.logger.Error("authorization code flow: failed to get application", "err", err)
		render.Respond(
			w,
			r,
			createStdError(stdInternalServerError, http.StatusInternalServerError, ""),
		)
		return false, nil
	}
	if auth.IsRevoked() {
		render.Respond(w, r, createStdError(stdUnauthorziedClient, http.StatusBadRequest, ""))
		return false, nil
	}
	app := auth.Application()
	if app.IsRetired() {
		render.Respond(
			w,
			r,
			createStdError(stdInvalidClient, http.StatusBadRequest, "Application does not exist."),
		)
		return false, nil
	}
	if !app.IsFlowAllowed(application.AuthorizationCodeFlow) {
		render.Respond(w, r, createStdError(stdInvalidGrant, http.StatusBadRequest, ""))
		return false, nil
	}
	if app.ClientID() != req.clientID {
		render.Respond(
			w,
			r,
			createStdError(
				stdInvalidClient,
				http.StatusUnauthorized,
				"Client authentication failed, due to missing or invalid client credentials.",
			),
		)
		return false, nil
	}
	if !app.ValidateClientSecret(req.clientSecret) {
		render.Respond(w, r, createStdError(stdInvalidClient, http.StatusBadRequest, ""))
		return false, nil
	}
	if !app.IsAllowedRedirectURI(req.redirectURI) {
		c.logger.Debug(
			"invalid redirect uri for application",
			"supplied_uri", sanitize.UserInputString(req.redirectURI),
			"accepted_uris", app.Properties().RedirectURIs(),
		)
		render.Respond(
			w,
			r,
			createStdError(stdInvalidRequest, http.StatusBadRequest, "invalid redirect_uri"),
		)
		return false, nil
	}

	if app.Properties().PKCE() {
		if req.codeVerifier == "" {
			render.Respond(
				w,
				r,
				createStdError(stdInvalidRequest, http.StatusBadRequest, "missing code_verifier"),
			)
			return false, nil
		}
		//https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
		if len(req.codeVerifier) < 43 || len(req.codeVerifier) > 128 {
			render.Respond(
				w,
				r,
				createStdError(
					stdInvalidRequest,
					http.StatusBadRequest,
					"invalid code_verifier supplied",
				),
			)
			return false, nil
		}
	}
	if app.Properties().PKCE() {
		err = c.rotator.PreRotationChallenge(r.Context(), req.code, req.codeVerifier)
		if err != nil {
			if errors.Is(tokens.ErrChallengeFailed, err) {
				c.logger.Info("PKCE code validation failed")
				//https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
				render.Respond(
					w,
					r,
					createStdError(stdInvalidGrant, http.StatusBadRequest, "pixi verification"),
				)
				return false, nil
			}
			c.logger.Error("unexpected PKCE code verification error", "err", err)
			return false, nil
		}
	}

	err = c.rotator.RotateCommonToken(
		r.Context(),
		tokens.AuthorizationCodeType,
		req.code,
		app.ClientID(),
	)
	if err != nil {
		if errors.Is(tokens.ErrTokenInvalidClientId, err) {
			c.logger.Error("authorization code flow: failed to rotate code", "err", err)
			render.Respond(w, r, createStdError(stdInvalidClient, http.StatusBadRequest, ""))
		}
		c.logger.Error("authorization code flow: failed to rotate code", "err", err)
		render.Respond(
			w,
			r,
			createStdError(stdInternalServerError, http.StatusInternalServerError, ""),
		)
		return false, nil
	}
	return true, auth
}
