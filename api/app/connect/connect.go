package connect

import (
	"fmt"
	"net/http"

	"github.com/eisenwinter/gotrxx/api/auth"
	"github.com/eisenwinter/gotrxx/sanitize"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type ConnnectRessource struct {
	logger    *zap.Logger
	tokenAuth *jwtauth.JWTAuth
	issuer    TokenIssuer
	rotator   TokenRotator
	verifier  TokenVerifier

	userSignIn SignIner

	appService ApplicationToClientIDMapper
	autService Authorizer
}

// https://www.oauth.com/oauth2-servers/access-tokens/password-grant/ gonna be removed

func (c *ConnnectRessource) Router() *chi.Mux {
	r := chi.NewRouter()

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	r.Post("/token", c.token)

	r.Get("/authorize", c.authorize)
	r.Post("/authorize", c.authorize)

	r.Group(func(ri chi.Router) {
		ri.Use(jwtauth.Authenticator(c.tokenAuth))
		//logout literally means `log out from all devices`
		ri.Post("/logout", c.logout)
		ri.Get("/userinfo", c.userinfo)
		ri.Post("/revoke", c.revoke)
	})

	r.Group(func(ri chi.Router) {
		ri.Use(auth.ConnectAuthenticator(c.appService))
		ri.Post("/introspect", c.introspect)
	})

	return r
}

func (c *ConnnectRessource) fieldValidationNotEmpty(
	w http.ResponseWriter,
	r *http.Request,
	name string,
	value string,
) bool {
	if value == "" {
		err := render.Render(
			w,
			r,
			createStdError(
				stdInvalidRequest,
				http.StatusBadRequest,
				fmt.Sprintf("field not supplied: %s", name),
			),
		)
		if err != nil {
			c.logger.Error("unable to render response", zap.Error(err))
		}
		return false
	}
	return true
}

func (c *ConnnectRessource) token(w http.ResponseWriter, r *http.Request) {
	//issues accessTokenResponse
	err := r.ParseForm()
	if err != nil {
		c.logger.Error("could not parse form on token endpoint", zap.Error(err))
		err = render.Render(w, r, createStdError(stdInvalidRequest, http.StatusBadRequest, ""))
		if err != nil {
			c.logger.Error("unable to render response", zap.Error(err))
		}
		return
	}
	grant := r.FormValue("grant_type")
	switch grantType(grant) {
	case passwordGrant:
		c.tokenPasswordGrant(r, w)
		return
	case refreshTokenGrant:
		c.tokenRefreshTokenGrant(r, w)
		return
	case clientCredentialsGrant:
		c.tokenClientCredentialsGrant(r, w)
		return
	case authorizationCodeGrant:
		c.tokenAuthorizationCodeGrant(r, w)
		return
	default:
		err = render.Render(w, r, createStdError(stdUnspportedGrantType, http.StatusBadRequest, ""))
		if err != nil {
			c.logger.Error("unable to render response", zap.Error(err))
		}
	}

}

func (c *ConnnectRessource) tokenRefreshTokenGrant(r *http.Request, w http.ResponseWriter) {
	refreshToken := r.FormValue("refresh_token")
	if !c.fieldValidationNotEmpty(w, r, "refresh_token", refreshToken) {
		return
	}
	// client id is NOT required for a refresh_token grant see
	// https://datatracker.ietf.org/doc/html/rfc6749#section-6 tough it must
	// require client authentication for confidential clients or for any
	// client that was issued client credentials (or with other
	//	authentication requirements),
	// authenticate the client if client authentication is included and
	// ensure that the refresh token was issued to the authenticated
	// client, and validate the refresh token.

	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	//we dont do scopes here - at all, but for the sake of completeness
	scope := r.FormValue("scope")
	req := &RefreshTokenTokenRequest{
		RefreshToken: refreshToken,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scope:        scope,
	}
	c.RefreshTokenGrant(req, w, r)
}

func (c *ConnnectRessource) tokenClientCredentialsGrant(r *http.Request, w http.ResponseWriter) {
	c.logger.Debug("client credentials")
	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.2
	// The authorization server MUST authenticate the client.
	// well we basically only accept with a client secret here
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	if clientID == "" {
		id, suppliedSecret, err := auth.ClientIDFromBasicAuth(r, c.appService)
		if err != nil {
			c.logger.Info("unable to get client_id from basic auth", zap.Error(err))
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
		clientID = id
		clientSecret = suppliedSecret
	}
	if !c.fieldValidationNotEmpty(w, r, "client_id", clientID) {
		return
	}

	if !c.fieldValidationNotEmpty(w, r, "client_secret", clientSecret) {
		return
	}

	scope := r.FormValue("scope")
	req := &clientCredentialsTokenRequest{
		clientID:     clientID,
		clientSecret: clientSecret,
		scope:        scope,
	}
	c.clientCredentialsGrant(req, w, r)
}

func (c *ConnnectRessource) tokenAuthorizationCodeGrant(r *http.Request, w http.ResponseWriter) {
	//https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
	c.logger.Debug("auth code")
	code := r.FormValue("code")

	if !c.fieldValidationNotEmpty(w, r, "code", code) {
		return
	}

	redirectURI := r.FormValue("redirect_uri")
	if !c.fieldValidationNotEmpty(w, r, "redirect_uri", redirectURI) {
		return
	}

	clientID := r.FormValue("client_id")
	if !c.fieldValidationNotEmpty(w, r, "client_id", clientID) {
		return
	}

	clientSecret := r.FormValue("client_secret")
	codeVerifier := r.FormValue("code_verifier")
	if codeVerifier == "" && clientSecret == "" {
		//https://datatracker.ietf.org/doc/html/rfc7636
		c.logger.Warn(
			"no code verifier for PKCE AND no client secret!",
			sanitize.UserInputString("client_id", clientID),
		)
	}

	req := &authorizationCodeTokenRequest{
		code:         code,
		redirectURI:  redirectURI,
		clientID:     clientID,
		clientSecret: clientSecret,
		codeVerifier: codeVerifier,
	}
	c.authorizationCodeGrant(req, w, r)
}

func (c *ConnnectRessource) tokenPasswordGrant(r *http.Request, w http.ResponseWriter) {
	username := r.FormValue("username")
	if !c.fieldValidationNotEmpty(w, r, "username", username) {
		return
	}
	password := r.FormValue("password")
	if !c.fieldValidationNotEmpty(w, r, "password", password) {
		return
	}
	clientID := r.FormValue("client_id")

	if !c.fieldValidationNotEmpty(w, r, "client_id", clientID) {
		return
	}
	clientSecret := r.FormValue("client_secret")

	scope := r.FormValue("scope")
	req := &PasswordGrantTokenRequest{
		Username:     username,
		Password:     password,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scope:        scope,
	}
	c.logger.Debug("password_grant called")
	c.PasswordGrant(req, w, r)
}

func (c *ConnnectRessource) authorize(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		c.logger.Error("error on parsing form in authorize endpoint", zap.Error(err))
	}
	responseType := r.FormValue("response_type")
	switch responseType {
	case "code":
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
		redir := r.FormValue("redirect_uri")
		scope := r.FormValue("scope")
		state := r.FormValue("state")
		challegeMethod := r.FormValue("code_challenge_method")
		challenge := r.FormValue("code_challenge")
		req := &authorizeAuthorizationCodeRequest{
			clientID:            clientID,
			redirectURI:         redir,
			scope:               scope,
			state:               state,
			codeChallengeMethod: challegeMethod,
			codeChallenge:       challenge,
			responseMode:        r.FormValue("response_mode"),
		}
		c.authorizeAuthorizationCode(req, w, r)
		return
	default:
		err = render.Render(
			w,
			r,
			createStdError(stdUnspportedResponseType, http.StatusBadRequest, ""),
		)
		if err != nil {
			c.logger.Error("unable to render response", zap.Error(err))
		}
		return
	}

}

func (c *ConnnectRessource) userinfo(w http.ResponseWriter, r *http.Request) {
	j, _, err := jwtauth.FromContext(r.Context())
	if err != nil {
		err = render.Render(w, r, createStdError(stdInvalidRequest, http.StatusBadRequest, ""))
		if err != nil {
			c.logger.Error("unable to render response", zap.Error(err))
		}
		c.logger.Error("errors getting jwt in userinfo endpoint")
		return
	}
	sub := j.Subject()
	id, err := uuid.Parse(sub)
	if err != nil {
		err = render.Render(w, r, createStdError(stdInvalidRequest, http.StatusBadRequest, ""))
		if err != nil {
			c.logger.Error("unable to render response", zap.Error(err))
		}
		c.logger.Error("errors parsing subjet in userinfo endpoint")
		return
	}
	user, err := c.userSignIn.UserFromSubject(r.Context(), id)
	if err != nil {
		err = render.Render(
			w,
			r,
			createStdError(stdInternalServerError, http.StatusInternalServerError, ""),
		)
		if err != nil {
			c.logger.Error("unable to render response", zap.Error(err))
		}
		c.logger.Error("errors loading user from subjet in userinfo endpoint")
		return
	}
	err = render.Render(w, r, &userInfoResponse{
		Subject: sub,
		Email:   user.Email,
		Roles:   user.Roles,
	})
	if err != nil {
		c.logger.Error("unable to render response", zap.Error(err))
	}
}

func validateRequiredField(field string, name string, w http.ResponseWriter,
	r *http.Request) bool {
	if field == "" {
		render.Respond(
			w,
			r,
			createStdError(
				stdInvalidClient,
				http.StatusBadRequest,
				fmt.Sprintf("requires %s", name),
			),
		)
		return false
	}
	return true
}

func NewConnnectRessource(logger *zap.Logger,
	tokenAuth *jwtauth.JWTAuth,
	issuer TokenIssuer,
	rotator TokenRotator,
	userSignIn SignIner,
	authService Authorizer,
	appService ApplicationToClientIDMapper,
	verifier TokenVerifier) *ConnnectRessource {
	return &ConnnectRessource{logger: logger,
		tokenAuth:  tokenAuth,
		issuer:     issuer,
		userSignIn: userSignIn,
		rotator:    rotator,
		autService: authService,
		appService: appService,
		verifier:   verifier}
}
