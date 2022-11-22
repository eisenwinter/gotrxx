package connect

import (
	"net/http"

	"github.com/go-chi/render"
)

// we just gonna use the standard rfc 6749 definition
// https://datatracker.ietf.org/doc/html/rfc6749#section-5.1

// Succesfull access token response
// @Description access token response as defined in https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
type accessTokenResponse struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"` //https://datatracker.ietf.org/doc/html/rfc6749#section-7.1
	ExpiresIn    *int      `json:"expires_in,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Scope        *[]string `json:"scope,omitempty"` //to be complete but we are not building a oauth server here (I guess)
}

func (*accessTokenResponse) Render(_ http.ResponseWriter, _ *http.Request) error {
	return nil
}

type authorizedAuthorizationCodeResponse struct {
	Code     string `json:"code"`
	State    string `json:"state"`
	Callback string `json:"-,omitempty"`
}

func (*authorizedAuthorizationCodeResponse) Render(_ http.ResponseWriter, _ *http.Request) error {
	return nil
}

// for errors
// we just gonna use the rfc again
// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
type oauthError string

// The request is missing a required parameter, includes an unsupported parameter value (other than grant type),
// repeats a parameter, includes multiple credentials, utilizes more than one mechanism for authenticating the client, or is otherwise malformed.
const stdInvalidRequest oauthError = "invalid_request"

//	Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).
//
// The authorization server MAY return an HTTP 401 (Unauthorized) status code to indicate which HTTP authentication schemes are supported.
// If the client attempted to authenticate via the "Authorization" request header field, the authorization server MUST respond with an HTTP 401 (Unauthorized)
// status code and include the "WWW-Authenticate" response header field matching the authentication scheme used by the client.
const stdInvalidClient oauthError = "invalid_client"

// The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired,
// revoked, does not match the redirection URI used in the authorization request, or was issued to another client.
const stdInvalidGrant oauthError = "invalid_grant"

// The authenticated client is not authorized to use this authorization grant type.
const stdUnauthorziedClient oauthError = "unauthorized_client"

// The authorization grant type is not supported by the authorization server.
const stdUnspportedGrantType oauthError = "unsupported_grant_type"

// this is a non oauth error indicating something went wrong beyond the covered spec
const stdInternalServerError oauthError = "server_error"

// The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the resource owner.
const stdInvalidScope oauthError = "invalid_scope"

// The authorization server does not support obtaining an authorization code using this method.
const stdUnspportedResponseType oauthError = "unsupported_response_type"

// he authorization server does not support the revocation of the presented token type.  That is, the client tried to revoke an access token on a server not supporting this feature
const stdUnspportedTokenType oauthError = "invalid_request"

type stdErrorResponse struct {
	Error            oauthError `json:"error,omitempty"`
	ErrorDescription string     `json:"error_description,omitempty"`
	ErrorURI         string     `json:"error_uri,omitempty"`
	StatusCode       int        `json:"-"`
}

func (e *stdErrorResponse) Render(_ http.ResponseWriter, r *http.Request) error {
	render.Status(r, e.StatusCode)
	return nil
}

func createStdError(err oauthError, status int, description string) *stdErrorResponse {
	return &stdErrorResponse{
		Error:            err,
		ErrorDescription: description,
		StatusCode:       status,
	}
}

type grantType string

const clientCredentialsGrant grantType = "client_credentials"
const authorizationCodeGrant grantType = "authorization_code"
const refreshTokenGrant grantType = "refresh_token"
const passwordGrant grantType = "password"

// PasswordGrantTokenRequest wraps everything from the password grant request
type PasswordGrantTokenRequest struct {
	Username     string
	Password     string
	ClientID     string
	ClientSecret string
	Scope        string

	IssueNetlifyToken bool
}

type RefreshTokenTokenRequest struct {
	RefreshToken string
	ClientID     string
	ClientSecret string
	Scope        string

	IssueNetlifyToken bool
}

type clientCredentialsTokenRequest struct {
	clientID     string
	clientSecret string
	scope        string
}

type authorizationCodeTokenRequest struct {
	code        string
	redirectURI string
	//REQUIRED
	clientID     string
	clientSecret string //making it either or with pcke
	codeVerifier string //PCKE
}

type authorizeAuthorizationCodeRequest struct {
	//OPTIONAL
	redirectURI string
	//OPTIONAL
	scope string
	// RECOMMENDED.  An opaque value used by the client to maintain
	// state between the request and callback.  The authorization
	// server includes this value when redirecting the user-agent back
	// to the client.  The parameter SHOULD be used for preventing
	// cross-site request forgery as described in Section 10.12.
	state string
	//REQUIRED
	clientID string

	//pixi params
	codeChallengeMethod string
	codeChallenge       string

	//multi OPTIONAL - NOT STD https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#OAuth.Post
	responseMode string
}

type userInfoResponse struct {
	Subject string   `json:"sub"`
	Email   string   `json:"email"`
	Roles   []string `json:"roles,omitempty"`
}

func (*userInfoResponse) Render(_ http.ResponseWriter, _ *http.Request) error {
	return nil
}

// https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
type introspectionResponse struct {
	Active          bool     `json:"active"`
	Scope           string   `json:"scope,omitempty"`
	ClientID        string   `json:"client_id,omitempty"`
	TokenType       string   `json:"token_type,omitempty"`
	Expiration      *int64   `json:"exp,omitempty"`
	IssuedAt        *int64   `json:"iat,omitempty"`
	NotBefore       *int64   `json:"nbf,omitempty"`
	Subject         string   `json:"sub,omitempty"`
	Audience        string   `json:"aud,omitempty"`
	Issuer          string   `json:"iss,omitempty"`
	JTI             string   `json:"jti,omitempty"`
	Roles           []string `json:"roles,omitempty"`
	AuthorizationID string   `json:"aut,omitempty"`
}

func (*introspectionResponse) Render(_ http.ResponseWriter, _ *http.Request) error {
	return nil
}
