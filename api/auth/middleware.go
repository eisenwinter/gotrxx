package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/eisenwinter/gotrxx/application"
	"github.com/eisenwinter/gotrxx/tokens"
	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

/*
 This middleware handles the basic auth request if no bearer token was processed prior
 to support Rfc6749  (https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1)

 this is the basis for
 The authorization server MUST:

   o  require client authentication for confidential clients or for any
      client that was issued client credentials (or with other
      authentication requirements),

 as per 4.1.3.
*/

type ApplicationQuerySource interface {
	ApplicationByClientID(ctx context.Context, clientID string) (*application.Application, error)
}

type BasicAuth struct {
	as ApplicationQuerySource
}

var (
	ErrBasicAuthHeaderNotFound    = errors.New("no header value found")
	ErrHeaderValueMalformed       = errors.New("header value malformed")
	ErrAppVerifcationFailed       = errors.New("application verification failed")
	ErrUnknown                    = errors.New("unknown error")
	ErrInvalidAuthorizationResult = errors.New("invalid authorization result")
)

func ConnectAuthenticator(as ApplicationQuerySource) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return connectAuthenticator(&BasicAuth{as: as}, next)
	}
}

func connectAuthenticator(ba *BasicAuth, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, _, err := jwtauth.FromContext(r.Context())
		if err != nil && !errors.Is(jwtauth.ErrNoTokenFound, err) {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		ctx := r.Context()
		if token == nil {
			ctx, err = ba.validateBasicAuth(r)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
		} else if jwt.Validate(token) != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		} else {
			clientID, ok := token.Get(tokens.ClaimClientID)
			if !ok {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			ctx = context.WithValue(ctx, ClientIDContextKey, clientID.(string))
			autID, ok := token.Get(tokens.ClaimAuthorization)
			if !ok {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			ctx = context.WithValue(ctx, AuthorizationIDContextKey, autID.(string))
			sub := token.Subject()
			ctx = context.WithValue(ctx, SubjectContextKey, sub)
			ctx = context.WithValue(ctx, SourceContextKey, AuthorizationSourceBearer)
		}

		// Token is authenticated, pass it through
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func ClientIDFromBasicAuth(r *http.Request, as ApplicationQuerySource) (string, string, error) {
	header := basicAuthorizationHeader(r)
	if header == "" {
		return "", "", ErrBasicAuthHeaderNotFound
	}
	text, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return "", "", ErrHeaderValueMalformed
	}
	split := strings.Split(string(text), ":")
	if len(split) != 2 {
		return "", "", ErrHeaderValueMalformed
	}
	clientID, err := url.QueryUnescape(split[0])
	if err != nil {
		return "", "", ErrHeaderValueMalformed
	}
	secret, err := url.QueryUnescape(split[1])
	if err != nil {
		return "", "", ErrHeaderValueMalformed
	}
	app, err := as.ApplicationByClientID(r.Context(), clientID)
	if err != nil {
		return "", "", ErrUnknown
	}

	if !app.HasSecret() {
		return "", "", ErrAppVerifcationFailed
	}

	if app.IsRetired() {
		return "", "", ErrAppVerifcationFailed
	}

	//only apps that have been private confidentiality may use basic auth
	if app.Confidentiality() != application.PrivateConfidentiality {
		return "", "", ErrAppVerifcationFailed
	}

	if !app.ValidateClientSecret(secret) {
		return "", "", ErrAppVerifcationFailed
	}

	return app.ClientID(), secret, nil
}

func (b *BasicAuth) validateBasicAuth(r *http.Request) (context.Context, error) {
	ctx := r.Context()
	clientID, _, err := ClientIDFromBasicAuth(r, b.as)
	if err != nil {
		return ctx, err
	}

	// ctx = context.WithValue(ctx, AuthorizationIDContextKey, "")
	ctx = context.WithValue(ctx, ClientIDContextKey, clientID)
	ctx = context.WithValue(ctx, SourceContextKey, AuthorizationSourceBasic)
	return ctx, nil

}

func basicAuthorizationHeader(r *http.Request) string {
	// Get token from authorization header.
	val := r.Header.Get("Authorization")
	if len(val) > 6 && strings.ToUpper(val[0:5]) == "BASIC" {
		return val[6:]
	}
	return ""
}

type contextKey struct {
	name string
}

type AuthorizationSource string

const AuthorizationSourceBearer = "bearer"
const AuthorizationSourceBasic = "basic"

var (
	SourceContextKey          = &contextKey{"Source"}
	AuthorizationIDContextKey = &contextKey{"AuthorizationID"}
	ClientIDContextKey        = &contextKey{"ClientID"}
	SubjectContextKey         = &contextKey{"Subject"}
)

type AuthorizationInfo struct {
	Source          string
	ClientID        string
	Subject         *string
	AuthorizationID *string
}

func FromContext(ctx context.Context) (*AuthorizationInfo, error) {
	source, ok := ctx.Value(SourceContextKey).(string)
	if !ok {
		return nil, ErrInvalidAuthorizationResult
	}
	ai := &AuthorizationInfo{}
	ai.Source = source

	clientID, ok := ctx.Value(ClientIDContextKey).(string)
	if !ok {
		return nil, ErrInvalidAuthorizationResult
	}
	ai.ClientID = clientID

	authorizationID, ok := ctx.Value(AuthorizationIDContextKey).(string)
	if ok {
		ai.AuthorizationID = &authorizationID
	}

	subject, ok := ctx.Value(SubjectContextKey).(string)
	if ok {
		ai.AuthorizationID = &subject
	}

	return ai, nil
}
