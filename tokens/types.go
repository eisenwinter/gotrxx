package tokens

import (
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

type CommonTokenType string

const RefreshTokenType CommonTokenType = "refresh_token"
const AuthorizationCodeType CommonTokenType = "authorization_code"

// single sign on token to remember signed in user
const RememberMeTokenType CommonTokenType = "remember_me"

const AccessTokenType CommonTokenType = "access_token"

type CommonToken struct {
	audience   []string
	issuedAt   time.Time
	expiration time.Time
	subject    string
	issuer     string
	scope      string
	tokenType  string
	email      string
	roles      []string
	clientID   string
	autID      string
}

func (c *CommonToken) Audience() []string {
	return c.audience
}

func (c *CommonToken) IssuedAt() time.Time {
	return c.issuedAt
}

func (c *CommonToken) Expiration() time.Time {
	return c.expiration
}

func (c *CommonToken) Subject() string {
	return c.subject
}

func (c *CommonToken) Issuer() string {
	return c.issuer
}

func (c *CommonToken) Scope() string {
	return c.scope
}

func (c *CommonToken) Type() string {
	return c.tokenType
}

func (c *CommonToken) Email() string {
	return c.email
}

func (c *CommonToken) Roles() []string {
	return c.roles
}

func (c *CommonToken) ClientID() string {
	return c.clientID
}

func (c *CommonToken) AuthorizationID() string {
	return c.autID
}

func commonTokenFromJWT(token jwt.Token) *CommonToken {
	t := &CommonToken{
		issuedAt:   token.IssuedAt(),
		audience:   token.Audience(),
		expiration: token.Expiration(),
		subject:    token.Subject(),
		issuer:     token.Issuer(),
		tokenType:  string(AccessTokenType),
	}
	if scope, ok := token.Get(ClaimScope); ok {
		t.scope = scope.(string)
	}
	if email, ok := token.Get(ClaimEmail); ok {
		t.email = email.(string)
	}
	if autID, ok := token.Get(ClaimAuthorization); ok {
		t.autID = autID.(string)
	}
	if clientID, ok := token.Get(ClaimClientID); ok {
		t.clientID = clientID.(string)
	}
	if roles, ok := token.Get(ClaimRoles); ok {
		if roles != nil {
			rin := roles.([]interface{})
			r := make([]string, len(rin))
			for i, v := range rin {
				r[i] = v.(string)
			}
			t.roles = r
		}

	}

	return t
}
