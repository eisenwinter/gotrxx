package tokens

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/eisenwinter/gotrxx/authorization"
	"github.com/eisenwinter/gotrxx/db"
	"github.com/eisenwinter/gotrxx/db/tables"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"go.uber.org/zap"
)

type Fetcher interface {
	CommonTokenDetails(
		ctx context.Context,
		tokenType string,
		token string,
	) (*db.CommonTokenDetails, error)
	UserByID(ctx context.Context, id uuid.UUID) (*db.UserData, error)
	ApplicationByClientID(ctx context.Context, clientID string) (*tables.ApplicationTable, error)
}

func NewTokenVerifier(log *zap.Logger,
	issuer *TokenIssuer,
	loader Fetcher,
	authService *authorization.Service) *TokenVerifier {
	return &TokenVerifier{
		log:         log,
		issuer:      issuer,
		loader:      loader,
		authService: authService,
	}
}

type TokenVerifier struct {
	log         *zap.Logger
	issuer      *TokenIssuer
	loader      Fetcher
	authService *authorization.Service
}

// ParseAndValidateAccessToken parses and validates the jwt token against
// the supplied claims, does not check the database by itself for any revocations
func (t *TokenVerifier) ParseAndValidateAccessToken(accessToken string) (jwt.Token, error) {
	if len(t.issuer.parseOptions) == 0 {
		return nil, errors.New("no valid JWT parsing options")
	}
	token, err := jwt.Parse([]byte(accessToken), t.issuer.parseOptions...)
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired()):
			return nil, errors.New("expired access token")
		default:
			t.log.Error("unexpected access token parsing error", zap.Error(err))
			return nil, errors.New("failed to parse access token")
		}

	}
	return token, nil
}

// ValidateAccessTokenDetails validates an access token and all underlying entities from the data store
// returns a common token wrapper if the token is still usable otherwise it will return a error
func (t *TokenVerifier) ValidateAccessTokenDetails(
	ctx context.Context,
	accessToken string,
) (*CommonToken, error) {
	if len(t.issuer.parseOptions) == 0 {
		return nil, errors.New("no valid JWT parsing options")
	}
	token, err := jwt.Parse([]byte(accessToken), t.issuer.parseOptions...)
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired()):
			return nil, ErrTokenExpired
		default:
			return nil, ErrInvalidToken
		}
	}
	clientID, ok := token.Get(ClaimClientID)
	if !ok {
		return nil, ErrInvalidToken
	}
	// if no subject its a client credentials machine token
	if token.Subject() != "" {
		//validate all the user the way down from application, to authorization, to user
		userID, err := uuid.Parse(token.Subject())
		if err != nil {
			return nil, err
		}
		auth, err := t.authService.VerifyUserAuthorization(ctx, userID, clientID.(string))
		if err != nil {
			return nil, err
		}
		user, err := t.loader.UserByID(ctx, auth.UserID())
		if err != nil {
			return nil, ErrInvalidToken
		}
		if user.BannedOn != nil {
			return nil, ErrInvalidToken
		}
		if user.LockoutTill != nil && user.LockoutTill.Before(time.Now().UTC()) {
			return nil, ErrInvalidToken
		}

	} else {
		client, err := t.loader.ApplicationByClientID(ctx, clientID.(string))
		if err != nil {
			return nil, err
		}
		if client.RetiredOn != nil {
			return nil, ErrInvalidToken
		}
	}

	return commonTokenFromJWT(token), nil
}

// ValidateRefreshTokenDetails validates an refresh against all stored entities
// returns a common token wrapper if the token is still usable
func (t *TokenVerifier) ValidateRefreshTokenDetails(
	ctx context.Context,
	refreshToken string,
) (*CommonToken, error) {
	d, err := t.loader.CommonTokenDetails(ctx, string(RefreshTokenType), refreshToken)
	if err != nil {
		if errors.Is(db.ErrNotFound, err) {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}
	if d.ExpiresAt.Before(time.Now().UTC()) {
		return nil, ErrTokenExpired
	}
	if d.RevokedAt != nil {
		return nil, ErrTokenRevoked
	}
	if d.RedeemedAt != nil {
		return nil, ErrInvalidToken
	}

	//we only issue refresh token to users so this fine

	// VerifyUserAuthorization is guaranteed to be a active authorization
	auth, err := t.authService.VerifyUserAuthorization(ctx, d.UserID, d.ClientID)
	if err != nil {
		return nil, ErrInvalidToken
	}
	user, err := t.loader.UserByID(ctx, d.UserID)
	if err != nil {
		return nil, ErrInvalidToken
	}
	if user.BannedOn != nil {
		return nil, ErrInvalidToken
	}
	if user.LockoutTill != nil && user.LockoutTill.Before(time.Now().UTC()) {
		return nil, ErrInvalidToken
	}
	token := &CommonToken{
		audience:   t.issuer.aud,
		autID:      d.AuthorizationId.String(),
		issuedAt:   d.IssuedAt,
		expiration: d.ExpiresAt,
		subject:    d.UserID.String(),
		scope:      strings.Join(auth.Scopes(), " "),
		tokenType:  string(RefreshTokenType),
		email:      user.Email,
		roles:      user.Roles,
		clientID:   auth.Application().ClientID(),
		issuer:     t.issuer.iss,
	}
	return token, nil
}
