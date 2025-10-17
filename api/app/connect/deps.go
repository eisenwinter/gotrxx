package connect

import (
	"context"

	"github.com/eisenwinter/gotrxx/application"
	"github.com/eisenwinter/gotrxx/authorization"
	"github.com/eisenwinter/gotrxx/tokens"
	"github.com/eisenwinter/gotrxx/user"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// TokenIssuer handles issuing and signing of tokens
type TokenIssuer interface {
	IssueAuthorizationCode(
		ctx context.Context,
		authorizationID uuid.UUID,
		codeChallenge string,
		codeChallengeMethod string,
	) (string, error)
	IssueAccessTokenForUser(
		user *user.SignedInUser,
		authorizationID uuid.UUID,
		clientID string,
		scopes []string,
	) (jwt.Token, error)
	Sign(token jwt.Token) ([]byte, error)
	IssueRefreshToken(
		ctx context.Context,
		authorizationID uuid.UUID,
	) (string, error)
	IssueAccessTokenForMachineClient(
		clientID string,
		scopes []string,
	) (jwt.Token, error)
	IssueNetlifyAccessTokenForUser(
		user *user.SignedInUser,
		authorizationID uuid.UUID,
		clientID string,
		scopes []string,
	) (jwt.Token, error)
}

type TokenRotator interface {
	PreRotationChallenge(
		ctx context.Context,
		authorizationCode string,
		codeVerifier string,
	) error
	RotateCommonToken(
		ctx context.Context,
		tokenType tokens.CommonTokenType,
		token string,
		clientID string,
	) error
	RevokeCommonTokensForAuthorization(
		ctx context.Context,
		autID uuid.UUID,
	) error
	RevokeCommonToken(
		ctx context.Context,
		tokenType tokens.CommonTokenType,
		token string,
		autID uuid.UUID,
	) error
}

// TokenVerifier verifies supplied tokens
type TokenVerifier interface {
	ParseAndValidateAccessToken(accessToken string) (jwt.Token, error)
	ValidateAccessTokenDetails(
		ctx context.Context,
		accessToken string,
	) (*tokens.CommonToken, error)
	ValidateRefreshTokenDetails(
		ctx context.Context,
		refreshToken string,
	) (*tokens.CommonToken, error)
}

// SignIner handles all user sign in related tasks
type SignIner interface {
	UserFromSubject(
		ctx context.Context,
		userID uuid.UUID,
	) (*user.SignedInUser, error)
	SignInByIDFromToken(
		ctx context.Context,
		userID uuid.UUID,
		tokenType string,
	) (*user.SignedInUser, error)
	SignIn(
		ctx context.Context,
		email string,
		password string,
	) (*user.SignedInUser, error)
}

// ApplicationToClientIDMapper resolves a application for a
// supplied client id
type ApplicationToClientIDMapper interface {
	ApplicationByClientID(
		ctx context.Context,
		clientID string,
	) (*application.Application, error)
}

// Authorizer handles all authorization related tasks
type Authorizer interface {
	AuthorizationByCommonToken(
		ctx context.Context,
		tokenType string,
		token string,
	) (*authorization.Authorization, error)
	ImplicitAuthorization(
		ctx context.Context,
		userID uuid.UUID,
		clientID string,
		scopes string,
	) (*authorization.Authorization, error)
	VerifyUserAuthorization(
		ctx context.Context,
		userID uuid.UUID,
		clientID string,
	) (*authorization.Authorization, error)
}
