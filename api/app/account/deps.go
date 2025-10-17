package account

import (
	"context"
	"time"

	"github.com/eisenwinter/gotrxx/authorization"
	"github.com/eisenwinter/gotrxx/tokens"
	"github.com/eisenwinter/gotrxx/user"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// SignIner handles any user sign-in related tasks
// like validating passwords or signing users from tokens
type SignIner interface {
	Validate(ctx context.Context, id uuid.UUID, password string) error
	InitializeMFA(ctx context.Context, email string) error
	SignInMFA(
		ctx context.Context,
		email string,
		password string,
		otp string,
	) (*user.SignedInUser, error)
	UserFromSubject(
		ctx context.Context,
		userID uuid.UUID,
	) (*user.SignedInUser, error)
	SignInByIDFromToken(
		ctx context.Context,
		userID uuid.UUID,
		tokenType string,
	) (*user.SignedInUser, error)
}

// UserService handles all data regarding to users
// it allows enabling, disabling mfa, registering
// checking roles, changing password and email
// and inviting users
type UserService interface {
	InRole(ctx context.Context, id uuid.UUID, role string) bool
	ChangeEmail(ctx context.Context, id uuid.UUID, email string) error
	ChangePassword(ctx context.Context, id uuid.UUID, password string) error
	ConfirmUser(ctx context.Context, token string) error
	InviteUser(ctx context.Context, email string) error
	IsMFAEnabled(ctx context.Context, userID uuid.UUID) bool
	ProvisionMFA(ctx context.Context, userID uuid.UUID) (string, string, error)
	EnableMFA(ctx context.Context, userID uuid.UUID, secret string) (string, error)
	DisableMFA(ctx context.Context, userID uuid.UUID) error
	EmailToID(ctx context.Context, email string) (uuid.UUID, bool)
	TriggerPasswordRecovery(ctx context.Context, id uuid.UUID) error
	RecoverPassword(
		ctx context.Context,
		email string,
		token string,
	) (uuid.UUID, error)
	RegisterFromInvite(
		ctx context.Context,
		email string,
		password string,
		phone *string,
		inviteCode string,
	) (uuid.UUID, error)
	RegisterUser(
		ctx context.Context,
		email string,
		password string,
		phone *string,
	) (uuid.UUID, error)
}

// TokenIssuer is used to issue and sign different kind of tokens
type TokenIssuer interface {
	IssueAccessTokenForUser(
		user *user.SignedInUser,
		authorizationID uuid.UUID,
		clientID string,
		scopes []string,
	) (jwt.Token, error)
	Sign(token jwt.Token) ([]byte, error)
	RememberMeDuration() time.Duration
	IssueRememberMeToken(
		ctx context.Context,
		authorizationID uuid.UUID,
	) (string, error)
}

// TokenVerifier is used to verify issued tokens
type TokenVerifier interface {
	ParseAndValidateAccessToken(accessToken string) (jwt.Token, error)
}

// TokenRotator is used to rotate tokens
type TokenRotator interface {
	RotateCommonToken(
		ctx context.Context,
		tokenType tokens.CommonTokenType,
		token string,
		clientID string,
	) error

	RevokeCommonToken(
		ctx context.Context,
		tokenType tokens.CommonTokenType,
		token string,
		autID uuid.UUID,
	) error
}

// AuthorizationService is used to handle authorizations
type AuthorizationService interface {
	VerifyUserAuthorization(
		ctx context.Context,
		userID uuid.UUID,
		clientID string,
	) (*authorization.Authorization, error)
	ImplicitAuthorization(
		ctx context.Context,
		userID uuid.UUID,
		clientID string,
		scopes string,
	) (*authorization.Authorization, error)
	AuthorizationByCommonToken(
		ctx context.Context,
		tokenType string,
		token string,
	) (*authorization.Authorization, error)
}
