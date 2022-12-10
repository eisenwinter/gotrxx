package management

import (
	"context"

	"github.com/eisenwinter/gotrxx/application"
	"github.com/eisenwinter/gotrxx/generator"
	"github.com/eisenwinter/gotrxx/manage"
	"github.com/google/uuid"
)

// Lister enables querrying paginated
// lists from the underlying datasource
type Lister interface {
	List(
		ctx context.Context,
		page int,
		pageSize int,
		q string,
		sort string,
	) (*manage.PaginationResponse, error)
}

// AuthorizationService enables managing authorizations
type AuthorizationService interface {
	Lister
	ActiveByUser(
		ctx context.Context,
		userID uuid.UUID,
	) ([]*manage.AuthorizationDTO, error)
	GrantAuthorization(
		ctx context.Context,
		userID uuid.UUID,
		clientID string,
		scope string,
	) error
	RevokeAuthorizationByClientIDAndUserID(
		ctx context.Context,
		clientID string,
		userID uuid.UUID,
	) error
}

// ApplicationService enables managing applications
type ApplicationService interface {
	Lister
	WithActiveUserAuthorizations(
		ctx context.Context,
		userID uuid.UUID,
	) ([]*manage.ApplicationDTO, error)
	ByClientID(
		ctx context.Context,
		clientID string,
	) (*manage.ApplicationDTO, error)
	CreateApplication(
		ctx context.Context,
		clientID string,
		clientSecret string,
		name string,
		flows []string,
		redirectUris []string,
		logoutURIs []string,
		confidentiality string,
		scope string,
		appType int,
		pkce bool) (int, error)
	RetireApplication(ctx context.Context, clientID string) error
	PurgeRetiredApplications(ctx context.Context) error
	AddRedirectURI(
		ctx context.Context,
		clientID string,
		redirectURI string,
	) error
	RemoveRedirectURI(
		ctx context.Context,
		clientID string,
		redirectURI string,
	) error
	AddLogoutURI(
		ctx context.Context,
		clientID string,
		logoutURI string,
	) error
	RemoveLogoutURI(
		ctx context.Context,
		clientID string,
		logoutURI string,
	) error
	AddFlow(
		ctx context.Context,
		clientID string,
		flow application.FlowType,
	) error
	RemoveFlow(
		ctx context.Context,
		clientID string,
		flow application.FlowType,
	) error
	TogglePKCE(ctx context.Context, clientID string, enable bool) error
	SetSecret(ctx context.Context, clientID string, secret string) error
}

// UserService enables managing users
type UserService interface {
	Lister
	InviteUser(
		ctx context.Context,
		email *string,
		roles []string,
		appIds []int,
	) (generator.RandomTokenType, error)
	ByID(ctx context.Context, userID uuid.UUID) (*manage.UserDTO, error)
	ConfirmUser(ctx context.Context, id uuid.UUID) error
	AddUserToRole(ctx context.Context, id uuid.UUID, role string) error
	RemoveUserFromRole(ctx context.Context, id uuid.UUID, role string) error
	BanUser(ctx context.Context, id uuid.UUID) error
	UnbanUser(ctx context.Context, id uuid.UUID) error
	UnlockUser(ctx context.Context, id uuid.UUID) error
	VerifyUserInRole(ctx context.Context, userID uuid.UUID, role string) error
}
