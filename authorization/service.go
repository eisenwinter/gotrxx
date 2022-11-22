package authorization

import (
	"context"
	"errors"
	"strings"

	"github.com/eisenwinter/gotrxx/application"
	"github.com/eisenwinter/gotrxx/db"
	"github.com/eisenwinter/gotrxx/db/tables"
	"github.com/eisenwinter/gotrxx/events"
	"github.com/eisenwinter/gotrxx/events/event"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

var (
	//ErrUngrantedImplicitAutoGrant implies that theres no auto granted authorization for this user
	ErrUngrantedImplicitAutoGrant error = errors.New("implicit auto grant not granted yet")
	//ErrRetiredApplication implies that the application is in retired state and canot be used anymore
	ErrRetiredApplication error = errors.New("application is retired")
	//ErrNotFound indicates that the requested entity could not be found
	ErrNotFound error = errors.New("requested entity not found")
)

type ApplicationSupplier interface {
	ApplicationByID(ctx context.Context, id int) (*application.Application, error)
	ApplicationByClientID(ctx context.Context, clientID string) (*application.Application, error)
}

type Service struct {
	log        *zap.Logger
	store      *db.DataStore
	dispatcher *events.Dispatcher
	supplier   ApplicationSupplier
}

func NewAuthorizationService(log *zap.Logger,
	store *db.DataStore,
	dispatcher *events.Dispatcher,
	supplier ApplicationSupplier) *Service {
	return &Service{
		log:        log,
		store:      store,
		dispatcher: dispatcher,
		supplier:   supplier,
	}
}

func (s *Service) build(
	ctx context.Context,
	table *tables.AuthorizationTable,
) (*Authorization, error) {
	app, err := s.supplier.ApplicationByID(ctx, table.ApplicationID)
	if err != nil {
		return nil, err
	}
	a := &Authorization{
		id:         table.ID,
		userID:     table.UserID,
		properties: table.Properties,
		app:        app,
		revokedAt:  table.RevokedAt,
	}
	return a, nil
}

func (s *Service) AuthorizationByCommonToken(
	ctx context.Context,
	tokenType string,
	token string,
) (*Authorization, error) {
	//guranteed to be for a not revoked, not redeemed, not expired token with a not revoked auth and a not retired application
	authTable, err := s.store.ActiveAuthorizationByCommonToken(ctx, tokenType, token)
	if err != nil {
		if errors.Is(db.ErrNotFound, err) {
			return nil, ErrNotFound
		}
		s.log.Error("error fetching authorization by client id and user id", zap.Error(err))
		return nil, err
	}

	auth, err := s.build(ctx, authTable)
	if err != nil {
		s.log.Error("error fetching application for authorization", zap.Error(err))
		return nil, err
	}

	return auth, nil
}

// VerifyUserAuthorization returns a non-revoked authorization for a non-retired application
func (s *Service) VerifyUserAuthorization(
	ctx context.Context,
	userID uuid.UUID,
	clientID string,
) (*Authorization, error) {
	//guranteed to be non-revoked and application is non-retired
	authTable, err := s.store.ActiveAuthorizationByUserAndClientID(ctx, clientID, userID)
	if err != nil {
		if errors.Is(db.ErrNotFound, err) {
			app, err := s.supplier.ApplicationByClientID(ctx, clientID)
			if err != nil {
				return nil, err
			}
			if !app.IsRetired() && app.Type() == application.ImplicitGrantedApplication {
				return nil, ErrUngrantedImplicitAutoGrant
			}
		}
		s.log.Error("error fetching authorization by client id and user id", zap.Error(err))
		return nil, err
	}

	auth, err := s.build(ctx, authTable)
	if err != nil {
		s.log.Error("error fetching application for authorization", zap.Error(err))
		return nil, err
	}

	return auth, nil
}

func (s *Service) ImplicitAuthorization(
	ctx context.Context,
	userID uuid.UUID,
	clientID string,
	scopes string,
) (*Authorization, error) {
	//creates a authorization for the auto grant (done in signin now where it doesnt fit)
	app, err := s.supplier.ApplicationByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if app.IsRetired() {
		return nil, ErrRetiredApplication
	}
	//assuming scopes are already verified prior to calling this
	parsedScopes := []string{}
	trimmed := strings.TrimSpace(scopes)
	if trimmed != "" {
		parsedScopes = strings.Split(trimmed, " ")
	}

	a, err := s.store.GrantAuthorization(ctx, app.ID(), userID, map[string]interface{}{
		"auto_granted": true,
		"scopes":       parsedScopes})
	if err != nil {
		return nil, err
	}
	s.dispatcher.Dispatch(&event.AuthorizationGranted{
		AuthorizationID: a,
		ApplicationID:   app.ID(),
		UserID:          userID,
		Scopes:          parsedScopes,
	})
	r, err := s.store.AuthorizationByID(ctx, a)
	if err != nil {
		s.log.Error("Unable to fetch just created authorization", zap.Error(err))
		return nil, err
	}
	return s.build(ctx, r)
}
