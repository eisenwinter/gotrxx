package manage

import (
	"context"
	"errors"
	"strings"

	"github.com/eisenwinter/gotrxx/config"
	"github.com/eisenwinter/gotrxx/db"
	"github.com/eisenwinter/gotrxx/events"
	"github.com/eisenwinter/gotrxx/events/event"
	"github.com/eisenwinter/gotrxx/pkg/logging"
	"github.com/google/uuid"
)

type AuthorizationService struct {
	store      *db.DataStore
	log        logging.Logger
	cfg        *config.Configuration
	dispatcher *events.Dispatcher
}

func (a *AuthorizationService) ActiveByUser(
	ctx context.Context,
	userID uuid.UUID,
) ([]*AuthorizationDTO, error) {
	auths, err := a.store.ActiveAuthorizationsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	dtos := make([]*AuthorizationDTO, 0)
	for _, v := range auths {
		dtos = append(dtos, authorizationDTOfromDB(v))
	}
	return dtos, nil
}

func (a *AuthorizationService) List(
	ctx context.Context,
	page int,
	pageSize int,
	q string,
	sort string,
) (*PaginationResponse, error) {
	auths, total, err := a.store.Authorizations(
		ctx,
		db.ListOptions{Page: page, PageSize: pageSize, Query: q, Sort: sort},
	)
	if err != nil {
		return nil, err
	}
	dtos := make([]*AuthorizationDTO, 0)
	for _, v := range auths {
		dtos = append(dtos, authorizationDTOfromDB(v))
	}
	return &PaginationResponse{
		Total:   total,
		Entries: dtos,
	}, nil
}

func (a *AuthorizationService) GrantAuthorization(
	ctx context.Context,
	userID uuid.UUID,
	clientID string,
	scope string,
) error {
	app, err := a.store.ApplicationByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(db.ErrNotFound, err) {
			return ErrNotFound
		}
		return err
	}
	parsedScopes := []string{}
	if scope != "" {
		parsedScopes = strings.Split(scope, " ")
	}
	aid, err := a.store.GrantAuthorization(
		ctx,
		app.ID,
		userID,
		map[string]interface{}{"auto_granted": false, "from_invite": false, "scopes": parsedScopes},
	)
	if err != nil {
		return err
	}
	a.dispatcher.Dispatch(&event.AuthorizationGranted{
		AuthorizationID: aid,
		ApplicationID:   app.ID,
		UserID:          userID,
		Scopes:          parsedScopes,
	})
	return nil
}

func (a *AuthorizationService) RevokeAuthorizationByClientIDAndUserID(
	ctx context.Context,
	clientID string,
	userID uuid.UUID,
) error {
	auth, err := a.store.ActiveAuthorizationByUserAndClientID(ctx, clientID, userID)
	if err != nil {
		if errors.Is(db.ErrNotFound, err) {
			return ErrNotFound
		}
		return err
	}
	if auth.RevokedAt != nil {
		return ErrEntityInvalidTransition
	}
	affected, err := a.store.RevokeAuthorization(ctx, auth.ID)
	if err != nil {
		return err
	}
	a.dispatcher.Dispatch(&event.AuthorizationRevoked{
		AuthorizationID: auth.ID,
		TokensAffected:  affected,
		ApplicationID:   auth.ApplicationID,
		UserID:          auth.UserID,
	})
	return nil
}

func (a *AuthorizationService) RevokeAuthorizationClientIDAndEmail(
	ctx context.Context,
	clientID string,
	email string,
) error {
	found, userID, err := a.store.IDFromEmail(ctx, email)
	if err != nil {
		if errors.Is(db.ErrNotFound, err) {
			return ErrNotFound
		}
		return err
	}
	if !found {
		return ErrNotFound
	}

	return a.RevokeAuthorizationByClientIDAndUserID(ctx, clientID, userID)
}

func NewAuthorizationService(store *db.DataStore,
	log logging.Logger,
	cfg *config.Configuration,
	dispatcher *events.Dispatcher) *AuthorizationService {

	return &AuthorizationService{
		store:      store,
		log:        log,
		cfg:        cfg,
		dispatcher: dispatcher,
	}
}
