package manage

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/eisenwinter/gotrxx/application"
	"github.com/eisenwinter/gotrxx/config"
	"github.com/eisenwinter/gotrxx/db"
	"github.com/eisenwinter/gotrxx/events"
	"github.com/eisenwinter/gotrxx/events/event"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

var ErrApplicationClientIDExists = errors.New("application with client_id already exists")
var ErrAppIsRetired = errors.New("application is retired")
var ErrInvalidSecret = errors.New("invalid secret")

type ApplicationService struct {
	store      *db.DataStore
	log        *zap.Logger
	cfg        *config.Configuration
	dispatcher *events.Dispatcher
}

func (a *ApplicationService) CreateApplication(
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
	pkce bool) (int, error) {

	f := make([]application.FlowType, len(flows))
	for i, v := range flows {
		f[i] = application.FlowType(v)
	}
	props := make(map[string]interface{})
	props["allowed_flows"] = f
	props["pkce"] = pkce
	parsedScopes := make([]string, 0)
	if scope != "" {
		parsedScopes = strings.Split(scope, " ")
	}
	props["scopes"] = parsedScopes
	if redirectUris == nil {
		redirectUris = []string{}
	}
	if logoutURIs == nil {
		logoutURIs = []string{}
	}
	props["logout_uris"] = logoutURIs
	props["redirect_uris"] = redirectUris
	var secret *string
	if clientSecret != "" {
		pw, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
		if err != nil {
			return 0, err
		}
		p := string(pw)
		secret = &p
	}
	id, err := a.store.CreateApplication(
		ctx,
		appType,
		clientID,
		secret,
		name,
		confidentiality,
		props,
	)
	if err != nil {
		if errors.Is(db.ErrAlreadyExists, err) {
			return 0, ErrApplicationClientIDExists
		}
		return 0, err
	}
	a.dispatcher.Dispatch(&event.ApplicationCreated{
		ApplicationID:   id,
		ClientID:        clientID,
		ApplicationName: name,
	})
	return id, err
}

func (a *ApplicationService) PurgeRetiredApplications(ctx context.Context) error {
	affectedClientIds, err := a.store.DeleteAllRetiredApplications(ctx)
	if err != nil {
		return err
	}
	a.dispatcher.Dispatch(&event.AllRetiredApplicationsPurged{
		AffectedClientIDs: affectedClientIds,
	})
	return nil
}

func (a *ApplicationService) RetireApplication(ctx context.Context, clientID string) error {
	app, err := a.store.ApplicationByClientID(ctx, clientID)
	if err != nil {
		return err
	}
	if app.RetiredOn != nil {
		return ErrAppIsRetired
	}
	_, _, err = a.store.RetireApplication(ctx, app.ID)
	if err != nil {
		return err
	}
	a.dispatcher.Dispatch(&event.ApplicationRetired{
		ApplicationID:   app.ID,
		ClientID:        clientID,
		ApplicationName: app.Name,
	})
	return nil
}

func (a *ApplicationService) TogglePKCE(ctx context.Context, clientID string, enable bool) error {
	app, err := a.store.ApplicationByClientID(ctx, clientID)
	if err != nil {
		return err
	}
	app.Properties["pkce"] = enable
	err = a.store.UpdateApplicationProperties(ctx, clientID, app.Properties)
	if err != nil {
		return err
	}
	a.dispatcher.Dispatch(&event.ApplicationSettingsChanged{
		ApplicationID:   app.ID,
		ClientID:        clientID,
		ApplicationName: app.Name,
		Property:        "pkce",
		Value:           fmt.Sprintf("%v", enable),
	})
	return nil
}

func (a *ApplicationService) AddRedirectURI(
	ctx context.Context,
	clientID string,
	redirectURI string,
) error {
	app, err := a.store.ApplicationByClientID(ctx, clientID)
	if err != nil {
		return err
	}
	for _, v := range app.Properties["redirect_uris"].([]interface{}) {
		if v == redirectURI {
			return nil
		}
	}
	app.Properties["redirect_uris"] = append(
		app.Properties["redirect_uris"].([]interface{}),
		redirectURI,
	)
	err = a.store.UpdateApplicationProperties(ctx, clientID, app.Properties)
	if err != nil {
		return err
	}
	a.dispatcher.Dispatch(&event.ApplicationSettingsChanged{
		ApplicationID:   app.ID,
		ClientID:        clientID,
		ApplicationName: app.Name,
		Property:        "redirect_uri",
		Value:           fmt.Sprintf("(+)%s", redirectURI),
	})
	return nil
}

func (a *ApplicationService) RemoveRedirectURI(
	ctx context.Context,
	clientID string,
	redirectURI string,
) error {
	app, err := a.store.ApplicationByClientID(ctx, clientID)
	if err != nil {
		return err
	}
	exists := false
	for _, v := range app.Properties["redirect_uris"].([]interface{}) {
		if v == redirectURI {
			exists = true
		}
	}
	if !exists {
		return nil
	}
	newUris := make([]string, 0)
	for _, v := range app.Properties["redirect_uris"].([]interface{}) {
		if v != redirectURI {
			newUris = append(newUris, v.(string))
		}
	}
	app.Properties["redirect_uris"] = newUris
	err = a.store.UpdateApplicationProperties(ctx, clientID, app.Properties)
	if err != nil {
		return err
	}
	a.dispatcher.Dispatch(&event.ApplicationSettingsChanged{
		ApplicationID:   app.ID,
		ClientID:        clientID,
		ApplicationName: app.Name,
		Property:        "redirect_uri",
		Value:           fmt.Sprintf("(-)%s", redirectURI),
	})
	return nil
}

func (a *ApplicationService) AddLogoutURI(
	ctx context.Context,
	clientID string,
	logoutURI string,
) error {
	app, err := a.store.ApplicationByClientID(ctx, clientID)
	if err != nil {
		return err
	}
	for _, v := range app.Properties["logout_uris"].([]interface{}) {
		if v == logoutURI {
			return nil
		}
	}
	app.Properties["logout_uris"] = append(app.Properties["logout_uris"].([]interface{}), logoutURI)
	err = a.store.UpdateApplicationProperties(ctx, clientID, app.Properties)
	if err != nil {
		return err
	}
	a.dispatcher.Dispatch(&event.ApplicationSettingsChanged{
		ApplicationID:   app.ID,
		ClientID:        clientID,
		ApplicationName: app.Name,
		Property:        "logout_uri",
		Value:           fmt.Sprintf("(+)%s", logoutURI),
	})
	return nil
}

func (a *ApplicationService) RemoveLogoutURI(
	ctx context.Context,
	clientID string,
	logoutURI string,
) error {
	app, err := a.store.ApplicationByClientID(ctx, clientID)
	if err != nil {
		return err
	}
	exists := false
	for _, v := range app.Properties["logout_uris"].([]interface{}) {
		if v == logoutURI {
			exists = true
		}
	}
	if !exists {
		return nil
	}
	newUris := make([]string, 0)
	for _, v := range app.Properties["logout_uris"].([]interface{}) {
		if v != logoutURI {
			newUris = append(newUris, v.(string))
		}
	}
	app.Properties["logout_uris"] = newUris
	err = a.store.UpdateApplicationProperties(ctx, clientID, app.Properties)
	if err != nil {
		return err
	}
	a.dispatcher.Dispatch(&event.ApplicationSettingsChanged{
		ApplicationID:   app.ID,
		ClientID:        clientID,
		ApplicationName: app.Name,
		Property:        "logout_uri",
		Value:           fmt.Sprintf("(-)%s", logoutURI),
	})
	return nil
}

func (a *ApplicationService) AddFlow(
	ctx context.Context,
	clientID string,
	flow application.FlowType,
) error {
	app, err := a.store.ApplicationByClientID(ctx, clientID)
	if err != nil {
		return err
	}
	for _, v := range app.Properties["allowed_flows"].([]interface{}) {
		if v == flow {
			return nil
		}
	}
	app.Properties["allowed_flows"] = append(app.Properties["allowed_flows"].([]interface{}), flow)
	err = a.store.UpdateApplicationProperties(ctx, clientID, app.Properties)
	if err != nil {
		return err
	}
	a.dispatcher.Dispatch(&event.ApplicationSettingsChanged{
		ApplicationID:   app.ID,
		ClientID:        clientID,
		ApplicationName: app.Name,
		Property:        "allowed_flow",
		Value:           fmt.Sprintf("(+)%s", flow),
	})
	return nil
}

func (a *ApplicationService) RemoveFlow(
	ctx context.Context,
	clientID string,
	flow application.FlowType,
) error {
	app, err := a.store.ApplicationByClientID(ctx, clientID)
	if err != nil {
		return err
	}
	exists := false
	for _, v := range app.Properties["allowed_flows"].([]interface{}) {
		if v == string(flow) {
			exists = true
		}
	}
	if !exists {
		return nil
	}
	newFlows := make([]string, 0)
	for _, v := range app.Properties["allowed_flows"].([]interface{}) {
		if v != string(flow) {
			newFlows = append(newFlows, v.(string))
		}
	}
	app.Properties["allowed_flows"] = newFlows
	err = a.store.UpdateApplicationProperties(ctx, clientID, app.Properties)
	if err != nil {
		return err
	}
	a.dispatcher.Dispatch(&event.ApplicationSettingsChanged{
		ApplicationID:   app.ID,
		ClientID:        clientID,
		ApplicationName: app.Name,
		Property:        "allowed_flow",
		Value:           fmt.Sprintf("(-)%s", flow),
	})
	return nil
}

func (a *ApplicationService) SetSecret(ctx context.Context, clientID string, secret string) error {
	if secret == "" {
		return ErrInvalidSecret
	}
	app, err := a.store.ApplicationByClientID(ctx, clientID)
	if err != nil {
		return err
	}
	pw, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	p := string(pw)
	err = a.store.SetApplicationSecret(ctx, clientID, p)
	if err != nil {
		return err
	}
	a.dispatcher.Dispatch(&event.ApplicationSettingsChanged{
		ApplicationID:   app.ID,
		ClientID:        clientID,
		ApplicationName: app.Name,
		Property:        "client_secret",
		Value:           "[redacted]",
	})
	return nil
}

func (a *ApplicationService) List(
	ctx context.Context,
	page int,
	pageSize int,
	q string,
	sort string,
) (*PaginationResponse, error) {
	apps, total, err := a.store.Applications(
		ctx,
		db.ListOptions{Page: page, PageSize: pageSize, Query: q, Sort: sort},
	)
	if err != nil {
		return nil, err
	}
	dtos := make([]*ApplicationDTO, 0)
	for _, v := range apps {
		dtos = append(dtos, applicationDTOfromDB(v))
	}
	return &PaginationResponse{
		Total:   total,
		Entries: dtos,
	}, nil
}

func (a *ApplicationService) WithActiveUserAuthorizations(
	ctx context.Context,
	userID uuid.UUID,
) ([]*ApplicationDTO, error) {
	apps, err := a.store.ActiveApplicationsWithUserAuthorizations(ctx, userID)
	if err != nil {
		return nil, err
	}
	dtos := make([]*ApplicationDTO, 0)
	for _, v := range apps {
		dtos = append(dtos, applicationDTOfromDB(v))
	}
	return dtos, nil
}

func (a *ApplicationService) ByClientID(
	ctx context.Context,
	clientID string,
) (*ApplicationDTO, error) {
	app, err := a.store.ApplicationByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	return applicationDTOfromDB(app), nil
}

func NewApplicationSevice(store *db.DataStore,
	log *zap.Logger,
	cfg *config.Configuration,
	dispatcher *events.Dispatcher) *ApplicationService {

	return &ApplicationService{
		store:      store,
		log:        log,
		cfg:        cfg,
		dispatcher: dispatcher,
	}
}
