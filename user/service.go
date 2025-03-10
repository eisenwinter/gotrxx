package user

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/eisenwinter/gotrxx/config"
	"github.com/eisenwinter/gotrxx/db"
	"github.com/eisenwinter/gotrxx/db/tables"
	"github.com/eisenwinter/gotrxx/events/event"
	"github.com/eisenwinter/gotrxx/generator"
	"github.com/eisenwinter/gotrxx/i18n"
	"github.com/eisenwinter/gotrxx/pkg/logging"
	"github.com/eisenwinter/gotrxx/pkg/sanitize"
	"github.com/google/uuid"
	"github.com/xlzd/gotp"
	"golang.org/x/crypto/bcrypt"
)

const maxIterationCycles = 100

var (
	ErrInviteOnly = errors.New(
		"behaivoural setting is set to only accept invited members",
	)
	ErrTokenGenTimeout         = errors.New("could not generate a token within given cycles")
	ErrEntityAlreadyExists     = errors.New("entity already exists in system")
	ErrTokenExpired            = errors.New("supplied token has expired")
	ErrEntityInvalidTransition = errors.New("entity does not support transition")
	ErrPasswordGuidelines      = errors.New("password doesnt match password guidlines")
)

// Mailer handles sending mails
type Mailer interface {
	SendPasswordRecoverMail(email string, code string, language string) error
	SendConfirmMail(email string, code string, language string) error
}

// UserStorer is a datasource providing and safing user information in a persistent way
type UserStorer interface {
	UserByID(ctx context.Context, id uuid.UUID) (*db.UserData, error)
	InviteData(ctx context.Context, inviteCode string) (*db.UserInviteData, error)
	GrantAuthorization(
		ctx context.Context,
		applicationId int,
		userID uuid.UUID,
		properties tables.MapStructure,
	) (uuid.UUID, error)
	ConsumeInvite(ctx context.Context, inviteCode string) error
	IsRegistred(ctx context.Context, email string) (bool, error)
	ConfirmTokenExists(ctx context.Context, token string) (bool, error)
	IsUserInRole(ctx context.Context, id uuid.UUID, role string) (bool, error)
	SetEmail(ctx context.Context, id uuid.UUID, email string) (bool, error)
	SetPassword(
		ctx context.Context,
		id uuid.UUID,
		passwordHash string,
	) (bool, error)
	SetRecoveryToken(
		ctx context.Context,
		id uuid.UUID,
		recoveryToken string,
	) (bool, error)
	ConsumeRecoveryToken(
		ctx context.Context,
		id uuid.UUID,
		recoveryToken string,
	) (bool, error)
	DisableMFA(ctx context.Context, id uuid.UUID) (bool, error)
	EnableMFA(
		ctx context.Context,
		id uuid.UUID,
		userSecret string,
		userRecoveryKey string,
	) (bool, error)
	IDFromEmail(ctx context.Context, email string) (bool, uuid.UUID, error)
	ConfirmUser(ctx context.Context, confirmToken string) (bool, uuid.UUID, error)
}

// UserManager allows to manage user data
type UserManager interface {
	AddUserToRole(ctx context.Context, id uuid.UUID, role string) error
	InsertUser(ctx context.Context,
		email string,
		password string,
		phone *string,
		confirmToken *string) (uuid.UUID, error)
	InviteUser(
		ctx context.Context,
		email *string,
		roles []string,
		appIds []int,
	) (generator.RandomTokenType, error)
}

func New(store UserStorer,
	logger logging.Logger,
	cfg *config.Configuration,
	mailer Mailer,
	dispatcher Dispatcher,
	manager UserManager) *Service {
	return &Service{
		store:      store,
		log:        logger,
		cfg:        cfg,
		mailer:     mailer,
		dispatcher: dispatcher,
		manager:    manager,
	}
}

type Service struct {
	store      UserStorer
	log        logging.Logger
	cfg        *config.Configuration
	mailer     Mailer
	dispatcher Dispatcher
	manager    UserManager
}

func (g *Service) currentLocale(ctx context.Context) string {
	locale := ctx.Value(i18n.ContextLangKey)
	if locale != nil && len(locale.(string)) == 2 {
		return locale.(string)
	}
	if len(g.cfg.Behaviour.DefaultLocale) == 2 {
		return g.cfg.Behaviour.DefaultLocale
	}
	return "en"
}

// GetUserByID returns a !unvalidated! user data provider
func (g *Service) getUserByID(ctx context.Context, id uuid.UUID) (*db.UserData, error) {
	provider, err := g.store.UserByID(ctx, id)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return nil, ErrEntityDoesNotExist
		}
		g.log.Error("unable to get user by id", "err", err)
		return nil, err
	}
	return provider, nil
}

// RegisterFromInvite registers a user from an invite, which means the user
// will automatically be granted roles and application permissions from the invite
func (g *Service) RegisterFromInvite(
	ctx context.Context,
	email string,
	password string,
	phone *string,
	inviteCode string,
) (uuid.UUID, error) {
	invite, err := g.store.InviteData(ctx, inviteCode)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return uuid.UUID{}, ErrEntityDoesNotExist
		}
		g.log.Error("could not fetch invite data", "err", err)
		return uuid.UUID{}, err
	}
	if invite.Expires.Before(time.Now().UTC()) {
		return uuid.UUID{}, ErrTokenExpired
	}
	id, err := g.register(ctx, email, password, phone)
	if err != nil {
		g.log.Error("unable to register from invite", "err", err)
		return uuid.UUID{}, err
	}
	for _, v := range invite.Roles {
		err = g.manager.AddUserToRole(ctx, id, v)
		if err != nil {
			g.log.Error(
				"could not add user to role",
				"role", v,
				"user_id", id.String(),
				"err", err,
			)
		}
	}

	for _, v := range invite.PreApplicationAuthorization {
		parsedScopes := []string{}
		if v.Scopes != "" {
			parsedScopes = strings.Split(v.Scopes, " ")
		}
		aid, err := g.store.GrantAuthorization(
			ctx,
			v.ApplicationID,
			id,
			map[string]interface{}{
				"auto_granted": true,
				"from_invite":  true,
				"scopes":       parsedScopes,
			},
		)
		if err != nil {
			g.log.Error(
				"could not auto grant user auth for invite application",
				"app", v.ApplicationID,
				"user_id", id.String(),
				"err", err,
			)
		} else {
			g.dispatcher.Dispatch(&event.AuthorizationGranted{
				AuthorizationID: aid,
				ApplicationID:   v.ApplicationID,
				UserID:          id,
				Scopes:          parsedScopes,
			})

		}
	}

	err = g.store.ConsumeInvite(ctx, inviteCode)
	if err != nil {
		g.log.Warn(
			"could not consume invite code",
			"invite_code", sanitize.UserInputString(inviteCode),
			"err", err,
		)
	} else {
		g.dispatcher.Dispatch(&event.UserInviteConsumed{
			InviteCode: inviteCode,
			UserID:     id,
		})
	}

	return id, nil
}

// RegisterUser registers a user from user supplied data
func (g *Service) RegisterUser(
	ctx context.Context,
	email string,
	password string,
	phone *string,
) (uuid.UUID, error) {
	if g.cfg.Behaviour.InviteOnly {
		return uuid.UUID{}, ErrInviteOnly
	}
	return g.register(ctx, email, password, phone)
}

// shared register boilerplate
func (g *Service) register(
	ctx context.Context,
	email string,
	password string,
	phone *string,
) (uuid.UUID, error) {
	if len(password) < g.cfg.Behaviour.PasswordMinLength {
		return uuid.UUID{}, ErrPasswordGuidelines
	}
	regis, err := g.store.IsRegistred(ctx, email)
	if err != nil {
		g.log.Error(
			"Could not check registration in data store",
			"email", sanitize.UserInputString(email),
			"err", err,
		)
		return uuid.UUID{}, err
	}
	if regis {
		return uuid.UUID{}, ErrEntityAlreadyExists
	}

	var confirmToken *string
	confirmToken = nil
	if !g.cfg.Behaviour.AutoConfirmUsers {
		gen := generator.New()
		exists := true
		timeout := 0
		for exists {
			token := gen.CreateSecureToken()
			exists, err = g.store.ConfirmTokenExists(ctx, string(token))
			if err != nil {
				g.log.Error("could not check if confirm token already exists", "err", err)
				return uuid.UUID{}, err
			}
			timeout++
			if timeout >= maxIterationCycles {
				return uuid.UUID{}, ErrTokenGenTimeout
			}
			if !exists {
				s := string(token)
				confirmToken = &s
			}
		}
	}
	id, err := g.manager.InsertUser(ctx, email, password, phone, confirmToken)
	if err != nil {
		return uuid.UUID{}, err
	}

	g.dispatcher.Dispatch(&event.UserSignup{
		UserID: id,
		Email:  email,
	})

	if g.cfg.Behaviour.AutoConfirmUsers {
		g.dispatcher.Dispatch(&event.UserConfirmed{
			UserID:        id,
			AutoConfirmed: true,
			ConfirmCode:   "",
		})

	}
	if confirmToken != nil {
		t := *confirmToken
		err = g.mailer.SendConfirmMail(email, t, g.currentLocale(ctx))
		if err != nil {
			g.log.Error("registration mail could not be sent", "err", err)
		} else {
			g.dispatcher.Dispatch(&event.EmailSignupConfirmSent{
				UserID:       id,
				ConfirmToken: t,
				Sent:         time.Now(),
				Email:        email,
			})
			if t != "" {
				g.log.Debug("confirm code sent", "confirm_token", *confirmToken)
			}

		}
	}

	return id, nil
}

// ConfirmUser confirms a user account with the supplied token
func (g *Service) ConfirmUser(ctx context.Context, token string) error {
	ok, id, err := g.store.ConfirmUser(ctx, token)
	if err != nil {
		g.log.Error(
			"Could not confirm in data store",
			"token", sanitize.UserInputString(token),
			"err", err,
		)
		return err
	}
	if !ok {
		return ErrEntityDoesNotExist
	}
	g.dispatcher.Dispatch(&event.UserConfirmed{
		ConfirmCode:   token,
		UserID:        id,
		AutoConfirmed: false,
	})
	return nil
}

func (g *Service) EmailToID(ctx context.Context, email string) (uuid.UUID, bool) {
	found, id, err := g.store.IDFromEmail(ctx, email)
	if err != nil {
		g.log.Error("unable to get matching user from store", "err", err)
		return uuid.UUID{}, false
	}
	return id, found
}

// ProvisionMFA returns a new secret and  a otpauth:// url if success
func (g *Service) ProvisionMFA(ctx context.Context, userID uuid.UUID) (string, string, error) {
	ud, err := g.getUserByID(ctx, userID)
	if err != nil {
		return "", "", err
	}
	secret := gotp.RandomSecret(64)
	totp := gotp.NewDefaultTOTP(secret)
	uri := totp.ProvisioningUri(ud.Email, g.cfg.Behaviour.Name)
	return secret, uri, nil
}

// EnableMFA enables multi factor auth for a user, this should only be called after ProvisionMFA
// it returns a recovery code which the user should note in case of device loss to still access his account
func (g *Service) EnableMFA(ctx context.Context, userID uuid.UUID, secret string) (string, error) {
	recoveryKey := generator.New().CreateSecureTokenWithSize(16)
	ok, err := g.store.EnableMFA(ctx, userID, secret, string(recoveryKey))
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrEntityInvalidTransition
	}
	g.dispatcher.Dispatch(&event.UserMFAEnabled{
		UserID: userID,
	})
	return string(recoveryKey), nil
}

// DisableMFA disables multi factor for a user IF the user has  multifactor enabled
func (g *Service) DisableMFA(ctx context.Context, userID uuid.UUID) error {
	ok, err := g.store.DisableMFA(ctx, userID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrEntityInvalidTransition
	}
	g.dispatcher.Dispatch(&event.UserMFADisabled{
		UserID: userID,
	})
	return nil
}

// IsMFAEnabled check if user has mfa enabled
func (g *Service) IsMFAEnabled(ctx context.Context, userID uuid.UUID) bool {
	ud, err := g.getUserByID(ctx, userID)
	if err != nil {
		return false
	}
	return ud.TwoFactor
}

// TriggerPasswordRecovery takes all step necassary to recover a user password
// if successful it will send a email to the user
func (g *Service) TriggerPasswordRecovery(ctx context.Context, id uuid.UUID) error {
	gen := generator.New()
	//those do not need checks if they are unique as they need a combination of email and token
	token := gen.CreateSecureToken()
	ok, err := g.store.SetRecoveryToken(ctx, id, string(token))
	if err != nil {
		g.log.Error("unable to set recovery token in store", "err", err)
		return err
	}
	if !ok {
		return ErrEntityDoesNotExist
	}
	g.dispatcher.Dispatch(&event.UserPasswordRecoveryRequested{
		UserID: id,
	})
	ud, err := g.getUserByID(ctx, id)
	if err != nil {
		return err
	}
	err = g.mailer.SendPasswordRecoverMail(ud.Email, string(token), g.currentLocale(ctx))
	if err != nil {
		g.log.Error("unable to send recovery email", "err", err)
		return err
	}
	g.dispatcher.Dispatch(&event.EmailPasswordRecoverySent{
		UserID:       id,
		Email:        ud.Email,
		ConfirmToken: string(token),
		Sent:         time.Now(),
	})

	return nil
}

// RecoverPassword is used to reset the password from the token obtained from the recovery mail
func (g *Service) RecoverPassword(
	ctx context.Context,
	email string,
	token string,
) (uuid.UUID, error) {
	id, found := g.EmailToID(ctx, email)
	if !found {
		return uuid.UUID{}, ErrEntityDoesNotExist
	}
	//consuming the recovery token also resets blocks
	ok, err := g.store.ConsumeRecoveryToken(ctx, id, token)
	if err != nil {
		return uuid.UUID{}, err
	}
	if !ok {
		return uuid.UUID{}, ErrEntityDoesNotExist
	}
	g.dispatcher.Dispatch(&event.UserPasswordRecoveryUsed{
		UserID: id,
		Email:  email,
		Token:  token,
	})
	return id, nil
}

// ChangePassword sets a new password for the supplied user id
func (g *Service) ChangePassword(ctx context.Context, id uuid.UUID, password string) error {
	if len(password) < g.cfg.Behaviour.PasswordMinLength {
		return ErrPasswordGuidelines
	}
	pw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	ok, err := g.store.SetPassword(ctx, id, string(pw))
	if err != nil {
		return err
	}
	if !ok {
		return ErrEntityDoesNotExist
	}
	g.dispatcher.Dispatch(&event.UserPasswordChanged{
		UserID: id,
	})
	return nil
}

// ChangeEmail changes the users email address, this will not trigger a reconfirm, be vary of that
func (g *Service) ChangeEmail(ctx context.Context, id uuid.UUID, email string) error {
	exists, err := g.store.IsRegistred(ctx, email)
	if err != nil {
		g.log.Error("could not check registred status from store", "err", err)
		return err
	}
	if exists {
		return ErrEntityInvalidTransition
	}
	ok, err := g.store.SetEmail(ctx, id, email)
	if err != nil {
		return err
	}
	if !ok {
		return ErrEntityDoesNotExist
	}
	g.dispatcher.Dispatch(&event.UserEmailChanged{
		UserID: id,
		Email:  email,
	})
	return nil
}

// InRole check if given user id is in role
func (g *Service) InRole(ctx context.Context, id uuid.UUID, role string) bool {
	ok, err := g.store.IsUserInRole(ctx, id, role)
	if err != nil {
		return false
	}
	return ok
}

// InviteUser is a user initiaized invite without roles and apps
func (g *Service) InviteUser(ctx context.Context, email string) error {
	_, err := g.manager.InviteUser(ctx, &email, []string{}, []int{})
	return err
}
