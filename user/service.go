package user

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/eisenwinter/gotrxx/config"
	"github.com/eisenwinter/gotrxx/db"
	"github.com/eisenwinter/gotrxx/events/event"
	"github.com/eisenwinter/gotrxx/generator"
	"github.com/eisenwinter/gotrxx/i18n"
	"github.com/eisenwinter/gotrxx/mailing"
	"github.com/eisenwinter/gotrxx/manage"
	"github.com/google/uuid"
	"github.com/xlzd/gotp"
	"go.uber.org/zap"
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

func New(store *db.DataStore,
	logger *zap.Logger,
	cfg *config.Configuration,
	mailer *mailing.Mailer,
	dispatcher Dispatcher,
	manager *manage.UserService) *Service {
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
	store      *db.DataStore
	log        *zap.Logger
	cfg        *config.Configuration
	mailer     *mailing.Mailer
	dispatcher Dispatcher
	manager    *manage.UserService
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
		g.log.Error("Unable to get user by id", zap.Error(err))
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
		g.log.Error("could not fetch invite data", zap.Error(err))
		return uuid.UUID{}, err
	}
	if invite.Expires.Before(time.Now().UTC()) {
		return uuid.UUID{}, ErrTokenExpired
	}
	id, err := g.register(ctx, email, password, phone)
	if err != nil {
		g.log.Error("unable to register from invite", zap.Error(err))
		return uuid.UUID{}, err
	}
	for _, v := range invite.Roles {
		err = g.manager.AddUserToRole(ctx, id, v)
		if err != nil {
			g.log.Error(
				"could not add user to role",
				zap.String("role", v),
				zap.String("user_id", id.String()),
				zap.Error(err),
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
				zap.Int("app", v.ApplicationID),
				zap.String("user_id", id.String()),
				zap.Error(err),
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
			zap.String("invite_code", inviteCode),
			zap.Error(err),
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
			zap.String("email", email),
			zap.Error(err),
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
				g.log.Error("Could not check if confirm token already exists", zap.Error(err))
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
			g.log.Error("Registration mail could not be sent", zap.Error(err))
		} else {

			g.dispatcher.Dispatch(&event.EmailSignupConfirmSent{
				UserID:       id,
				ConfirmToken: t,
				Sent:         time.Now(),
				Email:        email,
			})
			if confirmToken != nil {
				g.log.Debug("Confirm code sent", zap.String("confirm_token", *confirmToken))
			}

		}
	}

	return id, nil
}

// ConfirmUser confirms a user account with the supplied token
func (g *Service) ConfirmUser(ctx context.Context, token string) error {
	ok, id, err := g.store.ConfirmUser(ctx, token)
	if err != nil {
		g.log.Error("Could not confirm in data store", zap.String("token", token), zap.Error(err))
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
		g.log.Error("Unable to get matching user from store", zap.Error(err))
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
		g.log.Error("Unable to set recovery token in store", zap.Error(err))
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
		g.log.Error("Unable to send recovery email", zap.Error(err))
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
		g.log.Error("could not check registred status from store", zap.Error(err))
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
