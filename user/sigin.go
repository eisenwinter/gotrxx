package user

import (
	"context"
	"errors"
	"time"

	"github.com/eisenwinter/gotrxx/config"
	"github.com/eisenwinter/gotrxx/db"
	"github.com/eisenwinter/gotrxx/events"
	"github.com/eisenwinter/gotrxx/events/event"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type UserLocker interface {
	LockUser(ctx context.Context, id uuid.UUID, until time.Time) error
}

type Dispatcher interface {
	Dispatch(event events.Event)
}

type LoginStorer interface {
}

type SigninService struct {
	store      *db.DataStore
	log        *zap.Logger
	cfg        *config.BehaviourConfiguration
	dispatcher Dispatcher
	userLocker UserLocker
}

func NewSignInService(store *db.DataStore,
	log *zap.Logger,
	cfg *config.BehaviourConfiguration,
	dispatcher Dispatcher,
	userLocker UserLocker) *SigninService {
	return &SigninService{
		store:      store,
		log:        log,
		cfg:        cfg,
		dispatcher: dispatcher,
		userLocker: userLocker,
	}
}

var (
	ErrEntityDoesNotExist       = errors.New("entity does not exist")
	ErrEntityOperationForbidden = errors.New("entity does not support operation")
	ErrInvalidCredentials       = errors.New("invalid credentials")
	ErrMFARequired              = errors.New("entity requires mfa")
	ErrInvalidOTP               = errors.New(
		"supplied one time password was not correct or already consumed",
	)
)

type SignedInUser struct {
	UserID uuid.UUID
	Email  string
	Roles  []string
}

// CanLogin checks if a user is eligble to login (not lockedout, not banned, not unconfirmed)
func (g *SigninService) CanLogin(ctx context.Context, userID uuid.UUID) (bool, error) {
	ud, err := g.store.UserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return false, ErrEntityDoesNotExist
		}
		return false, err
	}
	provider := &userSignin{ud: ud}
	return provider.CanLogin(), nil
}

// UserFromSubject returns a user by id, this should be only used in special cases
func (g *SigninService) UserFromSubject(
	ctx context.Context,
	userID uuid.UUID,
) (*SignedInUser, error) {
	ud, err := g.store.UserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return nil, ErrEntityDoesNotExist
		}
		return nil, err
	}
	provider := &userSignin{ud: ud}
	if !provider.CanLogin() {
		return nil, ErrEntityOperationForbidden
	}
	user := &SignedInUser{
		UserID: provider.ID(),
		Email:  ud.Email,
		Roles:  ud.Roles,
	}
	return user, nil
}

// SignInByIDFromToken creates a signed in user after the supplied token type has been
// validated - do not use this without validating the token before!
func (g *SigninService) SignInByIDFromToken(
	ctx context.Context,
	userID uuid.UUID,
	tokenType string,
) (*SignedInUser, error) {
	ud, err := g.store.UserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return nil, ErrEntityDoesNotExist
		}
		return nil, err
	}
	provider := &userSignin{ud: ud}
	if !provider.CanLogin() {
		return nil, ErrEntityOperationForbidden
	}
	g.dispatcher.Dispatch(&event.UserSignedInByToken{
		UserID:    provider.ID(),
		TokenType: tokenType,
	})
	user := &SignedInUser{
		UserID: provider.ID(),
		Email:  ud.Email,
		Roles:  ud.Roles,
	}
	return user, nil
}

// InitializeMFA marks a otp as pending
func (g *SigninService) InitializeMFA(ctx context.Context, email string) error {
	ud, err := g.store.UserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return ErrEntityDoesNotExist
		}
		g.log.Error("unexpected date store error", zap.Error(err))
		return err
	}
	provider := &userSignin{ud: ud}
	if !provider.CanLogin() {
		return ErrEntityOperationForbidden
	}
	if !provider.MFAEnabled() {
		return ErrEntityOperationForbidden
	}

	return g.store.SetOTPPending(ctx, provider.ID(), true)
}

// Validate validates a password, this is used for user settings
// which require reentering the password to change those things
// this method is exclusively only to be used for this not any other things
// as it doesnt increase lockout counts and check MFA settings
func (g *SigninService) Validate(ctx context.Context, id uuid.UUID, password string) error {
	ud, err := g.store.UserByID(ctx, id)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return ErrEntityDoesNotExist
		}
		g.log.Error("unexpected date store error", zap.Error(err))
		return err
	}
	provider := &userSignin{ud: ud}
	if !provider.CanLogin() {
		return ErrEntityOperationForbidden
	}
	ok := provider.ValidatePassword(password)
	if !ok {
		return ErrInvalidCredentials
	}
	return nil
}

// SignInMFA signs in the user with the credentials and the OTP
func (g *SigninService) SignInMFA(
	ctx context.Context,
	email string,
	password string,
	otp string,
) (*SignedInUser, error) {
	ud, err := g.store.UserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return nil, ErrEntityDoesNotExist
		}
		g.log.Error("unexpected date store error", zap.Error(err))
		return nil, err
	}
	provider := &userSignin{ud: ud}
	if !provider.CanLogin() {
		return nil, ErrEntityOperationForbidden
	}
	ok := provider.ValidatePassword(password)
	if !ok {
		if g.cfg.AutoLockoutCount > 0 && provider.CurrentFailureCount() >= g.cfg.AutoLockoutCount {
			err = g.userLocker.LockUser(
				ctx,
				provider.ID(),
				time.Now().UTC().Add(g.cfg.AutoLockoutDuration),
			)
			if err != nil {
				g.log.Error("could not lock user after failure count exceeded", zap.Error(err))
			}
			return nil, ErrEntityOperationForbidden
		}
		err = g.store.SetFailureCount(ctx, provider.ID(), provider.CurrentFailureCount()+1)
		if err != nil {
			g.log.Error("unable to reset failure count", zap.Error(err))
		}
		return nil, ErrInvalidCredentials
	}
	if provider.MFAEnabled() {
		if otp == "" {
			return nil, ErrMFARequired
		}
		err = provider.ValidateOTP(otp)
		if err != nil {
			return nil, ErrInvalidOTP
		}
		err = g.store.SetOTPPending(ctx, provider.ID(), false)
		if err != nil {
			g.log.Error("unable to reset otp timestamp", zap.Error(err))
		}
	}
	g.dispatcher.Dispatch(&event.UserLogin{
		UserID: provider.ID(),
	})
	if provider.CurrentFailureCount() > 0 {
		err = g.store.SetFailureCount(ctx, provider.ID(), 0)
		if err != nil {
			g.log.Error("unable to reset failure count", zap.Error(err))
		}
	}

	user := &SignedInUser{
		UserID: provider.ID(),
		Email:  ud.Email,
		Roles:  ud.Roles,
	}
	return user, nil
}

// SignIn signs in a user with the supplied credentials
func (g *SigninService) SignIn(
	ctx context.Context,
	email string,
	password string,
) (*SignedInUser, error) {
	return g.SignInMFA(ctx, email, password, "")
}
