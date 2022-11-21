package manage

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/eisenwinter/gotrxx/config"
	"github.com/eisenwinter/gotrxx/db"
	"github.com/eisenwinter/gotrxx/events"
	"github.com/eisenwinter/gotrxx/events/event"
	"github.com/eisenwinter/gotrxx/generator"
	"github.com/eisenwinter/gotrxx/i18n"
	"github.com/eisenwinter/gotrxx/mailing"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

//this contains all the methods that a user cannot do himself
//the user.service part is everything the user can trigger and use himself proactivly

const maxIterationCycles = 100

var (
	ErrInviteOnly              = errors.New("behaivoural setting is set to only accept invited members")
	ErrTokenGenTimeout         = errors.New("could not generate a token within given cycles")
	ErrEntityAlreadyExists     = errors.New("entity already exists in system")
	ErrTokenExpired            = errors.New("supplied token has expired")
	ErrEntityInvalidTransition = errors.New("entity does not support transition")
	ErrPasswordGuidelines      = errors.New("password doesnt match password guidlines")
	ErrNotFound                = errors.New("entity not found")
)

func NewUserService(store *db.DataStore,
	log *zap.Logger,
	cfg *config.Configuration,
	mailer *mailing.Mailer,
	dispatcher *events.Dispatcher) *UserService {
	return &UserService{
		store:      store,
		log:        log,
		cfg:        cfg,
		mailer:     mailer,
		dispatcher: dispatcher,
	}
}

type UserService struct {
	store      *db.DataStore
	log        *zap.Logger
	cfg        *config.Configuration
	mailer     *mailing.Mailer
	dispatcher *events.Dispatcher
}

func (g *UserService) List(ctx context.Context, page int, pageSize int, q string, sort string) (*PaginationResponse, error) {
	apps, total, err := g.store.Users(ctx, db.ListOptions{Page: page, PageSize: pageSize, Query: q, Sort: sort})
	if err != nil {
		return nil, err
	}
	dtos := make([]*UserDTO, 0)
	for _, v := range apps {
		//Todo: reconsider 1:n querrying, but for now its paginated and
		//only used on the gotrxx-admin backend so its okay-ish
		roles, err := g.store.UserRoles(ctx, v.ID)
		if err != nil {
			return nil, err
		}
		dtos = append(dtos, userDTOfromDB(v, roles))
	}
	return &PaginationResponse{
		Total:   total,
		Entries: dtos,
	}, nil
}

func (g *UserService) ById(ctx context.Context, userID uuid.UUID) (*UserDTO, error) {
	user, err := g.store.User(ctx, userID)
	if err != nil {
		return nil, err
	}

	roles, err := g.store.UserRoles(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	return userDTOfromDB(user, roles), nil
}

func (g *UserService) currentLocale(ctx context.Context) string {
	locale := ctx.Value(i18n.ContextLangKey)
	if locale != nil && len(locale.(string)) == 2 {
		return locale.(string)
	}
	if len(g.cfg.Behaviour.DefaultLocale) == 2 {
		return g.cfg.Behaviour.DefaultLocale
	}
	return "en"
}

func (g *UserService) EmailToId(ctx context.Context, email string) (uuid.UUID, error) {
	found, id, err := g.store.IdFromEmail(ctx, email)
	if err != nil {
		g.log.Error("Unable to get matching user from store", zap.Error(err))
		return uuid.UUID{}, ErrNotFound
	}
	if !found {
		return uuid.UUID{}, ErrNotFound
	}
	return id, nil
}

func (g *UserService) ConfirmUser(ctx context.Context, id uuid.UUID) error {
	err := g.store.ManualConfirmUser(ctx, id)
	if err != nil && errors.Is(db.ErrNotFound, err) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	g.dispatcher.Dispatch(ctx, &event.UserConfirmed{
		ConfirmCode:   "",
		UserID:        id,
		AutoConfirmed: true,
	})
	return nil
}

func (g *UserService) AddUserToRole(ctx context.Context, id uuid.UUID, role string) error {
	canonicalRole := strings.ToLower(role)
	err := g.store.AddUserToRole(ctx, id, canonicalRole)
	if err != nil {
		return err
	}
	g.dispatcher.Dispatch(ctx, &event.UserAddedToRole{
		UserID: id,
		Role:   canonicalRole,
	})
	return nil
}

func (g *UserService) RemoveUserFromRole(ctx context.Context, id uuid.UUID, role string) error {
	canonicalRole := strings.ToLower(role)
	err := g.store.RemoveUserFromRole(ctx, id, canonicalRole)
	if err != nil {
		return err
	}
	g.dispatcher.Dispatch(ctx, &event.UserRemovedFromRole{
		UserID: id,
		Role:   canonicalRole,
	})
	return nil
}

var ErrUserNotInRole = errors.New("user is not in role")

func (g *UserService) VerifyUserInRole(ctx context.Context, userID uuid.UUID, role string) error {
	canonicalRole := strings.ToLower(role)
	ok, err := g.store.IsUserInRole(ctx, userID, canonicalRole)
	if err != nil {
		return err
	}
	if !ok {
		return ErrUserNotInRole
	}
	return nil
}

func (g *UserService) LockUser(ctx context.Context, id uuid.UUID, until time.Time) error {
	ok, err := g.store.LockUser(ctx, id, until)
	if err != nil {
		return err
	}
	if !ok {
		return ErrEntityInvalidTransition
	}
	g.dispatcher.Dispatch(ctx, &event.UserLocked{
		UserID:      id,
		LockedUntil: until,
	})
	return nil
}

func (g *UserService) UnlockUser(ctx context.Context, id uuid.UUID) error {
	ok, err := g.store.UnlockUser(ctx, id)
	if err != nil {
		return err
	}
	if !ok {
		return ErrEntityInvalidTransition
	}
	g.dispatcher.Dispatch(ctx, &event.UserUnlocked{
		UserID: id,
	})
	return nil
}

func (g *UserService) BanUser(ctx context.Context, id uuid.UUID) error {
	err := g.store.BanUser(ctx, id)
	if err != nil {
		return err
	}

	g.dispatcher.Dispatch(ctx, &event.UserBanned{
		UserID: id,
	})
	return nil
}

func (g *UserService) UnbanUser(ctx context.Context, id uuid.UUID) error {
	err := g.store.UnbanUser(ctx, id)
	if err != nil {
		return err
	}

	g.dispatcher.Dispatch(ctx, &event.UserUnbanned{
		UserID: id,
	})
	return nil
}

// InitialUserInvite used for docker container setup, it seeds a predefined a user invite for the admin user
// so the admin user can signup with his wanted credentials
func (g *UserService) InitialUserInvite(ctx context.Context, inviteCode string, roles []string, appIds []int) error {
	exists, err := g.store.InviteCodeExists(ctx, string(inviteCode))
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	for _, r := range roles {
		if r != "" {
			_, err = g.store.AddRole(ctx, r)
			if err != nil && !errors.Is(err, db.ErrAlreadyExists) {
				g.log.Error("Could not create role for user invite", zap.Error(err))
				return err
			}
		}
	}
	expiryDate := time.Now().Add(g.cfg.Behaviour.InviteExpiry).UTC()
	err = g.store.InviteUser(ctx, expiryDate, nil, string(inviteCode), roles, appIds...)
	if err != nil {
		g.log.Error("Could not persist user invite", zap.Error(err))
		return err
	}
	g.dispatcher.Dispatch(ctx, &event.UserInvited{
		ExpiryDate: expiryDate,
		Email:      "",
		InviteCode: string(inviteCode),
	})
	return nil
}

func (g *UserService) InviteUser(ctx context.Context, email *string, roles []string, appIds []int) (generator.RandomTokenType, error) {
	tokenGen := generator.New()
	inviteCode := tokenGen.CreatePINLikeToken()
	exists, err := g.store.InviteCodeExists(ctx, string(inviteCode))
	if err != nil {
		g.log.Error("Unable to check invite code against datastore", zap.Error(err))
		return "", err
	}
	timeout := 0
	for exists {
		exists, err = g.store.InviteCodeExists(ctx, string(inviteCode))
		if err != nil {
			g.log.Error("Unable to check invite code against datastore", zap.Error(err))
			return "", err
		}
		if exists {
			timeout++
		}
		if timeout >= maxIterationCycles {
			g.log.Error("Unable to generate new invite code")
			return "", ErrTokenGenTimeout
		}
		inviteCode = tokenGen.CreatePINLikeToken()
	}
	if email != nil {
		if ok, ierr := g.store.IsInviteable(ctx, *email); ierr != nil || !ok {
			if ierr != nil {
				return "", ierr
			}
			return "", ErrEntityAlreadyExists
		}
	}
	for _, r := range roles {
		if r != "" {
			_, err = g.store.AddRole(ctx, r)
			if err != nil && !errors.Is(err, db.ErrAlreadyExists) {
				g.log.Error("Could not create role for user invite", zap.Error(err))
				return "", err
			}
		}
	}
	expiryDate := time.Now().Add(g.cfg.Behaviour.InviteExpiry).UTC()
	err = g.store.InviteUser(ctx, expiryDate, email, string(inviteCode), roles, appIds...)
	if err != nil {
		g.log.Error("Could not persist user invite", zap.Error(err))
		return "", err
	}
	e := ""
	if email != nil {
		e = *email
		err := g.mailer.SendInviteMail(e, string(inviteCode), g.currentLocale(ctx))
		if err != nil {
			g.log.Error("Could not send invite email to user", zap.String("email", e), zap.Error(err))
		} else {
			err = g.store.SetInviteSent(ctx, e, string(inviteCode))
			if err != nil {
				g.log.Error("Could not persist sent date for invite email to user", zap.String("email", e), zap.Error(err))
			}
			g.dispatcher.Dispatch(ctx, &event.EmailInviteSent{
				InviteCode: string(inviteCode),
				Email:      e,
				Sent:       time.Now(),
			})
		}
	}
	g.dispatcher.Dispatch(ctx, &event.UserInvited{
		ExpiryDate: expiryDate,
		Email:      e,
		InviteCode: string(inviteCode),
	})
	return inviteCode, nil
}

func (g *UserService) InsertUser(ctx context.Context,
	email string,
	password string,
	phone *string,
	confirmToken *string) (uuid.UUID, error) {
	pw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return uuid.UUID{}, err
	}

	id, err := g.store.InsertUser(ctx, email, string(pw), phone, confirmToken)
	if err != nil {
		g.log.Error("Inserting user into store failed", zap.Error(err))
		return uuid.UUID{}, err
	}
	return id, nil
}
