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
	"github.com/eisenwinter/gotrxx/pkg/logging"
	"github.com/eisenwinter/gotrxx/pkg/sanitize"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

//this contains all the methods that a user cannot do himself
//the user.service part is everything the user can trigger and use himself proactivly

const maxIterationCycles = 100

var (
	// ErrInviteOnly indicates a invite only setup - only invited members may be accepted
	ErrInviteOnly = errors.New(
		"behaivoural setting is set to only accept invited members",
	)
	// ErrTokenGenTimeout indicates a token generation has timed out
	ErrTokenGenTimeout = errors.New("could not generate a token within given cycles")

	// ErrEntityAlreadyExists indicates this entity already exists
	ErrEntityAlreadyExists = errors.New("entity already exists in system")

	// ErrTokenExpired indicates that the supplied token has expired
	ErrTokenExpired = errors.New("supplied token has expired")

	// ErrEntityInvalidTransition indicates this entity cant transition
	ErrEntityInvalidTransition = errors.New("entity does not support transition")

	// ErrPasswordGuidelines indicates a violation of the password guidlines
	ErrPasswordGuidelines = errors.New("password doesnt match password guidlines")

	// ErrNotFound indicates the entity does not exist
	ErrNotFound = errors.New("entity not found")
)

// NewUserService returns a new user service
func NewUserService(store *db.DataStore,
	log logging.Logger,
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

// UserService is used to manage user data
type UserService struct {
	store      *db.DataStore
	log        logging.Logger
	cfg        *config.Configuration
	mailer     *mailing.Mailer
	dispatcher *events.Dispatcher
}

func (g *UserService) List(
	ctx context.Context,
	page int,
	pageSize int,
	q string,
	sort string,
) (*PaginationResponse, error) {
	apps, total, err := g.store.Users(
		ctx,
		db.ListOptions{Page: page, PageSize: pageSize, Query: q, Sort: sort},
	)
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

func (g *UserService) ByID(ctx context.Context, userID uuid.UUID) (*UserDTO, error) {
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

func (g *UserService) EmailToID(ctx context.Context, email string) (uuid.UUID, error) {
	found, id, err := g.store.IDFromEmail(ctx, email)
	if err != nil {
		g.log.Error("unable to get matching user from store", "err", err)
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
	g.dispatcher.Dispatch(&event.UserConfirmed{
		ConfirmCode:   "",
		UserID:        id,
		AutoConfirmed: true,
	})
	return nil
}

func (g *UserService) AddUserToRole(ctx context.Context, id uuid.UUID, role string) error {
	canonicalRole := strings.ToLower(role)
	if canonicalRole != "" {
		err := g.store.AddUserToRole(ctx, id, canonicalRole)
		if err != nil {
			return err
		}
		g.dispatcher.Dispatch(&event.UserAddedToRole{
			UserID: id,
			Role:   canonicalRole,
		})
	}
	return nil
}

func (g *UserService) RemoveUserFromRole(ctx context.Context, id uuid.UUID, role string) error {
	canonicalRole := strings.ToLower(role)
	err := g.store.RemoveUserFromRole(ctx, id, canonicalRole)
	if err != nil {
		return err
	}
	g.dispatcher.Dispatch(&event.UserRemovedFromRole{
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
	g.dispatcher.Dispatch(&event.UserLocked{
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
	g.dispatcher.Dispatch(&event.UserUnlocked{
		UserID: id,
	})
	return nil
}

func (g *UserService) BanUser(ctx context.Context, id uuid.UUID) error {
	err := g.store.BanUser(ctx, id)
	if err != nil {
		return err
	}

	g.dispatcher.Dispatch(&event.UserBanned{
		UserID: id,
	})
	return nil
}

func (g *UserService) UnbanUser(ctx context.Context, id uuid.UUID) error {
	err := g.store.UnbanUser(ctx, id)
	if err != nil {
		return err
	}

	g.dispatcher.Dispatch(&event.UserUnbanned{
		UserID: id,
	})
	return nil
}

// InitialUserInvite used for docker container setup, it seeds a predefined a user invite for the admin user
// so the admin user can signup with his wanted credentials
func (g *UserService) InitialUserInvite(
	ctx context.Context,
	inviteCode string,
	roles []string,
	appIds []int,
) error {
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
				g.log.Error("could not create role for user invite", "err", err)
				return err
			}
		}
	}
	expiryDate := time.Now().Add(g.cfg.Behaviour.InviteExpiry).UTC()
	err = g.store.InviteUser(ctx, expiryDate, nil, string(inviteCode), roles, appIds...)
	if err != nil {
		g.log.Error("could not persist user invite", "err", err)
		return err
	}
	g.dispatcher.Dispatch(&event.UserInvited{
		ExpiryDate: expiryDate,
		Email:      "",
		InviteCode: string(inviteCode),
	})
	return nil
}

func (g *UserService) InviteUser(
	ctx context.Context,
	email *string,
	roles []string,
	appIds []int,
) (generator.RandomTokenType, error) {
	tokenGen := generator.New()
	inviteCode := tokenGen.CreatePINLikeToken()
	exists, err := g.store.InviteCodeExists(ctx, string(inviteCode))
	if err != nil {
		g.log.Error("unable to check invite code against datastore", "err", err)
		return "", err
	}
	timeout := 0
	for exists {
		exists, err = g.store.InviteCodeExists(ctx, string(inviteCode))
		if err != nil {
			g.log.Error("unable to check invite code against datastore", "err", err)
			return "", err
		}
		if exists {
			timeout++
		}
		if timeout >= maxIterationCycles {
			g.log.Error("unable to generate new invite code - timeout reached")
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
		_, err = g.store.AddRole(ctx, r)
		if err != nil && !errors.Is(err, db.ErrAlreadyExists) {
			g.log.Error("could not create role for user invite", "err", err)
			return "", err
		}
	}
	expiryDate := time.Now().Add(g.cfg.Behaviour.InviteExpiry).UTC()
	err = g.store.InviteUser(ctx, expiryDate, email, string(inviteCode), roles, appIds...)
	if err != nil {
		g.log.Error("could not persist user invite", "err", err)
		return "", err
	}
	e := ""
	if email != nil {
		e = g.sendInviteMail(ctx, *email, inviteCode)
	}
	g.dispatcher.Dispatch(&event.UserInvited{
		ExpiryDate: expiryDate,
		Email:      e,
		InviteCode: string(inviteCode),
	})
	return inviteCode, nil
}

func (g *UserService) sendInviteMail(
	ctx context.Context,
	email string,
	inviteCode generator.RandomTokenType,
) string {
	err := g.mailer.SendInviteMail(email, string(inviteCode), g.currentLocale(ctx))
	if err != nil {
		g.log.Error(
			"Could not send invite email to user",
			"email", sanitize.UserInputString(email),
			"err", err,
		)
	} else {
		err = g.store.SetInviteSent(ctx, email, string(inviteCode))
		if err != nil {
			g.log.Error("could not persist sent date for invite email to user", "email", sanitize.UserInputString(email), "err", err)
		}
		g.dispatcher.Dispatch(&event.EmailInviteSent{
			InviteCode: string(inviteCode),
			Email:      email,
			Sent:       time.Now(),
		})
	}
	return email
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
		g.log.Error("inserting user into store failed", "err", err)
		return uuid.UUID{}, err
	}
	return id, nil
}
