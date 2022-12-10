package user

import (
	"context"
	"testing"
	"time"

	"github.com/eisenwinter/gotrxx/config"
	"github.com/eisenwinter/gotrxx/db"
	"github.com/eisenwinter/gotrxx/user/mocks"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/xlzd/gotp"
	"go.uber.org/zap/zaptest"
	"golang.org/x/crypto/bcrypt"
)

func TestValidateUnknownUserID(t *testing.T) {
	assert := assert.New(t)
	dataStore := mocks.NewLoginStorer(t)
	logger := zaptest.NewLogger(t)
	dispatcher := mocks.NewDispatcher(t)
	locker := mocks.NewUserLocker(t)
	service := NewSignInService(
		dataStore,
		logger,
		&config.BehaviourConfiguration{},
		dispatcher,
		locker,
	)
	ctx := context.Background()
	uid := uuid.MustParse("d1ef48c5-1fad-4514-ba2c-3a1851d39f87")
	pwd := "test"

	dataStore.On("UserByID", ctx, uid).Return(nil, db.ErrNotFound)

	err := service.Validate(ctx, uid, pwd)
	assert.NotNil(err)
	assert.ErrorIs(err, ErrEntityDoesNotExist)
}

func TestValidateUserNotEligbleToLoginBecauseLocked(t *testing.T) {
	assert := assert.New(t)
	dataStore := mocks.NewLoginStorer(t)
	logger := zaptest.NewLogger(t)
	dispatcher := mocks.NewDispatcher(t)
	locker := mocks.NewUserLocker(t)
	service := NewSignInService(
		dataStore,
		logger,
		&config.BehaviourConfiguration{},
		dispatcher,
		locker,
	)
	ctx := context.Background()
	uid := uuid.MustParse("d1ef48c5-1fad-4514-ba2c-3a1851d39f87")
	pwd := "test"
	lockedTill := time.Now().Add(time.Hour * 2)
	ud := &db.UserData{
		ID:          uid,
		LockoutTill: &lockedTill,
	}

	dataStore.On("UserByID", ctx, uid).Return(ud, nil)

	err := service.Validate(ctx, uid, pwd)
	assert.NotNil(err)
	assert.ErrorIs(err, ErrEntityOperationForbidden)
}

func TestValidateUserNotEligbleToLoginBecauseBanned(t *testing.T) {
	assert := assert.New(t)
	dataStore := mocks.NewLoginStorer(t)
	logger := zaptest.NewLogger(t)
	dispatcher := mocks.NewDispatcher(t)
	locker := mocks.NewUserLocker(t)
	service := NewSignInService(
		dataStore,
		logger,
		&config.BehaviourConfiguration{},
		dispatcher,
		locker,
	)
	ctx := context.Background()
	uid := uuid.MustParse("d1ef48c5-1fad-4514-ba2c-3a1851d39f87")
	pwd := "test"
	lockedTill := time.Now()
	ud := &db.UserData{
		ID:       uid,
		BannedOn: &lockedTill,
	}

	dataStore.On("UserByID", ctx, uid).Return(ud, nil)

	err := service.Validate(ctx, uid, pwd)
	assert.NotNil(err)
	assert.ErrorIs(err, ErrEntityOperationForbidden)
}

func TestValidateUserNotEligbleToLoginBecauseUnconfirmed(t *testing.T) {
	assert := assert.New(t)
	dataStore := mocks.NewLoginStorer(t)
	logger := zaptest.NewLogger(t)
	dispatcher := mocks.NewDispatcher(t)
	locker := mocks.NewUserLocker(t)
	service := NewSignInService(
		dataStore,
		logger,
		&config.BehaviourConfiguration{},
		dispatcher,
		locker,
	)
	ctx := context.Background()
	uid := uuid.MustParse("d1ef48c5-1fad-4514-ba2c-3a1851d39f87")
	pwd := "test"
	ud := &db.UserData{
		ID: uid,
	}

	dataStore.On("UserByID", ctx, uid).Return(ud, nil)

	err := service.Validate(ctx, uid, pwd)
	assert.NotNil(err)
	assert.ErrorIs(err, ErrEntityOperationForbidden)
}

func TestValidateInvalidPassword(t *testing.T) {
	assert := assert.New(t)
	dataStore := mocks.NewLoginStorer(t)
	logger := zaptest.NewLogger(t)
	dispatcher := mocks.NewDispatcher(t)
	locker := mocks.NewUserLocker(t)
	service := NewSignInService(
		dataStore,
		logger,
		&config.BehaviourConfiguration{},
		dispatcher,
		locker,
	)
	ctx := context.Background()
	uid := uuid.MustParse("d1ef48c5-1fad-4514-ba2c-3a1851d39f87")
	pwd := "test"
	confirmed := time.Now()
	ud := &db.UserData{
		ID:             uid,
		EmailConfirmed: &confirmed,
		PasswordHash:   []byte{0},
	}

	dataStore.On("UserByID", ctx, uid).Return(ud, nil)

	err := service.Validate(ctx, uid, pwd)
	assert.NotNil(err)
	assert.ErrorIs(err, ErrInvalidCredentials)
}

func TestCanLoginNotFound(t *testing.T) {
	assert := assert.New(t)
	dataStore := mocks.NewLoginStorer(t)
	logger := zaptest.NewLogger(t)
	dispatcher := mocks.NewDispatcher(t)
	locker := mocks.NewUserLocker(t)
	service := NewSignInService(
		dataStore,
		logger,
		&config.BehaviourConfiguration{},
		dispatcher,
		locker,
	)
	ctx := context.Background()
	uid := uuid.MustParse("d1ef48c5-1fad-4514-ba2c-3a1851d39f87")

	dataStore.On("UserByID", ctx, uid).Return(nil, db.ErrNotFound)

	_, err := service.CanLogin(ctx, uid)
	assert.NotNil(err)
	assert.ErrorIs(err, ErrEntityDoesNotExist)
}

func TestCanLogin(t *testing.T) {
	assert := assert.New(t)
	dataStore := mocks.NewLoginStorer(t)
	logger := zaptest.NewLogger(t)
	dispatcher := mocks.NewDispatcher(t)
	locker := mocks.NewUserLocker(t)
	service := NewSignInService(
		dataStore,
		logger,
		&config.BehaviourConfiguration{},
		dispatcher,
		locker,
	)
	ctx := context.Background()
	uid := uuid.MustParse("d1ef48c5-1fad-4514-ba2c-3a1851d39f87")
	confirmed := time.Now()
	ud := &db.UserData{
		ID:             uid,
		EmailConfirmed: &confirmed,
	}

	dataStore.On("UserByID", ctx, uid).Return(ud, nil)

	ok, err := service.CanLogin(ctx, uid)
	assert.Nil(err)
	assert.True(ok)
}

func TestUserFromSubject(t *testing.T) {
	assert := assert.New(t)
	dataStore := mocks.NewLoginStorer(t)
	logger := zaptest.NewLogger(t)
	dispatcher := mocks.NewDispatcher(t)
	locker := mocks.NewUserLocker(t)
	service := NewSignInService(
		dataStore,
		logger,
		&config.BehaviourConfiguration{},
		dispatcher,
		locker,
	)
	ctx := context.Background()
	uid := uuid.MustParse("d1ef48c5-1fad-4514-ba2c-3a1851d39f87")
	confirmed := time.Now()
	ud := &db.UserData{
		ID:             uid,
		EmailConfirmed: &confirmed,
	}

	dataStore.On("UserByID", ctx, uid).Return(ud, nil)

	signedInUser, err := service.UserFromSubject(ctx, uid)
	assert.Nil(err)
	assert.NotNil(signedInUser)
}

func TestSignInByIDFromToken(t *testing.T) {
	assert := assert.New(t)
	dataStore := mocks.NewLoginStorer(t)
	logger := zaptest.NewLogger(t)
	dispatcher := mocks.NewDispatcher(t)
	locker := mocks.NewUserLocker(t)
	service := NewSignInService(
		dataStore,
		logger,
		&config.BehaviourConfiguration{},
		dispatcher,
		locker,
	)
	ctx := context.Background()
	uid := uuid.MustParse("d1ef48c5-1fad-4514-ba2c-3a1851d39f87")
	confirmed := time.Now()
	ud := &db.UserData{
		ID:             uid,
		EmailConfirmed: &confirmed,
	}

	dataStore.On("UserByID", ctx, uid).Return(ud, nil)
	dispatcher.On("Dispatch", mock.Anything).Return()

	signedInUser, err := service.SignInByIDFromToken(ctx, uid, "dummy-token")
	assert.Nil(err)
	assert.NotNil(signedInUser)
}

func TestInitializeMFA(t *testing.T) {
	assert := assert.New(t)
	dataStore := mocks.NewLoginStorer(t)
	logger := zaptest.NewLogger(t)
	dispatcher := mocks.NewDispatcher(t)
	locker := mocks.NewUserLocker(t)
	service := NewSignInService(
		dataStore,
		logger,
		&config.BehaviourConfiguration{},
		dispatcher,
		locker,
	)
	ctx := context.Background()
	email := "test@example.com"
	confirmed := time.Now()
	ud := &db.UserData{
		Email:          email,
		EmailConfirmed: &confirmed,
		TwoFactor:      true,
	}
	dataStore.On("SetOTPPending", ctx, mock.Anything, true).Return(nil)
	dataStore.On("UserByEmail", ctx, email).Return(ud, nil)

	err := service.InitializeMFA(ctx, email)
	assert.Nil(err)
}

func TestInitializeMFNotEnabled(t *testing.T) {
	assert := assert.New(t)
	dataStore := mocks.NewLoginStorer(t)
	logger := zaptest.NewLogger(t)
	dispatcher := mocks.NewDispatcher(t)
	locker := mocks.NewUserLocker(t)
	service := NewSignInService(
		dataStore,
		logger,
		&config.BehaviourConfiguration{},
		dispatcher,
		locker,
	)
	ctx := context.Background()
	email := "test@example.com"
	confirmed := time.Now()
	ud := &db.UserData{
		Email:          email,
		EmailConfirmed: &confirmed,
		TwoFactor:      false,
	}
	dataStore.On("UserByEmail", ctx, email).Return(ud, nil)

	err := service.InitializeMFA(ctx, email)
	assert.NotNil(err)
	assert.ErrorIs(err, ErrEntityOperationForbidden)
}

func TestSignInInvalidPassword(t *testing.T) {
	assert := assert.New(t)
	dataStore := mocks.NewLoginStorer(t)
	logger := zaptest.NewLogger(t)
	dispatcher := mocks.NewDispatcher(t)
	locker := mocks.NewUserLocker(t)
	service := NewSignInService(
		dataStore,
		logger,
		&config.BehaviourConfiguration{},
		dispatcher,
		locker,
	)
	ctx := context.Background()
	email := "test@example.com"
	password := "test"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), 10)
	confirmed := time.Now()
	ud := &db.UserData{
		Email:          email,
		EmailConfirmed: &confirmed,
		TwoFactor:      false,
		PasswordHash:   hash,
	}
	dataStore.On("SetFailureCount", ctx, mock.Anything, mock.Anything).Return(nil)
	dataStore.On("UserByEmail", ctx, email).Return(ud, nil)
	_, err := service.SignIn(ctx, email, "somethingelse")
	assert.NotNil(err)
	assert.ErrorIs(err, ErrInvalidCredentials)
}

func TestSignInLockoutThresholdCrossed(t *testing.T) {
	assert := assert.New(t)
	dataStore := mocks.NewLoginStorer(t)
	logger := zaptest.NewLogger(t)
	dispatcher := mocks.NewDispatcher(t)
	locker := mocks.NewUserLocker(t)
	service := NewSignInService(
		dataStore,
		logger,
		&config.BehaviourConfiguration{
			AutoLockoutCount: 10,
		},
		dispatcher,
		locker,
	)
	ctx := context.Background()
	email := "test@example.com"
	password := "test"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), 10)
	confirmed := time.Now()
	ud := &db.UserData{
		Email:               email,
		EmailConfirmed:      &confirmed,
		TwoFactor:           false,
		PasswordHash:        hash,
		CurrentFailureCount: 10,
	}
	locker.On("LockUser", ctx, mock.Anything, mock.Anything).Return(nil)
	dataStore.On("UserByEmail", ctx, email).Return(ud, nil)
	_, err := service.SignIn(ctx, email, "somethingelse")
	assert.NotNil(err)
	assert.ErrorIs(err, ErrEntityOperationForbidden)
}

func TestSignIn(t *testing.T) {
	assert := assert.New(t)
	dataStore := mocks.NewLoginStorer(t)
	logger := zaptest.NewLogger(t)
	dispatcher := mocks.NewDispatcher(t)
	locker := mocks.NewUserLocker(t)
	service := NewSignInService(
		dataStore,
		logger,
		&config.BehaviourConfiguration{},
		dispatcher,
		locker,
	)
	ctx := context.Background()
	email := "test@example.com"
	password := "test"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), 10)
	confirmed := time.Now()
	ud := &db.UserData{
		Email:          email,
		EmailConfirmed: &confirmed,
		TwoFactor:      false,
		PasswordHash:   hash,
	}
	dataStore.On("UserByEmail", ctx, email).Return(ud, nil)
	dispatcher.On("Dispatch", mock.Anything).Return()
	usr, err := service.SignIn(ctx, email, password)
	assert.Nil(err)
	assert.NotNil(usr)
}

func TestSignInMFAInvalidOTP(t *testing.T) {
	assert := assert.New(t)
	dataStore := mocks.NewLoginStorer(t)
	logger := zaptest.NewLogger(t)
	dispatcher := mocks.NewDispatcher(t)
	locker := mocks.NewUserLocker(t)
	service := NewSignInService(
		dataStore,
		logger,
		&config.BehaviourConfiguration{},
		dispatcher,
		locker,
	)
	ctx := context.Background()
	email := "test@example.com"
	password := "test"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), 10)
	otp := "test"
	confirmed := time.Now()
	ud := &db.UserData{
		Email:          email,
		EmailConfirmed: &confirmed,
		TwoFactor:      true,
		PasswordHash:   hash,
	}
	dataStore.On("UserByEmail", ctx, email).Return(ud, nil)

	usr, err := service.SignInMFA(ctx, email, password, otp)
	assert.NotNil(err)
	assert.ErrorIs(err, ErrInvalidOTP)
	assert.Nil(usr)
}

func TestSignInMFA(t *testing.T) {
	assert := assert.New(t)
	dataStore := mocks.NewLoginStorer(t)
	logger := zaptest.NewLogger(t)
	dispatcher := mocks.NewDispatcher(t)
	locker := mocks.NewUserLocker(t)
	service := NewSignInService(
		dataStore,
		logger,
		&config.BehaviourConfiguration{},
		dispatcher,
		locker,
	)
	ctx := context.Background()
	email := "test@example.com"
	password := "test"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), 10)
	confirmed := time.Now()
	secret := gotp.RandomSecret(64)
	ud := &db.UserData{
		Email:           email,
		EmailConfirmed:  &confirmed,
		TwoFactor:       true,
		PasswordHash:    hash,
		OtpPending:      true,
		TwoFactorSecret: secret,
	}
	totp := gotp.NewDefaultTOTP(secret)
	otp := totp.Now()
	dataStore.On("UserByEmail", ctx, email).Return(ud, nil)
	dataStore.On("SetOTPPending", ctx, mock.Anything, false).Return(nil)
	dispatcher.On("Dispatch", mock.Anything).Return()
	usr, err := service.SignInMFA(ctx, email, password, otp)
	assert.Nil(err)
	assert.NotNil(usr)
}
