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
	"go.uber.org/zap/zaptest"
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
