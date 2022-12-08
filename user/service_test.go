package user

import (
	"context"
	"errors"
	"testing"

	"github.com/eisenwinter/gotrxx/config"
	"github.com/eisenwinter/gotrxx/user/mocks"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap/zaptest"
)

func TestEmailToIDNotFound(t *testing.T) {
	assert := assert.New(t)
	logger := zaptest.NewLogger(t)
	dataStore := mocks.NewUserStorer(t)
	mailer := mocks.NewMailer(t)
	dispatcher := mocks.NewDispatcher(t)
	manager := mocks.NewUserManager(t)
	ctx := context.Background()
	service := New(dataStore, logger, &config.Configuration{}, mailer, dispatcher, manager)
	dataStore.On("IDFromEmail", ctx, "test@example.com").Return(false, uuid.New(), nil)
	_, found := service.EmailToID(ctx, "test@example.com")
	assert.False(found)
}

func TestEmailToIDFalseOnErrr(t *testing.T) {
	assert := assert.New(t)
	logger := zaptest.NewLogger(t)
	dataStore := mocks.NewUserStorer(t)
	mailer := mocks.NewMailer(t)
	dispatcher := mocks.NewDispatcher(t)
	manager := mocks.NewUserManager(t)
	ctx := context.Background()
	service := New(dataStore, logger, &config.Configuration{}, mailer, dispatcher, manager)
	dataStore.On("IDFromEmail", ctx, "test@example.com").Return(false, uuid.New(), errors.New("dummy"))
	_, found := service.EmailToID(ctx, "test@example.com")
	assert.False(found)
}
func TestEmailToID(t *testing.T) {
	assert := assert.New(t)
	logger := zaptest.NewLogger(t)
	dataStore := mocks.NewUserStorer(t)
	mailer := mocks.NewMailer(t)
	dispatcher := mocks.NewDispatcher(t)
	manager := mocks.NewUserManager(t)
	ctx := context.Background()
	service := New(dataStore, logger, &config.Configuration{}, mailer, dispatcher, manager)
	uid := uuid.New()
	dataStore.On("IDFromEmail", ctx, "test@example.com").Return(true, uid, nil)
	id, found := service.EmailToID(ctx, "test@example.com")
	assert.True(found)
	assert.Equal(uid, id)
}

func TestRegisterUser(t *testing.T) {
	assert := assert.New(t)
	logger := zaptest.NewLogger(t)
	dataStore := mocks.NewUserStorer(t)
	mailer := mocks.NewMailer(t)
	dispatcher := mocks.NewDispatcher(t)
	manager := mocks.NewUserManager(t)
	ctx := context.Background()
	service := New(dataStore, logger, &config.Configuration{
		Behaviour: &config.BehaviourConfiguration{
			InviteOnly: false,
		},
	}, mailer, dispatcher, manager)

	email := "test@example.com"
	password := "testtest"

	userID := uuid.New()

	dataStore.On("IsRegistred", ctx, email).Return(false, nil)
	dataStore.On("ConfirmTokenExists", ctx, mock.Anything).Return(false, nil)

	manager.On("InsertUser", ctx, email, password, mock.Anything, mock.Anything).Return(userID, nil)

	dispatcher.On("Dispatch", mock.Anything).Return()

	mailer.On("SendConfirmMail", email, mock.Anything, mock.Anything).Return(nil)

	id, err := service.RegisterUser(ctx, email, password, nil)
	assert.Nil(err)
	assert.NotEqual(uuid.Nil, id)
	assert.Equal(userID, id)
}
