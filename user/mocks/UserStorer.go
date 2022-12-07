// Code generated by mockery v2.15.0. DO NOT EDIT.

package mocks

import (
	context "context"

	db "github.com/eisenwinter/gotrxx/db"
	mock "github.com/stretchr/testify/mock"

	tables "github.com/eisenwinter/gotrxx/db/tables"

	uuid "github.com/google/uuid"
)

// UserStorer is an autogenerated mock type for the UserStorer type
type UserStorer struct {
	mock.Mock
}

// ConfirmTokenExists provides a mock function with given fields: ctx, token
func (_m *UserStorer) ConfirmTokenExists(ctx context.Context, token string) (bool, error) {
	ret := _m.Called(ctx, token)

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, string) bool); ok {
		r0 = rf(ctx, token)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, token)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ConfirmUser provides a mock function with given fields: ctx, confirmToken
func (_m *UserStorer) ConfirmUser(ctx context.Context, confirmToken string) (bool, uuid.UUID, error) {
	ret := _m.Called(ctx, confirmToken)

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, string) bool); ok {
		r0 = rf(ctx, confirmToken)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 uuid.UUID
	if rf, ok := ret.Get(1).(func(context.Context, string) uuid.UUID); ok {
		r1 = rf(ctx, confirmToken)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(uuid.UUID)
		}
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, string) error); ok {
		r2 = rf(ctx, confirmToken)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// ConsumeInvite provides a mock function with given fields: ctx, inviteCode
func (_m *UserStorer) ConsumeInvite(ctx context.Context, inviteCode string) error {
	ret := _m.Called(ctx, inviteCode)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, inviteCode)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ConsumeRecoveryToken provides a mock function with given fields: ctx, id, recoveryToken
func (_m *UserStorer) ConsumeRecoveryToken(ctx context.Context, id uuid.UUID, recoveryToken string) (bool, error) {
	ret := _m.Called(ctx, id, recoveryToken)

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, string) bool); ok {
		r0 = rf(ctx, id, recoveryToken)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID, string) error); ok {
		r1 = rf(ctx, id, recoveryToken)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DisableMFA provides a mock function with given fields: ctx, id
func (_m *UserStorer) DisableMFA(ctx context.Context, id uuid.UUID) (bool, error) {
	ret := _m.Called(ctx, id)

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) bool); ok {
		r0 = rf(ctx, id)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID) error); ok {
		r1 = rf(ctx, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// EnableMFA provides a mock function with given fields: ctx, id, userSecret, userRecoveryKey
func (_m *UserStorer) EnableMFA(ctx context.Context, id uuid.UUID, userSecret string, userRecoveryKey string) (bool, error) {
	ret := _m.Called(ctx, id, userSecret, userRecoveryKey)

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, string, string) bool); ok {
		r0 = rf(ctx, id, userSecret, userRecoveryKey)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID, string, string) error); ok {
		r1 = rf(ctx, id, userSecret, userRecoveryKey)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GrantAuthorization provides a mock function with given fields: ctx, applicationId, userID, properties
func (_m *UserStorer) GrantAuthorization(ctx context.Context, applicationId int, userID uuid.UUID, properties tables.MapStructure) (uuid.UUID, error) {
	ret := _m.Called(ctx, applicationId, userID, properties)

	var r0 uuid.UUID
	if rf, ok := ret.Get(0).(func(context.Context, int, uuid.UUID, tables.MapStructure) uuid.UUID); ok {
		r0 = rf(ctx, applicationId, userID, properties)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(uuid.UUID)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, int, uuid.UUID, tables.MapStructure) error); ok {
		r1 = rf(ctx, applicationId, userID, properties)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IDFromEmail provides a mock function with given fields: ctx, email
func (_m *UserStorer) IDFromEmail(ctx context.Context, email string) (bool, uuid.UUID, error) {
	ret := _m.Called(ctx, email)

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, string) bool); ok {
		r0 = rf(ctx, email)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 uuid.UUID
	if rf, ok := ret.Get(1).(func(context.Context, string) uuid.UUID); ok {
		r1 = rf(ctx, email)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(uuid.UUID)
		}
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, string) error); ok {
		r2 = rf(ctx, email)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// InviteData provides a mock function with given fields: ctx, inviteCode
func (_m *UserStorer) InviteData(ctx context.Context, inviteCode string) (*db.UserInviteData, error) {
	ret := _m.Called(ctx, inviteCode)

	var r0 *db.UserInviteData
	if rf, ok := ret.Get(0).(func(context.Context, string) *db.UserInviteData); ok {
		r0 = rf(ctx, inviteCode)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*db.UserInviteData)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, inviteCode)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IsRegistred provides a mock function with given fields: ctx, email
func (_m *UserStorer) IsRegistred(ctx context.Context, email string) (bool, error) {
	ret := _m.Called(ctx, email)

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, string) bool); ok {
		r0 = rf(ctx, email)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, email)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IsUserInRole provides a mock function with given fields: ctx, id, role
func (_m *UserStorer) IsUserInRole(ctx context.Context, id uuid.UUID, role string) (bool, error) {
	ret := _m.Called(ctx, id, role)

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, string) bool); ok {
		r0 = rf(ctx, id, role)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID, string) error); ok {
		r1 = rf(ctx, id, role)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SetEmail provides a mock function with given fields: ctx, id, email
func (_m *UserStorer) SetEmail(ctx context.Context, id uuid.UUID, email string) (bool, error) {
	ret := _m.Called(ctx, id, email)

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, string) bool); ok {
		r0 = rf(ctx, id, email)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID, string) error); ok {
		r1 = rf(ctx, id, email)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SetPassword provides a mock function with given fields: ctx, id, passwordHash
func (_m *UserStorer) SetPassword(ctx context.Context, id uuid.UUID, passwordHash string) (bool, error) {
	ret := _m.Called(ctx, id, passwordHash)

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, string) bool); ok {
		r0 = rf(ctx, id, passwordHash)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID, string) error); ok {
		r1 = rf(ctx, id, passwordHash)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SetRecoveryToken provides a mock function with given fields: ctx, id, recoveryToken
func (_m *UserStorer) SetRecoveryToken(ctx context.Context, id uuid.UUID, recoveryToken string) (bool, error) {
	ret := _m.Called(ctx, id, recoveryToken)

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, string) bool); ok {
		r0 = rf(ctx, id, recoveryToken)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID, string) error); ok {
		r1 = rf(ctx, id, recoveryToken)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UserByID provides a mock function with given fields: ctx, id
func (_m *UserStorer) UserByID(ctx context.Context, id uuid.UUID) (*db.UserData, error) {
	ret := _m.Called(ctx, id)

	var r0 *db.UserData
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) *db.UserData); ok {
		r0 = rf(ctx, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*db.UserData)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID) error); ok {
		r1 = rf(ctx, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

type mockConstructorTestingTNewUserStorer interface {
	mock.TestingT
	Cleanup(func())
}

// NewUserStorer creates a new instance of UserStorer. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewUserStorer(t mockConstructorTestingTNewUserStorer) *UserStorer {
	mock := &UserStorer{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}