// Code generated by mockery v2.15.0. DO NOT EDIT.

package mocks

import (
	context "context"

	db "github.com/eisenwinter/gotrxx/db"
	mock "github.com/stretchr/testify/mock"

	uuid "github.com/google/uuid"
)

// LoginStorer is an autogenerated mock type for the LoginStorer type
type LoginStorer struct {
	mock.Mock
}

// SetFailureCount provides a mock function with given fields: ctx, id, count
func (_m *LoginStorer) SetFailureCount(ctx context.Context, id uuid.UUID, count int) error {
	ret := _m.Called(ctx, id, count)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, int) error); ok {
		r0 = rf(ctx, id, count)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SetOTPPending provides a mock function with given fields: ctx, id, pending
func (_m *LoginStorer) SetOTPPending(ctx context.Context, id uuid.UUID, pending bool) error {
	ret := _m.Called(ctx, id, pending)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, bool) error); ok {
		r0 = rf(ctx, id, pending)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UserByEmail provides a mock function with given fields: ctx, email
func (_m *LoginStorer) UserByEmail(ctx context.Context, email string) (*db.UserData, error) {
	ret := _m.Called(ctx, email)

	var r0 *db.UserData
	if rf, ok := ret.Get(0).(func(context.Context, string) *db.UserData); ok {
		r0 = rf(ctx, email)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*db.UserData)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, email)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UserByID provides a mock function with given fields: ctx, id
func (_m *LoginStorer) UserByID(ctx context.Context, id uuid.UUID) (*db.UserData, error) {
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

type mockConstructorTestingTNewLoginStorer interface {
	mock.TestingT
	Cleanup(func())
}

// NewLoginStorer creates a new instance of LoginStorer. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewLoginStorer(t mockConstructorTestingTNewLoginStorer) *LoginStorer {
	mock := &LoginStorer{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
