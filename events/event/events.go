package event

import (
	"time"

	"github.com/eisenwinter/gotrxx/events"
	"github.com/google/uuid"
)

const (
	UserInvitedEvent         events.EventName = "user_invited"
	UserInviteConsumedEvent  events.EventName = "user_invite_consumed"
	UserConfirmedEvent       events.EventName = "user_confirmed"
	UserSignupEvent          events.EventName = "user_signup"
	UserLockedEvent          events.EventName = "user_locked"
	UserUnlockedEvent        events.EventName = "user_unlocked"
	UserSignedInByTokenEvent events.EventName = "user_token_signin"

	UserBannedEvent   events.EventName = "user_banned"
	UserUnbannedEvent events.EventName = "user_unbanned"

	UserLoginEvent events.EventName = "user_login"

	UserMFAEnabledEvent  events.EventName = "user_mfa_enabled"
	UserMFADisabledEvent events.EventName = "user_mfa_disabled"

	UserPasswordRecoveryRequestedEvent events.EventName = "user_password_recovery_requested"
	UserPasswordRecoveryUsedEvent      events.EventName = "user_password_recovery_used"
	UserEmailChangedEvent              events.EventName = "user_email_changed"
	UserPasswordChangedEvent           events.EventName = "user_password_changed"

	UserRemovedFromRoleEvent events.EventName = "user_removed_from_role"
	UserAddedToRoleEvent     events.EventName = "user_added_to_role"

	AuthorizationGrantedEvent events.EventName = "authorization_granted"
	AuthorizationRevokedEvent events.EventName = "authorization_revoked"

	TokenAlreadyRedeemedEvent events.EventName = "token_already_redeemed"
	TokenRevokedEvent         events.EventName = "token_revoked"

	EmailPasswordRecoverySentEvent events.EventName = "email_password_recovery_sent"
	EmailSignupConfirmSentEvent    events.EventName = "email_signup_confirm_sent"
	EmailInviteSentEvent           events.EventName = "email_invite_sent"

	ApplicationCreatedEvent events.EventName = "application_created"
	ApplicationRetiredEvent events.EventName = "application_retired"

	ApplicationSettingsChangedEvent events.EventName = "application_changed"

	AllRetiredApplicationsPurgedEvent events.EventName = "retired_applications_purged"

	RoleCreatedEvent events.EventName = "role_created"
	RoleDeletedEvent events.EventName = "role_deleted"
)

type UserInvited struct {
	InviteCode string
	Email      string
	ExpiryDate time.Time
}

func (*UserInvited) Name() events.EventName { return UserInvitedEvent }

type UserInviteConsumed struct {
	InviteCode string
	UserID     uuid.UUID
}

func (*UserInviteConsumed) Name() events.EventName { return UserInviteConsumedEvent }

type UserConfirmed struct {
	UserID        uuid.UUID
	AutoConfirmed bool
	ConfirmCode   string
}

func (*UserConfirmed) Name() events.EventName { return UserConfirmedEvent }

type UserSignup struct {
	UserID uuid.UUID
	Email  string
}

func (*UserSignup) Name() events.EventName { return UserSignupEvent }

type UserLocked struct {
	UserID      uuid.UUID
	LockedUntil time.Time
}

func (*UserLocked) Name() events.EventName { return UserLockedEvent }

type UserUnlocked struct {
	UserID uuid.UUID
}

func (*UserUnlocked) Name() events.EventName { return UserUnlockedEvent }

type UserLogin struct {
	UserID uuid.UUID
}

func (*UserLogin) Name() events.EventName { return UserLoginEvent }

type UserSignedInByToken struct {
	UserID    uuid.UUID
	TokenType string
}

func (*UserSignedInByToken) Name() events.EventName { return UserSignedInByTokenEvent }

type UserPasswordRecoveryRequested struct {
	UserID uuid.UUID
}

func (*UserPasswordRecoveryRequested) Name() events.EventName {
	return UserPasswordRecoveryRequestedEvent
}

type UserPasswordRecoveryUsed struct {
	UserID uuid.UUID
	Token  string
	Email  string
}

func (*UserPasswordRecoveryUsed) Name() events.EventName { return UserPasswordRecoveryUsedEvent }

type UserEmailChanged struct {
	UserID uuid.UUID
	Email  string
}

func (*UserEmailChanged) Name() events.EventName { return UserEmailChangedEvent }

type UserPasswordChanged struct {
	UserID uuid.UUID
}

func (*UserPasswordChanged) Name() events.EventName { return UserPasswordChangedEvent }

type UserRemovedFromRole struct {
	UserID uuid.UUID
	Role   string
}

func (*UserRemovedFromRole) Name() events.EventName { return UserRemovedFromRoleEvent }

type UserAddedToRole struct {
	UserID uuid.UUID
	Role   string
}

func (*UserAddedToRole) Name() events.EventName { return UserAddedToRoleEvent }

type EmailPasswordRecoverySent struct {
	UserID       uuid.UUID
	ConfirmToken string
	Email        string
	Sent         time.Time
}

func (*EmailPasswordRecoverySent) Name() events.EventName { return EmailPasswordRecoverySentEvent }

type EmailSignupConfirmSent struct {
	UserID       uuid.UUID
	ConfirmToken string
	Email        string
	Sent         time.Time
}

func (*EmailSignupConfirmSent) Name() events.EventName { return EmailSignupConfirmSentEvent }

type EmailInviteSent struct {
	InviteCode string
	Email      string
	Sent       time.Time
}

func (*EmailInviteSent) Name() events.EventName { return EmailInviteSentEvent }

type UserBanned struct {
	UserID uuid.UUID
}

func (*UserBanned) Name() events.EventName { return UserBannedEvent }

type UserUnbanned struct {
	UserID uuid.UUID
}

func (*UserUnbanned) Name() events.EventName { return UserUnbannedEvent }

type AuthorizationGranted struct {
	AuthorizationID uuid.UUID
	UserID          uuid.UUID
	ApplicationID   int
	Scopes          []string
}

func (*AuthorizationGranted) Name() events.EventName {
	return AuthorizationGrantedEvent
}

type AuthorizationRevoked struct {
	AuthorizationID uuid.UUID
	UserID          uuid.UUID
	ApplicationID   int
	TokensAffected  int64
}

func (*AuthorizationRevoked) Name() events.EventName {
	return AuthorizationRevokedEvent
}

type TokenAlreadyRedeemed struct {
	TokenID         int
	AuthorizationID uuid.UUID
	UserID          uuid.UUID
	Token           string
	TokenType       string
}

func (*TokenAlreadyRedeemed) Name() events.EventName {
	return TokenAlreadyRedeemedEvent
}

type TokenRevoked struct {
	TokenID         int
	AuthorizationID uuid.UUID
	UserID          uuid.UUID
	Token           string
	TokenType       string
}

func (*TokenRevoked) Name() events.EventName { return TokenRevokedEvent }

type ApplicationCreated struct {
	ApplicationID   int
	ClientID        string
	ApplicationName string
}

func (*ApplicationCreated) Name() events.EventName { return ApplicationCreatedEvent }

type ApplicationRetired struct {
	ApplicationID   int
	ClientID        string
	ApplicationName string
}

func (*ApplicationRetired) Name() events.EventName { return ApplicationRetiredEvent }

type ApplicationSettingsChanged struct {
	ApplicationID   int
	ClientID        string
	ApplicationName string
	Property        string
	Value           string
}

func (*ApplicationSettingsChanged) Name() events.EventName { return ApplicationSettingsChangedEvent }

type UserMFAEnabled struct {
	UserID uuid.UUID
}

func (*UserMFAEnabled) Name() events.EventName { return UserMFAEnabledEvent }

type UserMFADisabled struct {
	UserID uuid.UUID
}

func (*UserMFADisabled) Name() events.EventName { return UserMFADisabledEvent }

type AllRetiredApplicationsPurged struct {
	AffectedClientIDs []string
}

func (*AllRetiredApplicationsPurged) Name() events.EventName {
	return AllRetiredApplicationsPurgedEvent
}

type RoleCreated struct {
	Role string
}

func (*RoleCreated) Name() events.EventName {
	return RoleCreatedEvent
}

type RoleDeleted struct {
	Role string
}

func (*RoleDeleted) Name() events.EventName {
	return RoleDeletedEvent
}
