package db

import (
	"github.com/eisenwinter/gotrxx/db/tables"
	"github.com/eisenwinter/gotrxx/events"
	"github.com/eisenwinter/gotrxx/events/event"
	"go.uber.org/zap"
)

// Auditor is a way to write audit log events into a persistent store
type Auditor interface {
	addToAuditLog(event string, payload tables.MapStructure) error
}

// BootstrapListeners registers all the event listeners from this package
func BootstrapListeners(store Auditor, log *zap.Logger) []events.EventListener {
	return []events.EventListener{
		&userIniviteListener{
			log:   log,
			store: store,
		},
		&userInviteConsumedListener{
			log:   log,
			store: store,
		},
		&userConfirmedListener{
			log:   log,
			store: store,
		},
		&userSignupListener{
			log:   log,
			store: store,
		},
		&userLockedListener{
			log:   log,
			store: store,
		},
		&userUnlockedListener{
			log:   log,
			store: store,
		},
		&userBannedListener{log: log,
			store: store},
		&userUnbannedListener{log: log,
			store: store},
		&userLoginListener{
			log:   log,
			store: store,
		},
		&userAddedToRoleListener{
			log:   log,
			store: store,
		},
		&emailSignupConfirmSentListener{
			log:   log,
			store: store,
		},
		&emailPasswordRecoverySentListener{
			log:   log,
			store: store,
		},
		&emailInviteSentListener{
			log:   log,
			store: store,
		},
		&userRemovedFromRoleListener{
			log:   log,
			store: store,
		},
		&userPasswordChangedListener{
			log:   log,
			store: store,
		},
		&userEmailChangedListener{
			log:   log,
			store: store,
		},
		&userPasswordRecoveryUsedListener{
			log:   log,
			store: store,
		},
		&userPasswordRecoveryRequestedListener{
			log:   log,
			store: store,
		},
		&securityAuthorizationGrantedListener{
			log:   log,
			store: store,
		},
		&securityAuthorizationRevokedListener{
			log:   log,
			store: store,
		},
		&tokenRevokedListener{
			log:   log,
			store: store,
		},
		&mfaDisabledListener{
			log:   log,
			store: store,
		},
		&mfaEnabledListener{
			log:   log,
			store: store,
		},
		&applicationCreatedListener{
			log:   log,
			store: store,
		},
		&applicationRetiredListener{
			log:   log,
			store: store,
		},
		&applicationPurgeListener{
			log:   log,
			store: store,
		},
		&userSignedInByTokenListener{
			log:   log,
			store: store,
		},
		&roleCreatedListener{
			log:   log,
			store: store,
		},
		&roleDeletedListener{
			log:   log,
			store: store,
		},
	}
}

type userIniviteListener struct {
	store Auditor
	log   *zap.Logger
}

func (*userIniviteListener) ForEvent() events.EventName {
	return event.UserInvitedEvent
}

func (l *userIniviteListener) Handle(ev events.Event) error {
	e := ev.(*event.UserInvited)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"email": e.Email,
		"code":  e.InviteCode,
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}
	return nil
}

type userInviteConsumedListener struct {
	store Auditor
	log   *zap.Logger
}

func (*userInviteConsumedListener) ForEvent() events.EventName {
	return event.UserInviteConsumedEvent
}

func (l *userInviteConsumedListener) Handle(ev events.Event) error {
	e := ev.(*event.UserInviteConsumed)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"invite_code": e.InviteCode,
		"user_id":     e.UserID.String(),
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}
	return nil
}

func toString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

type userConfirmedListener struct {
	store Auditor
	log   *zap.Logger
}

func (*userConfirmedListener) ForEvent() events.EventName {
	return event.UserConfirmedEvent
}

func (l *userConfirmedListener) Handle(ev events.Event) error {
	e := ev.(*event.UserConfirmed)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"auto_confirm": toString(e.AutoConfirmed),
		"user_id":      e.UserID.String(),
		"confirm_code": e.ConfirmCode,
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}
	return nil
}

type userSignupListener struct {
	store Auditor
	log   *zap.Logger
}

func (*userSignupListener) ForEvent() events.EventName {
	return event.UserSignupEvent
}

func (l *userSignupListener) Handle(ev events.Event) error {
	e := ev.(*event.UserSignup)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"user_id": e.UserID.String(),
		"email":   e.Email,
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}
	return nil
}

type userLockedListener struct {
	store Auditor
	log   *zap.Logger
}

func (*userLockedListener) ForEvent() events.EventName {
	return event.UserLockedEvent
}

func (l *userLockedListener) Handle(ev events.Event) error {
	e := ev.(*event.UserLocked)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"user_id":      e.UserID.String(),
		"locked_until": e.LockedUntil.Format("2006-02-01 03:04:05"),
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}

	return nil
}

type userUnlockedListener struct {
	store Auditor
	log   *zap.Logger
}

func (*userUnlockedListener) ForEvent() events.EventName {
	return event.UserUnlockedEvent
}

func (l *userUnlockedListener) Handle(ev events.Event) error {
	e := ev.(*event.UserUnlocked)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"user_id": e.UserID.String(),
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}

	return nil
}

type userBannedListener struct {
	store Auditor
	log   *zap.Logger
}

func (*userBannedListener) ForEvent() events.EventName {
	return event.UserBannedEvent
}

func (l *userBannedListener) Handle(ev events.Event) error {
	e := ev.(*event.UserUnlocked)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"user_id": e.UserID.String(),
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}

	return nil
}

type userUnbannedListener struct {
	store Auditor
	log   *zap.Logger
}

func (*userUnbannedListener) ForEvent() events.EventName {
	return event.UserUnbannedEvent
}

func (l *userUnbannedListener) Handle(ev events.Event) error {
	e := ev.(*event.UserUnlocked)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"user_id": e.UserID.String(),
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}

	return nil
}

type userLoginListener struct {
	store Auditor
	log   *zap.Logger
}

func (*userLoginListener) ForEvent() events.EventName {
	return event.UserLoginEvent
}

func (l *userLoginListener) Handle(ev events.Event) error {
	e := ev.(*event.UserLogin)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"user_id": e.UserID.String(),
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}

	return nil
}

type userPasswordRecoveryRequestedListener struct {
	store Auditor
	log   *zap.Logger
}

func (*userPasswordRecoveryRequestedListener) ForEvent() events.EventName {
	return event.UserPasswordRecoveryRequestedEvent
}

func (l *userPasswordRecoveryRequestedListener) Handle(ev events.Event) error {
	e := ev.(*event.UserPasswordRecoveryRequested)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"user_id": e.UserID.String(),
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}

	return nil
}

type userPasswordRecoveryUsedListener struct {
	store Auditor
	log   *zap.Logger
}

func (*userPasswordRecoveryUsedListener) ForEvent() events.EventName {
	return event.UserPasswordRecoveryUsedEvent
}

func (l *userPasswordRecoveryUsedListener) Handle(ev events.Event) error {
	e := ev.(*event.UserPasswordRecoveryUsed)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"user_id": e.UserID.String(),
		"email":   e.Email,
		"token":   e.Token,
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}

	return nil
}

type userEmailChangedListener struct {
	store Auditor
	log   *zap.Logger
}

func (*userEmailChangedListener) ForEvent() events.EventName {
	return event.UserEmailChangedEvent
}

func (l *userEmailChangedListener) Handle(ev events.Event) error {
	e := ev.(*event.UserEmailChanged)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"user_id":   e.UserID.String(),
		"new_email": e.Email,
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}

	return nil
}

type userPasswordChangedListener struct {
	store Auditor
	log   *zap.Logger
}

func (*userPasswordChangedListener) ForEvent() events.EventName {
	return event.UserPasswordChangedEvent
}

func (l *userPasswordChangedListener) Handle(ev events.Event) error {
	e := ev.(*event.UserPasswordChanged)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"user_id": e.UserID.String(),
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}
	return nil
}

type userRemovedFromRoleListener struct {
	store Auditor
	log   *zap.Logger
}

func (*userRemovedFromRoleListener) ForEvent() events.EventName {
	return event.UserRemovedFromRoleEvent
}

func (l *userRemovedFromRoleListener) Handle(ev events.Event) error {
	e := ev.(*event.UserRemovedFromRole)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"user_id": e.UserID.String(),
		"role":    e.Role,
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}
	return nil
}

type userAddedToRoleListener struct {
	store Auditor
	log   *zap.Logger
}

func (*userAddedToRoleListener) ForEvent() events.EventName {
	return event.UserAddedToRoleEvent
}

func (l *userAddedToRoleListener) Handle(ev events.Event) error {
	e := ev.(*event.UserAddedToRole)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"user_id": e.UserID.String(),
		"role":    e.Role,
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}
	return nil
}

type emailSignupConfirmSentListener struct {
	store Auditor
	log   *zap.Logger
}

func (*emailSignupConfirmSentListener) ForEvent() events.EventName {
	return event.EmailSignupConfirmSentEvent
}

func (l *emailSignupConfirmSentListener) Handle(ev events.Event) error {
	e := ev.(*event.EmailSignupConfirmSent)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"user_id": e.UserID.String(),
		"email":   e.Email,
		"token":   e.ConfirmToken,
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}
	return nil
}

type emailPasswordRecoverySentListener struct {
	store Auditor
	log   *zap.Logger
}

func (*emailPasswordRecoverySentListener) ForEvent() events.EventName {
	return event.EmailPasswordRecoverySentEvent
}

func (l *emailPasswordRecoverySentListener) Handle(ev events.Event) error {
	e := ev.(*event.EmailPasswordRecoverySent)

	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"user_id": e.UserID.String(),
		"email":   e.Email,
		"token":   e.ConfirmToken,
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}
	return nil
}

type emailInviteSentListener struct {
	store Auditor
	log   *zap.Logger
}

func (*emailInviteSentListener) ForEvent() events.EventName {
	return event.EmailInviteSentEvent
}

func (l *emailInviteSentListener) Handle(ev events.Event) error {
	e := ev.(*event.EmailInviteSent)

	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"email":       e.Email,
		"invite_code": e.InviteCode,
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}
	return nil
}

type securityAuthorizationGrantedListener struct {
	store Auditor
	log   *zap.Logger
}

func (*securityAuthorizationGrantedListener) ForEvent() events.EventName {
	return event.AuthorizationGrantedEvent
}

func (l *securityAuthorizationGrantedListener) Handle(ev events.Event) error {
	e := ev.(*event.AuthorizationGranted)

	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"email":          e.AuthorizationID,
		"user_id":        e.UserID,
		"application_id": e.ApplicationID,
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}
	return nil
}

type securityAuthorizationRevokedListener struct {
	store Auditor
	log   *zap.Logger
}

func (*securityAuthorizationRevokedListener) ForEvent() events.EventName {
	return event.AuthorizationRevokedEvent
}

func (l *securityAuthorizationRevokedListener) Handle(ev events.Event) error {
	e := ev.(*event.AuthorizationRevoked)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"email":           e.AuthorizationID.String(),
		"user_id":         e.UserID.String(),
		"application_id":  e.ApplicationID,
		"affected_tokens": e.TokensAffected,
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}
	return nil
}

type tokenRevokedListener struct {
	store Auditor
	log   *zap.Logger
}

func (*tokenRevokedListener) ForEvent() events.EventName {
	return event.TokenRevokedEvent
}

func (l *tokenRevokedListener) Handle(ev events.Event) error {
	e := ev.(*event.TokenRevoked)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"email":      e.AuthorizationID.String(),
		"user_id":    e.UserID.String(),
		"token_id":   e.TokenID,
		"token":      e.Token,
		"token_type": e.TokenType,
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}
	return nil
}

type mfaEnabledListener struct {
	store Auditor
	log   *zap.Logger
}

func (*mfaEnabledListener) ForEvent() events.EventName {
	return event.UserMFAEnabledEvent
}

func (l *mfaEnabledListener) Handle(ev events.Event) error {
	e := ev.(*event.UserMFAEnabled)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"user_id": e.UserID.String(),
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}
	return nil
}

type mfaDisabledListener struct {
	store Auditor
	log   *zap.Logger
}

func (*mfaDisabledListener) ForEvent() events.EventName {
	return event.UserMFADisabledEvent
}

func (l *mfaDisabledListener) Handle(ev events.Event) error {
	e := ev.(*event.UserMFADisabled)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"user_id": e.UserID.String(),
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}
	return nil
}

type applicationCreatedListener struct {
	store Auditor
	log   *zap.Logger
}

func (*applicationCreatedListener) ForEvent() events.EventName {
	return event.ApplicationCreatedEvent
}

func (l *applicationCreatedListener) Handle(ev events.Event) error {
	e := ev.(*event.ApplicationCreated)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"application_id": e.ApplicationID,
		"client_id":      e.ClientID,
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}
	return nil
}

type applicationRetiredListener struct {
	store Auditor
	log   *zap.Logger
}

func (*applicationRetiredListener) ForEvent() events.EventName {
	return event.ApplicationRetiredEvent
}

func (l *applicationRetiredListener) Handle(ev events.Event) error {
	e := ev.(*event.ApplicationRetired)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"application_id": e.ApplicationID,
		"client_id":      e.ClientID,
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}
	return nil
}

type applicationPurgeListener struct {
	store Auditor
	log   *zap.Logger
}

func (*applicationPurgeListener) ForEvent() events.EventName {
	return event.AllRetiredApplicationsPurgedEvent
}

func (l *applicationPurgeListener) Handle(ev events.Event) error {
	e := ev.(*event.AllRetiredApplicationsPurged)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"affected_client_ids": e.AffectedClientIDs,
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}
	return nil
}

type userSignedInByTokenListener struct {
	store Auditor
	log   *zap.Logger
}

func (*userSignedInByTokenListener) ForEvent() events.EventName {
	return event.UserSignedInByTokenEvent
}

func (l *userSignedInByTokenListener) Handle(ev events.Event) error {
	e := ev.(*event.UserSignedInByToken)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"user_id":    e.UserID.String(),
		"token_type": e.TokenType,
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}
	return nil
}

type roleCreatedListener struct {
	store Auditor
	log   *zap.Logger
}

func (*roleCreatedListener) ForEvent() events.EventName {
	return event.RoleCreatedEvent
}

func (l *roleCreatedListener) Handle(ev events.Event) error {
	e := ev.(*event.RoleCreated)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"role": e.Role,
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}
	return nil
}

type roleDeletedListener struct {
	store Auditor
	log   *zap.Logger
}

func (*roleDeletedListener) ForEvent() events.EventName {
	return event.RoleDeletedEvent
}

func (l *roleDeletedListener) Handle(ev events.Event) error {
	e := ev.(*event.RoleDeleted)
	err := l.store.addToAuditLog(string(l.ForEvent()), map[string]interface{}{
		"role": e.Role,
	})
	if err != nil {
		l.log.Warn("Could not persist event to audit log", zap.Error(err))
	}
	return nil
}
