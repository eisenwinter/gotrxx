package tables

import (
	"time"

	"github.com/google/uuid"
)

// UserTable represents the users table
type UserTable struct {
	ID                   uuid.UUID  `db:"id,omitempty"                     fiql:"id,db:id"`
	Email                string     `db:"email"                            fiql:"email,db:email"`
	EmailConfirmed       *time.Time `db:"email_confirmed"`
	Phone                *string    `db:"phone"                            fiql:"phone,db:phone"`
	PhoneConfirmed       *time.Time `db:"phone_confirmed"`
	Mfa                  bool       `db:"mfa"`
	MfaSecret            *string    `db:"mfa_secret"                                                                             json:"-"`
	MfaRecoveryKey       *string    `db:"mfa_recovery_key"                                                                       json:"-"`
	PendingOTP           bool       `db:"pending_otp"`
	LockoutTill          *time.Time `db:"lockout_till"                     fiql:"lockout_till,db:lockout_till"`
	BannedOn             *time.Time `db:"banned_on"                        fiql:"banned_on,db:banned_on"`
	Password             string     `db:"password"                                                                               json:"-"`
	CurrentFailureCount  int        `db:"current_failure_count"`
	RecoveryToken        *string    `db:"recovery_token"                                                                         json:"-"`
	RecoveryTokenCreated *time.Time `db:"recovery_token_created,omitempty"`
	ConfirmToken         *string    `db:"confirm_token"                    fiql:"confirm_token,db:confirm_token"`
	ConfirmTokenCreated  *time.Time `db:"confirm_token_created,omitempty"  fiql:"confirm_token_created,db:confirm_token_created"`
	CreatedAt            time.Time  `db:"created_at"                       fiql:"created_at,db:created_at"`
	UpdatedAt            *time.Time `db:"updated_at,omitempty"             fiql:"updated_at,db:updated_at"`
}
