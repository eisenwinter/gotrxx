package tables

import "time"

// UserInviteTable represents the table
type UserInviteTable struct {
	ID         int        `db:"id" fiql:"id,db:id"`
	Email      *string    `db:"email" email:"type,db:email"`
	Code       string     `db:"code" fiql:"code,db:code"`
	SentAt     *time.Time `db:"sent_at" fiql:"sent_at,db:sent_at"`
	ConsumedAt *time.Time `db:"consumed_at" fiql:"consumed_at,db:consumed_at"`
	ExpiresAt  time.Time  `db:"expires_at" fiql:"expires_at,db:expires_at"`
	CreatedAt  time.Time  `db:"created_at" fiql:"created_at,db:created_at"`
}
