package tables

import (
	"time"

	"github.com/google/uuid"
)

// TokenTable represents the tokens table
type TokenTable struct {
	ID              int          `db:"id,omitempty"`
	ApplicationID   int          `db:"application_id"`
	AuthorizationID uuid.UUID    `db:"authorization_id"`
	UserID          uuid.UUID    `db:"user_id"`
	TokenType       string       `db:"token_type"`
	Token           string       `db:"token"`
	Properties      MapStructure `db:"properties"`
	RedeemedAt      *time.Time   `db:"redeemed_at"`
	RevokedAt       *time.Time   `db:"revoked_at"`
	ExpiresAt       time.Time    `db:"expires_at"`
	CreatedAt       time.Time    `db:"created_at"`
	UpdatedAt       *time.Time   `db:"updated_at"`
}
