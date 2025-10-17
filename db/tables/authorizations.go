package tables

import (
	"time"

	"github.com/google/uuid"
)

// AuthorizationTable represents the authorizations table
type AuthorizationTable struct {
	ID            uuid.UUID    `db:"id,omitempty"`
	ApplicationID int          `db:"application_id"`
	UserID        uuid.UUID    `db:"user_id"`
	Properties    MapStructure `db:"properties"`
	RevokedAt     *time.Time   `db:"revoked_at"`
	CreatedAt     time.Time    `db:"created_at"`
	UpdatedAt     *time.Time   `db:"updated_at"`
}
