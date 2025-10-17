package tables

import "github.com/google/uuid"

// UserRoleTable represents the table
type UserRoleTable struct {
	RoleID int       `db:"role_id"`
	UserID uuid.UUID `db:"user_id"`
}
