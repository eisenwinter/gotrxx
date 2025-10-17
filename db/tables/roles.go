package tables

import "time"

// RoleTable represents the roles table
type RoleTable struct {
	ID        int       `db:"id,omitempty" fiql:"id,db:id"`
	Name      string    `db:"name"         fiql:"name,db:name"`
	CreatedAt time.Time `db:"created_at"   fiql:"created_at,db:created_at"`
}
