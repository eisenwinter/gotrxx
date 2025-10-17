package tables

import (
	"time"
)

// ApplicationTable represents the applications table
type ApplicationTable struct {
	ID              int          `db:"id,omitempty"    fiql:"id,db:id"`
	ClientID        string       `db:"client_id"       fiql:"client_id,db:client_id"`
	ClientSecret    *string      `db:"client_secret"                                             json:"-"`
	Name            string       `db:"name"            fiql:"name,db:name"`
	ApplicationType int          `db:"type"            fiql:"type,db:type"`
	Confidentiality string       `db:"confidentiality" fiql:"confidentiality,db:confidentiality"`
	Properties      MapStructure `db:"properties"`
	RetiredOn       *time.Time   `db:"retired_on"      fiql:"retired_on,db:retired_on"`
	CreatedAt       time.Time    `db:"created_at"      fiql:"created_at,db:created_at"`
	UpdatedAt       *time.Time   `db:"updated_at"      fiql:"updated_at,db:updated_at"`
}
