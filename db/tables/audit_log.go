package tables

import "time"

// AuditLogTable represents the audit_log table
type AuditLogTable struct {
	ID        int       `db:"id"`
	EventType string    `db:"event_type"`
	Event     string    `db:"event"`
	CreatedAt time.Time `db:"created_at"`
}
