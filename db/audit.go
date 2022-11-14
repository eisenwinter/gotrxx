package db

import (
	"time"

	"github.com/eisenwinter/gotrxx/db/tables"
	"github.com/jmoiron/sqlx"

	sq "github.com/Masterminds/squirrel"
)

type auditor struct {
	db *sqlx.DB
}

// addToAuditLog adds a audit log entry

func (d *auditor) addToAuditLog(event string, payload tables.MapStructure) error {
	insert := sq.
		Insert("audit_logs").
		Columns("event_type", "event", "created_at").
		Values(event, payload, time.Now().UTC())
	_, err := insert.RunWith(d.db).Exec()
	return err
}
