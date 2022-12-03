package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/adlio/schema"
	"github.com/eisenwinter/gotrxx/config"
	"github.com/eisenwinter/gotrxx/db/tables"
	"github.com/jmoiron/sqlx"

	"go.uber.org/zap"

	sq "github.com/Masterminds/squirrel"
	fq "github.com/eisenwinter/fiql-sql-adapter"
)

//go:embed migrations
var migrations embed.FS

var (
	// ErrNotFound indicates the requested entity was not found
	ErrNotFound = errors.New("the requested entry was not found")
	// ErrAlreadyExists indicates the entity already exists within the store
	ErrAlreadyExists = errors.New("this entity already exists")
	// ErrInUse signals a foreign key violation
	ErrInUse = errors.New("this entity is needed for another entity")
)

type DataStore struct {
	log      *zap.Logger
	db       *sqlx.DB
	adapters map[string]*fq.Adapter
	migrate  func() error
}

func (d *DataStore) Close() {
	d.db.Close()
}

func (d *DataStore) EnsureUsable() error {
	if d.migrate != nil {
		return d.migrate()
	}
	return nil
}

func (d *DataStore) exists(
	ctx context.Context,
	table string,
	pred interface{},
	args ...interface{},
) (bool, error) {
	var result bool
	q := sq.Select("1").Prefix("SELECT EXISTS (").From(table).Where(pred, args).Suffix(")")
	err := q.RunWith(d.db).ScanContext(ctx, &result)
	if err != nil {
		return false, err
	}
	return result, nil
}

func (d *DataStore) getStatement(
	ctx context.Context,
	dest interface{},
	statement sq.SelectBuilder,
	tx *sqlx.Tx,
) error {
	q, a, err := statement.ToSql()
	if err != nil {
		d.log.Error("Unable to construct sql", zap.Error(err))
		return err
	}
	//d.log.Debug("SQL statement built", zap.String("sql", q))
	if tx != nil {
		return tx.GetContext(ctx, dest, q, a...)
	}
	return d.db.GetContext(ctx, dest, q, a...)
}

func (d *DataStore) returningInsertStatement(
	ctx context.Context,
	dest interface{},
	statement sq.InsertBuilder,
	tx *sqlx.Tx,
) error {
	q, a, err := statement.ToSql()
	if err != nil {
		d.log.Error("Unable to construct sql", zap.Error(err))
		return err
	}
	if tx != nil {
		return tx.GetContext(ctx, dest, q, a...)
	}
	return d.db.GetContext(ctx, dest, q, a...)
}

func (d *DataStore) selectStatement(
	ctx context.Context,
	dest interface{},
	statement sq.SelectBuilder,
	tx *sqlx.Tx,
) error {
	q, a, err := statement.ToSql()
	if err != nil {
		d.log.Error("Unable to construct sql", zap.Error(err))
		return err
	}
	if tx != nil {
		return tx.SelectContext(ctx, dest, q, a...)
	}
	return d.db.SelectContext(ctx, dest, q, a...)
}

func (d *DataStore) deleteStatement(
	ctx context.Context,
	statement sq.DeleteBuilder,
	tx *sqlx.Tx,
) (sql.Result, error) {
	q, a, err := statement.ToSql()
	if err != nil {
		d.log.Error("Unable to construct sql", zap.Error(err))
		return nil, err
	}
	if tx != nil {
		return tx.ExecContext(ctx, q, a...)
	}
	return d.db.ExecContext(ctx, q, a...)
}

func (d *DataStore) insertStatement(
	ctx context.Context,
	statement sq.InsertBuilder,
	tx *sqlx.Tx,
) (sql.Result, error) {
	q, a, err := statement.ToSql()
	if err != nil {
		d.log.Error("Unable to construct sql", zap.Error(err))
		return nil, err
	}
	if tx != nil {
		return tx.ExecContext(ctx, q, a...)
	}
	return d.db.ExecContext(ctx, q, a...)
}

func (d *DataStore) updateStatement(
	ctx context.Context,
	statement sq.UpdateBuilder,
	tx *sqlx.Tx,
) (sql.Result, error) {
	q, a, err := statement.ToSql()
	if err != nil {
		d.log.Error("Unable to construct sql", zap.Error(err))
		return nil, err
	}
	if tx != nil {
		return tx.ExecContext(ctx, q, a...)
	}
	return d.db.ExecContext(ctx, q, a...)
}

func NewStore(logger *zap.Logger, cfg *config.DatabaseConfiguration) (*DataStore, error) {
	switch cfg.Type {
	case "sqlite":
		return NewSqliteStore(logger.Named("database"), cfg)
	case "mysql":
		return NewMysqlStore(logger.Named("database"), cfg)
	case "pg":
		return NewPostgrestore(logger.Named("database"), cfg)
	default:
		return nil, errors.New("unknown datastore")
	}
}

func NewMysqlStore(logger *zap.Logger, cfg *config.DatabaseConfiguration) (*DataStore, error) {
	adaptedDsn := cfg.DSN
	if strings.Contains(adaptedDsn, "?") {
		adaptedDsn += "&parseTime=true"
	} else {
		adaptedDsn += "?parseTime=true"
	}
	db, err := sqlx.Open("mysql", adaptedDsn)
	if err != nil {
		logger.Error("Could open database", zap.Error(err))
		return nil, err
	}

	migrate := func() error {
		migdb, err := sqlx.Open("mysql", cfg.DSN+"?multiStatements=True")
		if err != nil {
			logger.Error("Could open database", zap.Error(err))
			return err
		}

		migrator := schema.NewMigrator(schema.WithDialect(schema.MySQL))
		mig, err := schema.FSMigrations(migrations, "migrations/mysql/*.sql")
		if err != nil {
			return err
		}
		return migrator.Apply(
			migdb,
			mig,
		)
	}

	return &DataStore{
		log:      logger,
		db:       db,
		migrate:  migrate,
		adapters: createMapping(fq.WithDialectMariaDB()),
	}, nil

}

func NewPostgrestore(logger *zap.Logger, cfg *config.DatabaseConfiguration) (*DataStore, error) {
	db, err := sqlx.Open("pgx", cfg.DSN)
	if err != nil {
		logger.Error("Could open database", zap.Error(err))
		return nil, err
	}

	migrate := func() error {
		database := db.DB
		migrator := schema.NewMigrator(schema.WithDialect(schema.Postgres))
		mig, err := schema.FSMigrations(migrations, "migrations/pg/*.sql")
		if err != nil {
			return err
		}
		return migrator.Apply(
			database,
			mig,
		)
	}

	return &DataStore{
		log:      logger,
		db:       db,
		migrate:  migrate,
		adapters: createMapping(fq.WithDialectPostgres()),
	}, nil

}

func NewSqliteStore(logger *zap.Logger, cfg *config.DatabaseConfiguration) (*DataStore, error) {
	db, err := sqlx.Open("sqlite3", cfg.DSN)
	if err != nil {
		logger.Error("Could open database", zap.Error(err))
		return nil, err
	}

	// check if dsn contains a directory which needs to be created
	split := strings.Split(cfg.DSN, "?")
	if len(split) >= 1 && strings.ContainsRune(split[0], os.PathSeparator) {
		striped := strings.TrimPrefix(split[0], "file:")
		dir := filepath.Dir(striped)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			logger.Warn("Trying to create directory", zap.String("directory", dir))
			err = os.Mkdir(dir, 0650)
			if err != nil {
				logger.Error("Could open database", zap.Error(err))
				return nil, err
			}
		}

	}

	migrate := func() error {
		database := db.DB
		migrator := schema.NewMigrator(schema.WithDialect(schema.SQLite))
		mig, err := schema.FSMigrations(migrations, "migrations/sqlite/*.sql")
		if err != nil {
			return err
		}
		return migrator.Apply(
			database,
			mig,
		)
	}

	return &DataStore{
		log:      logger,
		db:       db,
		migrate:  migrate,
		adapters: createMapping(fq.WithDialectSQLite()),
	}, nil

}

func createMapping(options ...func(*fq.Adapter)) map[string]*fq.Adapter {
	adapters := make(map[string]*fq.Adapter)
	adapters["applications"] = fq.NewAdapterFor(tables.ApplicationTable{}, options...)
	adapters["user_invites"] = fq.NewAdapterFor(tables.UserInviteTable{}, options...)
	adapters["roles"] = fq.NewAdapterFor(tables.RoleTable{}, options...)
	adapters["users"] = fq.NewAdapterFor(tables.UserTable{}, options...)
	return adapters
}

func (d *DataStore) Auditor() Auditor {
	return &auditor{
		db: d.db,
	}
}
