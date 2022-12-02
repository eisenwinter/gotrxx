package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/eisenwinter/gotrxx/db/tables"
	"go.uber.org/zap"
)

func (d *DataStore) whereFromAdapater(
	table string,
	query string,
) (func(sq.SelectBuilder) sq.SelectBuilder, error) {
	if query != "" {
		where, err := d.adapters[table].Where(query)
		if err != nil {
			return nil, err
		}
		w, a, err := where.ToSql()
		if err != nil {
			return nil, err
		}
		return func(sb sq.SelectBuilder) sq.SelectBuilder {
			return sb.Where(w, a...)
		}, nil

	}
	return func(sb sq.SelectBuilder) sq.SelectBuilder {
		return sb
	}, nil
}

func (d *DataStore) orderByFromAdapater(
	q sq.SelectBuilder,
	table string,
	defaultOrderby string,
	opts ListOptions,
) sq.SelectBuilder {
	if opts.Sort != "" {
		order, err := d.adapters[table].OrderBy(opts.Sort)
		if err != nil {
			q = q.OrderBy(defaultOrderby)
		} else {
			or, _, _ := order.ToSql()
			q = q.OrderBy(or)
		}
	} else {
		q = q.OrderBy(defaultOrderby)
	}
	return q
}

func (d *DataStore) Applications(
	ctx context.Context,
	opts ListOptions,
) ([]*tables.ApplicationTable, int, error) {
	if opts.Page <= 0 {
		opts.Page = 1
	}
	var c int
	count := sq.Select("COUNT(*)").From("applications")
	applyWhere, err := d.whereFromAdapater("applications", opts.Query)
	if err != nil {
		return nil, 0, err
	}
	count = applyWhere(count)
	err = count.RunWith(d.db).Scan(&c)
	if err != nil {
		return nil, 0, err
	}
	offset := (opts.Page - 1) * opts.PageSize
	if c < int(offset) {
		return []*tables.ApplicationTable{}, c, nil
	}

	if err != nil {
		return nil, 0, err
	}

	var entities []*tables.ApplicationTable
	q := sq.
		Select(
			"id",
			"client_id",
			"name",
			"type",
			"properties",
			"retired_on",
			"confidentiality",
			"client_secret",
		).
		From("applications")
	q = applyWhere(q)
	q = d.orderByFromAdapater(q, "applications", "id DESC", opts)
	q = q.Offset(uint64(offset)).Limit(uint64(opts.PageSize))
	err = d.selectStatement(ctx, &entities, q, nil)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, 0, ErrNotFound
		}
		return nil, 0, err
	}

	return entities, c, nil
}

func (d *DataStore) ApplicationByClientID(
	ctx context.Context,
	clientID string,
) (*tables.ApplicationTable, error) {
	var entity tables.ApplicationTable
	q := sq.
		Select(
			"id",
			"client_id",
			"name",
			"type",
			"properties",
			"retired_on",
			"confidentiality",
			"client_secret",
		).
		From("applications").Where(sq.Eq{"client_id": clientID})
	err := d.getStatement(ctx, &entity, q, nil)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &entity, nil
}

func (d *DataStore) ApplicationByID(ctx context.Context, id int) (*tables.ApplicationTable, error) {
	var entity tables.ApplicationTable
	q := sq.
		Select(
			"id",
			"client_id",
			"name",
			"type",
			"properties",
			"retired_on",
			"confidentiality",
			"client_secret",
		).
		From("applications").Where(sq.Eq{"id": id})
	err := d.getStatement(ctx, &entity, q, nil)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &entity, nil
}

func (d *DataStore) ActiveApplicationsWithUserAuthorizations(
	ctx context.Context,
	userID uuid.UUID,
) ([]*tables.ApplicationTable, error) {
	q := sq.
		Select("applications.id",
			"applications.client_id",
			"applications.name",
			"applications.type",
			"applications.properties",
			"applications.retired_on",
			"applications.confidentiality",
			"applications.client_secret").
		From("applications").
		InnerJoin("authorizations on authorizations.application_id = applications.id").
		Where(sq.And{
			sq.Eq{"authorizations.user_id": userID},
			sq.Eq{"authorizations.revoked_at": nil},
			sq.Eq{"applications.retired_on": nil},
		})

	var entities []*tables.ApplicationTable
	err := d.selectStatement(ctx, &entities, q, nil)
	if err != nil {
		if errors.Is(sql.ErrNoRows, err) {
			return []*tables.ApplicationTable{}, nil
		}
		return nil, err
	}
	return entities, nil
}

func (d *DataStore) CreateApplication(ctx context.Context,
	appType int,
	clientID string,
	clientSecret *string,
	name string,
	confidentiality string,
	properties tables.MapStructure) (int, error) {
	m := map[string]interface{}{"client_id": clientID,
		"name":            name,
		"type":            appType,
		"confidentiality": confidentiality,
		"properties":      properties,
		"client_secret":   clientSecret,
		"created_at":      time.Now().UTC()}
	insert := sq.Insert("applications").SetMap(m)
	insert = insert.Suffix("RETURNING id")
	var id int
	err := d.returningInsertStatement(ctx, &id, insert, nil)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return 0, ErrAlreadyExists
		}
		d.log.Error("could not insert app", zap.Error(err))
		return 0, err
	}
	return id, nil
}

func (d *DataStore) UpdateApplicationProperties(
	ctx context.Context,
	clientID string,
	properties tables.MapStructure,
) error {
	ts := time.Now().UTC()
	app := sq.
		Update("applications").
		Set("updated_at", ts).
		Set("properties", properties).
		Where(sq.Eq{"client_id": clientID})
	_, err := d.updateStatement(ctx, app, nil)
	return err
}

func (d *DataStore) SetApplicationSecret(
	ctx context.Context,
	clientID string,
	secret string,
) error {
	ts := time.Now().UTC()
	app := sq.
		Update("applications").
		Set("updated_at", ts).
		Set("client_secret", secret).
		Where(sq.Eq{"client_id": clientID})
	_, err := d.updateStatement(ctx, app, nil)
	return err
}

func (d *DataStore) DeleteAllRetiredApplications(ctx context.Context) ([]string, error) {
	sel := sq.Select("client_id").From("applications").Where("retired_on IS NOT NULL")
	var clientIDs []string
	err := d.selectStatement(ctx, &clientIDs, sel, nil)
	if err != nil {
		return clientIDs, err
	}
	del := sq.Delete("applications").Where("retired_on IS NOT NULL")
	_, err = del.RunWith(d.db).ExecContext(ctx)
	if err != nil {
		return clientIDs, err
	}
	return clientIDs, nil
}

func (d *DataStore) RetireApplication(ctx context.Context, id int) (int64, int64, error) {
	tx, err := d.db.BeginTxx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	ts := time.Now().UTC()

	app := sq.
		Update("applications").
		Set("updated_at", ts).
		Set("retired_on", ts).
		Where(sq.And{sq.Eq{"id": id}, sq.Eq{"retired_on": nil}})
	_, err = d.updateStatement(ctx, app, tx)
	if err != nil {
		rollBack(tx, d)
		return 0, 0, err
	}
	aut := sq.
		Update("authorizations").
		Set("updated_at", ts).
		Set("revoked_at", ts).
		Where(sq.Eq{"application_id": id})
	rs, err := d.updateStatement(ctx, aut, tx)
	if err != nil {
		rollBack(tx, d)
		return 0, 0, err
	}
	auths, err := rs.RowsAffected()
	if err != nil {
		rollBack(tx, d)
		return 0, 0, err
	}
	tok := sq.
		Update("tokens").
		Set("updated_at", ts).
		Set("revoked_at", ts).
		Where(sq.Eq{"application_id": id})
	rs, err = d.updateStatement(ctx, tok, tx)
	if err != nil {
		rollBack(tx, d)
		return 0, 0, err
	}
	tokens, err := rs.RowsAffected()
	if err != nil {
		rollBack(tx, d)
		return 0, 0, err
	}
	err = tx.Commit()
	if err != nil {
		return 0, 0, err
	}
	return auths, tokens, nil
}

func rollBack(tx *sqlx.Tx, d *DataStore) {
	if rerr := tx.Rollback(); rerr != nil {
		d.log.Error("couldnt rollback", zap.Error(rerr))
	}
}
