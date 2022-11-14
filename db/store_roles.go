package db

import (
	"context"
	"database/sql"
	"errors"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/eisenwinter/gotrxx/db/tables"
)

func (d *DataStore) Roles(ctx context.Context, opts ListOptions) ([]*tables.RoleTable, int, error) {
	if opts.Page <= 0 {
		opts.Page = 1
	}

	var c int
	count := sq.Select("COUNT(*)").From("roles")
	applyWhere, err := d.whereFromAdapater("roles", opts.Query)
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
		return []*tables.RoleTable{}, c, nil
	}
	var entities []*tables.RoleTable
	q := sq.
		Select("id", "name", "created_at").
		From("roles")
	q = applyWhere(q)
	q = d.orderByFromAdapater(q, "roles", "id DESC", opts)
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

func (d *DataStore) AddRole(ctx context.Context, role string) (int, error) {
	exists, err := d.exists("roles", sq.Eq{"name": role})
	if err != nil {
		return 0, err
	}
	if exists {
		return 0, ErrAlreadyExists
	}

	var roleId int
	ins := sq.
		Insert("roles").
		Columns("name", "created_at").
		Values(role, time.Now().UTC()).
		Suffix("RETURNING id")
	err = d.returningInsertStatement(ctx, &roleId, ins, nil)
	if err != nil {
		return roleId, err
	}
	return roleId, nil
}

func (d *DataStore) DeleteRole(ctx context.Context, role string) error {
	roleQuery := sq.Select("id").From("roles").Where(sq.Eq{"role": role})
	var roleId int
	err := roleQuery.RunWith(d.db).QueryRow().Scan(&roleId)
	if err != nil {
		if errors.Is(sql.ErrNoRows, err) {
			return ErrNotFound
		}
		return err
	}

	exists, err := d.exists("user_invite_roles", sq.Eq{"role_id": roleId})
	if err != nil {
		return err
	}
	if exists {
		return ErrInUse
	}
	exists, err = d.exists("user_roles", sq.Eq{"role_id": roleId})
	if err != nil {
		return err
	}
	if exists {
		return ErrInUse
	}
	del := sq.Delete("roles").Where(sq.Eq{"id": roleId})
	_, err = d.deleteStatement(ctx, del, nil)
	return err
}
