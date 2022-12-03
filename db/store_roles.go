package db

import (
	"context"
	"database/sql"
	"errors"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/eisenwinter/gotrxx/db/tables"
)

// Roles gets all roles in the datastore paginated
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

// AddRole adds a role to the datastore
func (d *DataStore) AddRole(ctx context.Context, role string) (int, error) {
	exists, err := d.exists(ctx, "roles", sq.Eq{"name": role})
	if err != nil {
		return 0, err
	}
	if exists {
		return 0, ErrAlreadyExists
	}

	var roleID int
	ins := sq.
		Insert("roles").
		Columns("name", "created_at").
		Values(role, time.Now().UTC()).
		Suffix("RETURNING id")
	err = d.returningInsertStatement(ctx, &roleID, ins, nil)
	if err != nil {
		return roleID, err
	}
	return roleID, nil
}

// DeleteRole delets a role from the datastore
func (d *DataStore) DeleteRole(ctx context.Context, role string) error {
	roleQuery := sq.Select("id").From("roles").Where(sq.Eq{"role": role})
	var roleID int
	err := roleQuery.RunWith(d.db).QueryRow().Scan(&roleID)
	if err != nil {
		if errors.Is(sql.ErrNoRows, err) {
			return ErrNotFound
		}
		return err
	}

	exists, err := d.exists(ctx, "user_invite_roles", sq.Eq{"role_id": roleID})
	if err != nil {
		return err
	}
	if exists {
		return ErrInUse
	}
	exists, err = d.exists(ctx, "user_roles", sq.Eq{"role_id": roleID})
	if err != nil {
		return err
	}
	if exists {
		return ErrInUse
	}
	del := sq.Delete("roles").Where(sq.Eq{"id": roleID})
	_, err = d.deleteStatement(ctx, del, nil)
	return err
}
