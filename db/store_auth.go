package db

import (
	"context"
	"database/sql"
	"errors"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/eisenwinter/gotrxx/db/tables"
	"github.com/google/uuid"
)

func (d *DataStore) Authorizations(
	ctx context.Context,
	opts ListOptions,
) ([]*tables.AuthorizationTable, int, error) {
	if opts.Page <= 0 {
		opts.Page = 1
	}
	var c int
	err := sq.Select("COUNT(*)").From("authorizations").RunWith(d.db).Scan(&c)
	if err != nil {
		return nil, 0, err
	}
	offset := (opts.Page - 1) * opts.PageSize
	if c < int(offset) {
		return []*tables.AuthorizationTable{}, c, nil
	}

	var entities []*tables.AuthorizationTable
	q := sq.
		Select(
			"id",
			"application_id",
			"user_id",
			"properties",
			"revoked_at",
			"created_at",
			"updated_at",
		).
		From("authorizations").
		OrderBy("id DESC").Offset(uint64(offset)).Limit(uint64(opts.PageSize))
	err = d.selectStatement(ctx, &entities, q, nil)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, 0, ErrNotFound
		}
		return nil, 0, err
	}

	return entities, c, nil
}

func (d *DataStore) ActiveAuthorizationsByUserID(
	ctx context.Context,
	userID uuid.UUID,
) ([]*tables.AuthorizationTable, error) {
	q := sq.
		Select("authorizations.id",
			"authorizations.application_id",
			"authorizations.user_id",
			"authorizations.properties",
			"authorizations.revoked_at",
			"authorizations.created_at",
			"authorizations.updated_at").
		From("authorizations").
		InnerJoin("applications on authorizations.application_id = applications.id").
		Where(sq.And{
			sq.Eq{"authorizations.user_id": userID},
			sq.Eq{"authorizations.revoked_at": nil},
			sq.Eq{"applications.retired_on": nil},
		}).
		OrderBy("authorizations.revoked_at ASC, applications.retired_on ASC")

	var entities []*tables.AuthorizationTable
	err := d.selectStatement(ctx, &entities, q, nil)
	if err != nil {
		if errors.Is(sql.ErrNoRows, err) {
			return []*tables.AuthorizationTable{}, nil
		}
		return nil, err
	}
	return entities, nil
}

func (d *DataStore) AuthorizationByID(
	ctx context.Context,
	id uuid.UUID,
) (*tables.AuthorizationTable, error) {
	q := sq.
		Select(
			"id",
			"application_id",
			"user_id",
			"properties",
			"revoked_at",
			"created_at",
			"updated_at",
		).
		From("authorizations").
		Where(sq.Eq{"id": id})
	var table tables.AuthorizationTable
	err := d.getStatement(ctx, &table, q, nil)
	if err != nil {
		if errors.Is(sql.ErrNoRows, err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &table, nil
}

func (d *DataStore) ActiveAuthorizationByUserAndClientID(
	ctx context.Context,
	clientID string,
	userID uuid.UUID,
) (*tables.AuthorizationTable, error) {
	q := sq.
		Select("authorizations.id",
			"authorizations.application_id",
			"authorizations.user_id",
			"authorizations.properties",
			"authorizations.revoked_at",
			"authorizations.created_at",
			"authorizations.updated_at").
		From("authorizations").
		Join("applications on authorizations.application_id = applications.id").
		Where(sq.And{
			sq.Eq{"authorizations.user_id": userID},
			sq.Eq{"applications.client_id": clientID},
			sq.Eq{"authorizations.revoked_at": nil},
			sq.Eq{"applications.retired_on": nil},
		}).
		OrderBy("authorizations.revoked_at ASC, applications.retired_on ASC")
	var table tables.AuthorizationTable
	err := d.getStatement(ctx, &table, q, nil)
	if err != nil {
		if errors.Is(sql.ErrNoRows, err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &table, nil
}

func (d *DataStore) ActiveAuthorizationByCommonToken(
	ctx context.Context,
	tokenType string,
	token string,
) (*tables.AuthorizationTable, error) {
	q := sq.
		Select("authorizations.id",
			"authorizations.application_id",
			"authorizations.user_id",
			"authorizations.properties",
			"authorizations.revoked_at",
			"authorizations.created_at",
			"authorizations.updated_at").
		From("tokens").
		Join("authorizations on tokens.authorization_id = authorizations.id").
		Join("applications on authorizations.application_id = applications.id").
		Where(sq.And{
			sq.Eq{"tokens.token_type": tokenType},
			sq.Eq{"tokens.token": token},
			sq.Eq{"authorizations.revoked_at": nil},
			sq.Eq{"applications.retired_on": nil},
			sq.Eq{"tokens.revoked_at": nil},
			sq.Eq{"tokens.redeemed_at": nil},
			sq.GtOrEq{"tokens.expires_at": time.Now().UTC()},
		}).
		OrderBy("authorizations.revoked_at ASC, applications.retired_on ASC")
	var table tables.AuthorizationTable
	err := d.getStatement(ctx, &table, q, nil)
	if err != nil {
		if errors.Is(sql.ErrNoRows, err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &table, nil
}

func (d *DataStore) GrantAuthorization(
	ctx context.Context,
	applicationId int,
	userID uuid.UUID,
	properties tables.MapStructure,
) (uuid.UUID, error) {
	m := map[string]interface{}{
		"application_id": applicationId,
		"user_id":        userID,
		"properties":     properties,
		"created_at":     time.Now().UTC(),
	}
	m["id"] = uuid.New() //Todo: decide if db suports auto uuid
	insert := sq.Insert("authorizations").SetMap(m)
	insert = insert.Suffix("RETURNING id")
	var id uuid.UUID
	err := d.returningInsertStatement(ctx, &id, insert, nil)
	d.log.Debug("granted authorization")
	return id, err
}

func (d *DataStore) RevokeAuthorization(ctx context.Context, id uuid.UUID) (int64, error) {
	tx, err := d.db.BeginTxx(ctx, nil)
	if err != nil {
		if tx != nil {
			rollBack(tx, d)
		}
		return 0, err
	}
	a := sq.Update("authorizations").
		Set("updated_at", time.Now().UTC()).
		Set("revoked_at", time.Now().UTC()).
		Where(sq.Eq{"id": id})
	_, err = d.updateStatement(ctx, a, tx)
	if err != nil {
		rollBack(tx, d)
		return 0, err
	}
	t := sq.Update("tokens").
		Set("updated_at", time.Now().UTC()).
		Set("revoked_at", time.Now().UTC()).
		Where(sq.And{sq.Eq{"authorization_id": id}, sq.GtOrEq{"expires_at": time.Now().UTC()}})
	rs, err := d.updateStatement(ctx, t, tx)
	if err != nil {
		rollBack(tx, d)
		return 0, err
	}
	count, err := rs.RowsAffected()
	if err != nil {
		rollBack(tx, d)
		return 0, err
	}
	err = tx.Commit()
	if err != nil {
		rollBack(tx, d)
		return 0, err
	}
	return count, nil
}
