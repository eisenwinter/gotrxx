package db

import (
	"context"
	"database/sql"
	"errors"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/eisenwinter/gotrxx/db/tables"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// all token related things in store

type autIDPair struct {
	ApplicationID int       `db:"application_id"`
	UserID        uuid.UUID `db:"user_id"`
}

func (d *DataStore) InsertCommonToken(
	ctx context.Context,
	authorizationID uuid.UUID,
	tokenType string,
	token string,
	expires time.Time,
	properties tables.MapStructure,
) (int, error) {
	exists, err := d.exists(
		ctx,
		"tokens",
		sq.And{sq.Eq{"token_type": tokenType}, sq.Eq{"token": token}},
	)
	if err != nil {
		return 0, err
	}
	if exists {
		return 0, ErrAlreadyExists
	}
	s := sq.Select("application_id", "user_id").
		From("authorizations").
		Where(sq.And{sq.Eq{"id": authorizationID}, sq.Eq{"revoked_at": nil}})
	var pair autIDPair
	err = d.getStatement(ctx, &pair, s, nil)
	if err != nil {
		return 0, err
	}
	m := map[string]interface{}{
		"authorization_id": authorizationID,
		"application_id":   pair.ApplicationID,
		"user_id":          pair.UserID,
		"token_type":       tokenType,
		"token":            token,
		"properties":       properties,
		"expires_at":       expires,
		"created_at":       time.Now().UTC()}
	insert := sq.Insert("tokens").SetMap(m)
	insert = insert.Suffix("RETURNING id")
	var id int
	err = d.returningInsertStatement(ctx, &id, insert, nil)
	if err != nil {
		d.log.Error("could not insert token", zap.Error(err))
		return 0, err
	}
	return id, nil
}

func (d *DataStore) RevokeCommonTokensForAuthorization(
	ctx context.Context,
	authorizationID uuid.UUID,
) (int, error) {
	a := sq.Update("tokens").
		Set("revoked_at", time.Now().UTC()).
		Set("updated_at", time.Now().UTC()).
		Where(sq.And{
			sq.Eq{"revoked_at": nil},
			sq.Eq{"authorization_id": authorizationID}})
	rs, err := d.updateStatement(ctx, a, nil)
	if err != nil {
		return 0, err
	}
	count, err := rs.RowsAffected()
	return int(count), err
}

func (d *DataStore) RevokeCommonToken(ctx context.Context, tokenType string, token string) error {
	a := sq.Update("tokens").
		Set("revoked_at", time.Now().UTC()).
		Set("updated_at", time.Now().UTC()).
		Where(sq.And{
			sq.Eq{"token_type": tokenType},
			sq.Eq{"token": token},
			sq.Eq{"revoked_at": nil}})
	_, err := d.updateStatement(ctx, a, nil)
	if err != nil {
		return err
	}
	return nil
}

func (d *DataStore) CommonTokenDetails(
	ctx context.Context,
	tokenType string,
	token string,
) (*CommonTokenDetails, error) {
	s := sq.Select("tokens.id",
		"tokens.authorization_id",
		"tokens.user_id",
		"tokens.token_type",
		"tokens.token",
		"tokens.properties",
		"tokens.redeemed_at",
		"tokens.revoked_at",
		"tokens.expires_at",
		"applications.client_id").
		From("tokens").
		Join("applications ON tokens.application_id = applications.id").
		Where(sq.And{
			sq.Eq{"tokens.token_type": tokenType},
			sq.Eq{"tokens.token": token},
		}).OrderBy("tokens.created_at DESC").Limit(1)
	var td CommonTokenDetails
	err := d.getStatement(ctx, &td, s, nil)
	if err != nil {
		if errors.Is(sql.ErrNoRows, err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &td, nil
}

func (d *DataStore) RedeemCommonToken(ctx context.Context, tokenType string, token string) error {
	a := sq.Update("tokens").
		Set("redeemed_at", time.Now().UTC()).
		Set("updated_at", time.Now().UTC()).
		Where(sq.And{
			sq.Eq{"token_type": tokenType},
			sq.GtOrEq{"expires_at": time.Now().UTC()},
			sq.Eq{"token": token},
			sq.Eq{"redeemed_at": nil},
			sq.Eq{"revoked_at": nil}})
	rs, err := d.updateStatement(ctx, a, nil)
	if err != nil {
		return err
	}
	c, err := rs.RowsAffected()
	if err != nil {
		return err
	}
	if c == 0 {
		return errors.New("could not redeem token")
	}
	return nil
}
