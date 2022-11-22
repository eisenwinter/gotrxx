package db

import (
	"context"
	"database/sql"
	"errors"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/eisenwinter/gotrxx/db/tables"
	"go.uber.org/zap"
)

func (d *DataStore) InviteUser(
	ctx context.Context,
	expires time.Time,
	email *string,
	code string,
	roles []string,
	applications ...int,
) error {
	tx, err := d.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	var inviteID int32
	inv := sq.Insert("user_invites").
		Columns("email", "code", "expires_at", "created_at").
		Values(email, code, expires, time.Now().UTC()).
		Suffix("RETURNING id")
	err = d.returningInsertStatement(ctx, &inviteID, inv, tx)
	if err != nil {
		d.log.Debug("retunring insert statement failed")
		rerr := tx.Rollback()
		if rerr != nil {
			d.log.Error("couldnt rollback", zap.Error(rerr))
		}
		return err
	}
	if len(roles) > 0 {
		var rolesIds []int
		idQuery := sq.Select("id").From("roles").Where(sq.Eq{"name": roles})
		err = d.selectStatement(ctx, &rolesIds, idQuery, tx)
		if err != nil {
			return err
		}
		for _, v := range rolesIds {
			i := sq.Insert("user_invite_roles").
				Columns("role_id", "user_invite_id").
				Values(v, inviteID)
			_, err := d.insertStatement(ctx, i, tx)
			if err != nil {
				rerr := tx.Rollback()
				if rerr != nil {
					d.log.Error("couldnt rollback", zap.Error(rerr))
				}
				return err
			}
		}
	}

	if len(applications) > 0 {
		for _, v := range applications {
			i := sq.Insert("user_invite_applications").
				Columns("application_id", "user_invite_id").
				Values(v, inviteID)
			_, err := d.insertStatement(ctx, i, tx)
			if err != nil {
				rerr := tx.Rollback()
				if rerr != nil {
					d.log.Error("couldnt rollback", zap.Error(rerr))
				}
				return err
			}
		}
	}
	return tx.Commit()
}

func (d *DataStore) InviteCodeExists(ctx context.Context, code string) (bool, error) {
	return d.exists(ctx, "user_invites", sq.Eq{"code": code})
}

func (d *DataStore) IsInviteable(ctx context.Context, email string) (bool, error) {
	user, err := d.exists(ctx, "users", sq.Eq{"email": email})
	if err != nil {
		return false, err
	}
	if user {
		return false, nil
	}
	invite, err := d.exists(
		ctx,
		"user_invites",
		sq.And{sq.Eq{"email": email}, sq.Gt{"expires_at": time.Now().UTC()}},
	)
	if err != nil {
		return false, err
	}
	return !invite, nil
}

func (d *DataStore) SetInviteSent(ctx context.Context, email string, code string) error {
	q := sq.
		Update("user_invites").
		Set("sent_at", time.Now().UTC()).
		Where("email = ? AND code = ?", email, code)
	_, err := d.updateStatement(ctx, q, nil)
	return err
}

func (d *DataStore) Invites(
	ctx context.Context,
	opts ListOptions,
) ([]*tables.UserInviteTable, int, error) {
	if opts.Page <= 0 {
		opts.Page = 1
	}

	var c int
	count := sq.Select("COUNT(*)").From("user_invites")
	applyWhere, err := d.whereFromAdapater("user_invites", opts.Query)
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
		return []*tables.UserInviteTable{}, c, nil
	}

	var entities []*tables.UserInviteTable
	q := sq.
		Select("id", "email", "code", "sent_at", "consumed_at", "created_at", "expires_at").
		From("user_invites")
	q = applyWhere(q)
	q = d.orderByFromAdapater(q, "user_invites", "id DESC", opts)
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

func (d *DataStore) InviteData(ctx context.Context, inviteCode string) (*UserInviteData, error) {
	c := sq.Select("*").From("user_invites").Where(sq.Eq{"code": inviteCode})
	var entity tables.UserInviteTable
	err := d.getStatement(ctx, &entity, c, nil)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	r := sq.
		Select("name").
		From("roles").
		Join("user_invite_roles ON roles.id = user_invite_roles.role_id").
		Where(sq.Eq{"user_invite_id": entity.ID})

	inviteData := &UserInviteData{}

	a := sq.
		Select("application_id", "scopes").
		From("user_invite_applications").
		Where(sq.Eq{"user_invite_id": entity.ID})

	err = d.selectStatement(ctx, &inviteData.PreApplicationAuthorization, a, nil)
	if err != nil {
		d.log.Error("invalid application fetching in datastore", zap.Error(err))
	}

	var roleSlice []tables.RoleTable
	err = d.selectStatement(ctx, &roleSlice, r, nil)
	if err != nil {
		d.log.Error("invalid role fetching in datastore", zap.Error(err))
	} else {
		inviteData.Roles = make([]string, len(roleSlice))
		for i, v := range roleSlice {
			inviteData.Roles[i] = v.Name
		}
	}
	inviteData.Expires = entity.ExpiresAt
	if entity.ConsumedAt != nil {
		//already consumed tokens are expired by consuming date
		inviteData.Expires = *entity.ConsumedAt
	}
	return inviteData, nil
}

func (d *DataStore) ConsumeInvite(ctx context.Context, inviteCode string) error {
	q := sq.
		Update("user_invites").
		Set("consumed_at", time.Now().UTC()).
		Where("code = ?", inviteCode)
	_, err := d.updateStatement(ctx, q, nil)
	return err
}
