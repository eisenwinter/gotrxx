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

func (d *DataStore) Users(ctx context.Context, opts ListOptions) ([]*tables.UserTable, int, error) {
	if opts.Page <= 0 {
		opts.Page = 1
	}

	var c int
	count := sq.Select("COUNT(*)").From("users")
	applyWhere, err := d.whereFromAdapater("users", opts.Query)
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
		return []*tables.UserTable{}, c, nil
	}

	var entities []*tables.UserTable
	q := sq.
		Select(
			"id",
			"email",
			"email_confirmed",
			"phone",
			"phone_confirmed",
			"mfa",
			"pending_otp",
			"lockout_till",
			"banned_on",
			"current_failure_count",
			"recovery_token_created",
			"confirm_token",
			"confirm_token_created",
			"created_at",
			"updated_at",
		).
		From("users")
	q = applyWhere(q)
	q = d.orderByFromAdapater(q, "users", "id DESC", opts)
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

func (d *DataStore) User(ctx context.Context, userID uuid.UUID) (*tables.UserTable, error) {
	var userEntity tables.UserTable
	userQuery := sq.Select("*").From("users").Where(sq.Eq{"id": userID})
	err := d.getStatement(ctx, &userEntity, userQuery, nil)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		d.log.Error("unable to query database", "err", err)
		return nil, err
	}
	return &userEntity, nil
}

func (d *DataStore) UserByEmail(ctx context.Context, email string) (*UserData, error) {
	userQuery := sq.Select("id").From("users").Where(sq.Eq{"email": email})
	var id uuid.UUID
	err := userQuery.RunWith(d.db).QueryRow().Scan(&id)
	if err != nil {
		if errors.Is(sql.ErrNoRows, err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return d.UserByID(ctx, id)
}

func (d *DataStore) UserByID(ctx context.Context, id uuid.UUID) (*UserData, error) {

	var userEntity tables.UserTable
	userQuery := sq.Select("*").From("users").Where(sq.Eq{"id": id})
	err := d.getStatement(ctx, &userEntity, userQuery, nil)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		d.log.Error("unable to query database", "err", err)
		return nil, err
	}
	provider := &UserData{}
	provider.Email = userEntity.Email
	provider.EmailConfirmed = userEntity.EmailConfirmed
	provider.ID = userEntity.ID
	provider.LockoutTill = userEntity.LockoutTill
	provider.BannedOn = userEntity.BannedOn
	provider.Phone = userEntity.Phone
	provider.PhoneConfirmed = userEntity.PhoneConfirmed
	provider.PasswordHash = []byte(userEntity.Password)
	provider.CurrentFailureCount = userEntity.CurrentFailureCount
	provider.TwoFactor = userEntity.Mfa
	if userEntity.MfaSecret != nil {
		provider.TwoFactorSecret = *userEntity.MfaSecret
	}
	provider.OtpPending = userEntity.PendingOTP
	var authorizations []*userAuthorization
	auts := sq.
		Select(
			"authorizations.id, applications.client_id",
			"authorizations.revoked_at",
			"authorizations.properties",
			"applications.type",
		).
		From("authorizations").
		Join("applications ON authorizations.application_id = applications.id").
		Where("authorizations.user_id = ?", id)
	err = d.selectStatement(ctx, &authorizations, auts, nil)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if len(authorizations) > 0 {
		provider.Authorizations = make([]*UserAuthorization, len(authorizations))
		for i, v := range authorizations {
			provider.Authorizations[i] = &UserAuthorization{
				ID:              v.ID,
				ApplicationType: v.ApplicationType,
				RevokedAt:       v.RevokedAt,
				ClientID:        v.ClientID,
				Properties:      v.Properties,
			}
		}
	}

	var roleSlice []tables.RoleTable
	rolesQuery := sq.
		Select("roles.name").
		From("roles").
		Join("user_roles ON roles.id = user_roles.role_id").
		Where(sq.Eq{"user_id": userEntity.ID})

	err = d.selectStatement(ctx, &roleSlice, rolesQuery, nil)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return provider, err
	}
	if len(roleSlice) > 0 {
		provider.Roles = make([]string, len(roleSlice))
		for i, v := range roleSlice {
			provider.Roles[i] = v.Name
		}
	}
	return provider, nil
}

func (d *DataStore) IsUserInRole(ctx context.Context, id uuid.UUID, role string) (bool, error) {
	sel := sq.Select("id").
		From("roles").
		InnerJoin("user_roles ON roles.id = user_roles.role_id").
		Where(sq.Eq{"name": role, "user_roles.user_id": id})
	var roleID int32
	err := d.getStatement(ctx, &roleID, sel, nil)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	if err == sql.ErrNoRows {
		return false, nil
	}
	return true, nil
}

func (d *DataStore) UserRoles(ctx context.Context, id uuid.UUID) ([]*tables.RoleTable, error) {

	var roles []*tables.RoleTable
	sel := sq.Select("roles.id", "roles.name").
		From("roles").
		InnerJoin("user_roles ON roles.id = user_roles.role_id").
		Where(sq.Eq{"user_roles.user_id": id})
	err := d.selectStatement(ctx, &roles, sel, nil)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []*tables.RoleTable{}, nil
		}
		return nil, err
	}
	return roles, nil
}

func (d *DataStore) AddUserToRole(ctx context.Context, id uuid.UUID, role string) error {
	sel := sq.Select("id").From("roles").Where(sq.Eq{"name": role})
	var roleID int32
	err := d.getStatement(ctx, &roleID, sel, nil)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if err == sql.ErrNoRows {
		ins := sq.
			Insert("roles").
			Columns("name", "created_at").
			Values(role, time.Now().UTC()).
			Suffix("RETURNING id")
		err := d.returningInsertStatement(ctx, &roleID, ins, nil)
		if err != nil {
			return err
		}
	}
	ins := sq.Insert("user_roles").
		Columns("role_id", "user_id").
		Values(roleID, id)
	_, err = d.insertStatement(ctx, ins, nil)
	return err
}

func (d *DataStore) RemoveUserFromRole(ctx context.Context, id uuid.UUID, role string) error {
	sel := sq.Select("id").From("roles").Where(sq.Eq{"name": role})
	var roleID int32
	err := d.getStatement(ctx, &roleID, sel, nil)
	if err != nil {
		return err
	}
	del := sq.Delete("user_roles").Where(sq.And{sq.Eq{"user_id": id}, sq.Eq{"role_id": roleID}})
	_, err = d.deleteStatement(ctx, del, nil)
	return err
}

func (d *DataStore) ConfirmTokenExists(ctx context.Context, token string) (bool, error) {
	return d.exists(ctx, "users", sq.Eq{"confirm_token": token})
}

func (d *DataStore) IsRegistred(ctx context.Context, email string) (bool, error) {
	user, err := d.exists(ctx, "users", sq.Eq{"email": email})
	if err != nil {
		return false, err
	}
	return user, nil
}

func (d *DataStore) LockUser(ctx context.Context, id uuid.UUID, lockTime time.Time) (bool, error) {
	ts := time.Now().UTC()
	q := sq.
		Update("users").
		Set("updated_at", ts).
		Set("lockout_till", lockTime).
		Where("id = ? AND lockout_till IS NULL", id)

	rs, err := d.updateStatement(ctx, q, nil)
	if err != nil {
		return false, err
	}
	affected, err := rs.RowsAffected()
	return affected > 0, err
}

func (d *DataStore) EnableMFA(
	ctx context.Context,
	id uuid.UUID,
	userSecret string,
	userRecoveryKey string,
) (bool, error) {
	ts := time.Now().UTC()
	q := sq.
		Update("users").
		Set("mfa", true).
		Set("updated_at", ts).
		Set("mfa_secret", userSecret).
		Set("mfa_recovery_key", userRecoveryKey).
		Where("id = ? AND mfa = ?", id, false)

	rs, err := d.updateStatement(ctx, q, nil)
	if err != nil {
		return false, err
	}
	affected, err := rs.RowsAffected()
	return affected > 0, err
}

func (d *DataStore) DisableMFA(ctx context.Context, id uuid.UUID) (bool, error) {
	ts := time.Now().UTC()
	q := sq.
		Update("users").
		Set("mfa", false).
		Set("updated_at", ts).
		Set("mfa_secret", nil).
		Set("mfa_recovery_key", nil).
		Where("id = ? AND mfa = ?", id, true)

	rs, err := d.updateStatement(ctx, q, nil)
	if err != nil {
		return false, err
	}
	affected, err := rs.RowsAffected()
	return affected > 0, err
}

func (d *DataStore) SetFailureCount(ctx context.Context, id uuid.UUID, count int) error {
	ts := time.Now().UTC()
	q := sq.
		Update("users").
		Set("updated_at", ts).
		Set("current_failure_count", count).
		Where("id = ?", id)
	_, err := d.updateStatement(ctx, q, nil)
	return err
}

func (d *DataStore) SetOTPPending(ctx context.Context, id uuid.UUID, pending bool) error {
	ts := time.Now().UTC()
	q := sq.
		Update("users").
		Set("updated_at", ts).
		Set("pending_otp", pending).
		Where("id = ?", id)
	_, err := d.updateStatement(ctx, q, nil)
	return err
}

func (d *DataStore) BanUser(ctx context.Context, id uuid.UUID) error {
	ts := time.Now().UTC()
	q := sq.
		Update("users").
		Set("updated_at", ts).
		Set("banned_on", time.Now().UTC()).
		Where("id = ? AND banned_on IS NULL", id)
	_, err := d.updateStatement(ctx, q, nil)
	return err
}

func (d *DataStore) UnbanUser(ctx context.Context, id uuid.UUID) error {
	ts := time.Now().UTC()
	q := sq.
		Update("users").
		Set("updated_at", ts).
		Set("banned_on", nil).
		Where("id = ? AND banned_on IS NOT NULL", id)
	_, err := d.updateStatement(ctx, q, nil)
	return err
}

func (d *DataStore) UnlockUser(ctx context.Context, id uuid.UUID) (bool, error) {
	ts := time.Now().UTC()
	q := sq.
		Update("users").
		Set("updated_at", ts).
		Set("lockout_till", nil).
		Set("current_failure_count", 0).
		Where("id = ? AND lockout_till IS NOT NULL", id)
	rs, err := d.updateStatement(ctx, q, nil)
	if err != nil {
		return false, err
	}
	affected, err := rs.RowsAffected()
	return affected > 0, err
}

func (d *DataStore) IDFromEmail(ctx context.Context, email string) (bool, uuid.UUID, error) {
	q := sq.Select("id").From("users").Where(sq.Eq{"email": email})
	var id uuid.UUID
	err := d.getStatement(ctx, &id, q, nil)
	if err != nil && err != sql.ErrNoRows {
		return false, uuid.UUID{}, err
	} else if err == sql.ErrNoRows {
		return false, uuid.UUID{}, nil
	}
	return true, id, nil
}

func (d *DataStore) SetPassword(
	ctx context.Context,
	id uuid.UUID,
	passwordHash string,
) (bool, error) {
	q := sq.
		Update("users").
		Set("password", passwordHash).
		Set("updated_at", time.Now().UTC()).
		Where("id = ?", id)
	rs, err := d.updateStatement(ctx, q, nil)
	if err != nil {
		return false, err
	}
	affected, err := rs.RowsAffected()
	return affected > 0, err
}

func (d *DataStore) SetRecoveryToken(
	ctx context.Context,
	id uuid.UUID,
	recoveryToken string,
) (bool, error) {
	q := sq.
		Update("users").
		Set("recovery_token", recoveryToken).
		Set("recovery_token_created", time.Now().UTC()).
		Set("updated_at", time.Now().UTC()).
		Where("id = ?", id)
	rs, err := d.updateStatement(ctx, q, nil)
	if err != nil {
		return false, err
	}
	affected, err := rs.RowsAffected()
	return affected > 0, err
}

func (d *DataStore) ConsumeRecoveryToken(
	ctx context.Context,
	id uuid.UUID,
	recoveryToken string,
) (bool, error) {
	q := sq.
		Update("users").
		Set("lockout_till", nil).
		Set("recovery_token", nil).
		Set("recovery_token_created", nil).
		Set("updated_at", time.Now().UTC()).
		Where("id = ? AND recovery_token = ?", id, recoveryToken)
	rs, err := d.updateStatement(ctx, q, nil)
	if err != nil {
		return false, err
	}
	affected, err := rs.RowsAffected()
	return affected > 0, err
}

func (d *DataStore) SetEmail(ctx context.Context, id uuid.UUID, email string) (bool, error) {
	q := sq.
		Update("users").
		Set("email", email).
		Set("updated_at", time.Now().UTC()).
		Where("id = ?", id)
	rs, err := d.updateStatement(ctx, q, nil)
	if err != nil {
		return false, err
	}
	affected, err := rs.RowsAffected()
	return affected > 0, err
}

func (d *DataStore) InsertUser(
	ctx context.Context,
	email string,
	passwordHash string,
	phone *string,
	confirmToken *string,
) (uuid.UUID, error) {
	timestamp := time.Now().UTC()
	m := map[string]interface{}{
		"email":      email,
		"password":   passwordHash,
		"phone":      phone,
		"created_at": timestamp,
	}
	m["id"] = uuid.New()
	if confirmToken != nil {
		m["confirm_token"] = confirmToken
		m["confirm_token_created"] = timestamp
	} else {
		//no token = autoconfirm
		m["email_confirmed"] = timestamp
	}
	insert := sq.Insert("users").SetMap(m)
	insert = insert.Suffix("RETURNING id")
	var id uuid.UUID
	err := d.returningInsertStatement(ctx, &id, insert, nil)
	if err != nil {
		d.log.Error("could not insert user", "err", err)
		return uuid.UUID{}, err
	}
	return id, nil
}

func (d *DataStore) ConfirmUser(ctx context.Context, confirmToken string) (bool, uuid.UUID, error) {
	if confirmToken == "" {
		return false, uuid.UUID{}, errors.New("empty confirm token")
	}
	var user tables.UserTable
	c := sq.Select("*").From("users").Where(sq.Eq{"confirm_token": confirmToken})
	err := d.getStatement(ctx, &user, c, nil)
	if err != nil && err != sql.ErrNoRows {
		return false, uuid.UUID{}, err
	}
	if err == sql.ErrNoRows {
		return false, uuid.UUID{}, nil
	}

	timestamp := time.Now().UTC()
	i := sq.Update("users").
		Set("email_confirmed", timestamp).
		Set("confirm_token", nil).
		Set("confirm_token_created", nil).
		Set("updated_at", time.Now().UTC())
	res, err := d.updateStatement(ctx, i, nil)
	if err != nil {
		return false, uuid.UUID{}, err
	}
	aff, err := res.RowsAffected()
	if err != nil {
		return false, uuid.UUID{}, err
	}
	if aff == 0 {
		return false, uuid.UUID{}, nil
	}
	return true, user.ID, nil
}

func (d *DataStore) ManualConfirmUser(ctx context.Context, id uuid.UUID) error {
	var user tables.UserTable
	c := sq.Select("*").From("users").Where(sq.Eq{"id": id})
	err := d.getStatement(ctx, &user, c, nil)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if err == sql.ErrNoRows {
		return ErrNotFound
	}

	timestamp := time.Now().UTC()
	i := sq.Update("users").
		Set("email_confirmed", timestamp).
		Set("confirm_token", nil).
		Set("confirm_token_created", nil).
		Set("updated_at", time.Now().UTC())
	_, err = d.updateStatement(ctx, i, nil)
	return err
}
