package tables

// UserInviteRolesTable represents the table
type UserInviteRolesTable struct {
	RoleID       int `db:"role_id"`
	UserInviteID int `db:"user_invite_id"`
}
