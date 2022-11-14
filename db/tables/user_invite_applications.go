package tables

// UserInviteApplicationsTable represents the table
type UserInviteApplicationsTable struct {
	ApplicationID int    `db:"application_id"`
	UserInviteID  int    `db:"user_invite_id"`
	Scopes        string `db:"scopes"`
}
