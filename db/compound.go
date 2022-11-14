package db

import (
	"time"

	"github.com/eisenwinter/gotrxx/db/tables"
	"github.com/google/uuid"
)

type userAuthorization struct {
	ID              uuid.UUID           `db:"id"`
	ClientID        string              `db:"client_id"`
	RevokedAt       *time.Time          `db:"revoked_at"`
	Properties      tables.MapStructure `db:"properties"`
	ApplicationType string              `db:"type"`
}

type UserAuthorization struct {
	ID              uuid.UUID           `db:"id"`
	ClientID        string              `db:"client_id"`
	RevokedAt       *time.Time          `db:"revoked_at"`
	Properties      tables.MapStructure `db:"properties"`
	ApplicationType string              `db:"type"`
}

type UserData struct {
	ID                  uuid.UUID
	Email               string
	EmailConfirmed      *time.Time
	Phone               *string
	PhoneConfirmed      *time.Time
	TwoFactor           bool
	TwoFactorSecret     string
	OtpPending          bool
	BannedOn            *time.Time
	LockoutTill         *time.Time
	PasswordHash        []byte
	CurrentFailureCount int
	LastSignIn          *time.Time
	Roles               []string
	Authorizations      []*UserAuthorization
}

type CommonTokenDetails struct {
	ID              int                 `db:"id"`
	AuthorizationId uuid.UUID           `db:"authorization_id"`
	UserID          uuid.UUID           `db:"user_id"`
	TokenType       string              `db:"token_type"`
	Token           string              `db:"token"`
	Properties      tables.MapStructure `db:"properties"`
	RedeemedAt      *time.Time          `db:"redeemed_at"`
	RevokedAt       *time.Time          `db:"revoked_at"`
	ExpiresAt       time.Time           `db:"expires_at"`
	ClientID        string              `db:"client_id"`
	IssuedAt        time.Time           `db:"created_at"`
}

func (c *CommonTokenDetails) CodeChallenge() string {
	if val, ok := c.Properties["code_challenge"]; ok {
		return val.(string)
	}
	return ""
}

func (c *CommonTokenDetails) CodeChallengeMethod() string {
	if val, ok := c.Properties["code_challenge_method"]; ok {
		return val.(string)
	}
	return ""
}

type ApplicationInvite struct {
	ApplicationID int    `db:"application_id"`
	Scopes        string `db:"scopes"`
}

type UserInviteData struct {
	Roles                       []string
	Expires                     time.Time
	PreApplicationAuthorization []ApplicationInvite
}

type ListOptions struct {
	PageSize int
	Page     int
	Sort     string
	Query    string
}
