//go:build integration
// +build integration

package db

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	"github.com/eisenwinter/gotrxx/config"
	"github.com/eisenwinter/gotrxx/db/tables"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/stdlib"
	_ "github.com/mattn/go-sqlite3"
)

type DatabaseIntegrationTestSuite struct {
	suite.Suite
	dataStore *DataStore
	dbType    string
	dsn       string
}

func (s *DatabaseIntegrationTestSuite) SetupTest() {
	//reset to clean state
	switch s.dbType {
	case "sqlite":
		//just reopen for :memory:
		dataStore, err := NewSqliteStore(zap.NewNop(), &config.DatabaseConfiguration{
			Type: s.dbType,
			DSN:  s.dsn,
		})
		if err != nil {
			log.Fatal("error creating database store")
		}
		s.dataStore = dataStore
		break
	case "pg":
		s.dataStore.db.MustExec("DROP SCHEMA IF EXISTS gotrxx CASCADE;")
		break
	case "mysql":
		s.dataStore.db.MustExec("DROP DATABASE IF EXISTS gotrxx;")
		s.dataStore.db.MustExec("CREATE DATABASE gotrxx;")
		s.dataStore.db.MustExec("USE gotrxx;")
		break
	}

	err := s.dataStore.EnsureUsable()
	assert.NoError(s.T(), err)
}

// Applications part

func (s *DatabaseIntegrationTestSuite) TestSeededApplications() {
	tables, total, err := s.dataStore.Applications(context.Background(), ListOptions{Page: 1, PageSize: 2})
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), 2, total)
	assert.Equal(s.T(), 2, total)
	if assert.NotNil(s.T(), tables) {
		for i := range tables {
			if tables[i].ClientID == "$.gotrxx" {
				assert.Equal(s.T(), "$.gotrxx", tables[i].ClientID)
				assert.Equal(s.T(), "Gotrxx itself", tables[i].Name)
				assert.Equal(s.T(), 1, tables[i].ApplicationType)
				assert.Equal(s.T(), "private", tables[i].Confidentiality)

			} else if tables[i].ClientID == "netlify-gotrue" {
				assert.Equal(s.T(), "netlify-gotrue", tables[i].ClientID)
				assert.Equal(s.T(), "Gotrue Wrapper", tables[i].Name)
				assert.Equal(s.T(), 1, tables[i].ApplicationType)
				assert.Equal(s.T(), "public", tables[i].Confidentiality)
			} else {
				assert.FailNow(s.T(), "unknown application seeded")
			}
		}

	}
}

func (s *DatabaseIntegrationTestSuite) TestSeededApplicationsQuery() {
	tables, total, err := s.dataStore.Applications(context.Background(), ListOptions{Page: 1, PageSize: 2, Query: "client_id==netlify-gotrue"})
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), 1, total)
	assert.Equal(s.T(), 1, total)
	if assert.NotNil(s.T(), tables) {
		for i := range tables {
			if tables[i].ClientID == "netlify-gotrue" {
				assert.Equal(s.T(), "netlify-gotrue", tables[i].ClientID)
				assert.Equal(s.T(), "Gotrue Wrapper", tables[i].Name)
				assert.Equal(s.T(), 1, tables[i].ApplicationType)
				assert.Equal(s.T(), "public", tables[i].Confidentiality)
			} else {
				assert.FailNow(s.T(), "unknown application seeded")
			}
		}

	}
}

func (s *DatabaseIntegrationTestSuite) TestSeededApplicationByClientID() {
	table, err := s.dataStore.ApplicationByClientID(context.Background(), "$.gotrxx")
	assert.NoError(s.T(), err)
	if assert.NotNil(s.T(), table) {
		assert.Equal(s.T(), "$.gotrxx", table.ClientID)
		assert.Equal(s.T(), "Gotrxx itself", table.Name)
		assert.Equal(s.T(), 1, table.ApplicationType)
		assert.Equal(s.T(), "private", table.Confidentiality)
		assert.NotNil(s.T(), table.Properties)
		assert.Contains(s.T(), table.Properties, "allowed_flows")
		assert.Contains(s.T(), table.Properties, "scopes")
		assert.Contains(s.T(), table.Properties, "redirect_uris")
	}
}

func (s *DatabaseIntegrationTestSuite) TestApplicationByClientIDNotFound() {
	_, err := s.dataStore.ApplicationByClientID(context.Background(), "non-existent")
	assert.ErrorIs(s.T(), ErrNotFound, err)
}

func (s *DatabaseIntegrationTestSuite) TestApplicationCreateRetireDelete() {
	//create application
	props := make(map[string]interface{})
	props["allowed_flows"] = []string{"refresh_token"}
	props["pkce"] = true
	props["scopes"] = []string{"profile"}
	props["logout_uris"] = []string{"https://gotrxx.local/lg"}
	props["redirect_uris"] = []string{"https://gotrxx.local/rdr"}
	secret := "secret"
	id, err := s.dataStore.CreateApplication(context.Background(), 1, "testeroni", &secret, "Testeroni", "public", props)
	assert.NoError(s.T(), err)
	assert.NotEqual(s.T(), 0, id)

	app, err := s.dataStore.ApplicationByID(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "testeroni", app.ClientID)
	assert.Equal(s.T(), "Testeroni", app.Name)
	assert.Equal(s.T(), 1, app.ApplicationType)
	assert.Equal(s.T(), "public", app.Confidentiality)
	assert.NotNil(s.T(), app.Properties)

	assert.Contains(s.T(), app.Properties, "allowed_flows")
	assert.Contains(s.T(), app.Properties, "scopes")
	assert.Contains(s.T(), app.Properties, "redirect_uris")
	assert.Contains(s.T(), app.Properties, "pkce")
	assert.Contains(s.T(), app.Properties, "logout_uris")

	assert.Contains(s.T(), app.Properties["allowed_flows"], "refresh_token")
	assert.Contains(s.T(), app.Properties["scopes"], "profile")
	assert.Contains(s.T(), app.Properties["logout_uris"], "https://gotrxx.local/lg")
	assert.Contains(s.T(), app.Properties["redirect_uris"], "https://gotrxx.local/rdr")

	assert.True(s.T(), app.Properties["pkce"].(bool))

	if assert.NotNil(s.T(), app.ClientSecret) {
		assert.Equal(s.T(), secret, *app.ClientSecret)
	}

	//retire application
	_, _, err = s.dataStore.RetireApplication(context.Background(), id)
	assert.NoError(s.T(), err)

	//reftech application
	app, err = s.dataStore.ApplicationByID(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), app.RetiredOn)

	//delete retirec
	del, err := s.dataStore.DeleteAllRetiredApplications(context.Background())
	assert.NoError(s.T(), err)
	assert.Contains(s.T(), del, "testeroni")

	_, err = s.dataStore.ApplicationByClientID(context.Background(), "testeroni")
	assert.ErrorIs(s.T(), ErrNotFound, err)

}

// Authorization part

func (s *DatabaseIntegrationTestSuite) TestAuthAuthorizationByIDNegative() {
	table, err := s.dataStore.AuthorizationByID(context.Background(), uuid.Nil)
	assert.Error(s.T(), err)
	assert.ErrorIs(s.T(), ErrNotFound, err)
	assert.Nil(s.T(), table)
}

func (s *DatabaseIntegrationTestSuite) TestAuthAuthorizationByIDPositive() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	confirmToken := "token"
	id, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, &confirmToken)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), id)

	aid, err := s.dataStore.GrantAuthorization(context.Background(), 1, id, make(tables.MapStructure))
	assert.NoError(s.T(), err)
	assert.NotEqual(s.T(), aid, uuid.Nil)

	table, err := s.dataStore.AuthorizationByID(context.Background(), aid)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), table)
	assert.Equal(s.T(), 1, table.ApplicationID)
	assert.NotEqual(s.T(), time.Time{}, table.CreatedAt)
}

func (s *DatabaseIntegrationTestSuite) TestAuthActiveAuthorizationByUserAndClientID() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	confirmToken := "token"
	id, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, &confirmToken)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), id)

	aid, err := s.dataStore.GrantAuthorization(context.Background(), 1, id, make(tables.MapStructure))
	assert.NoError(s.T(), err)
	assert.NotEqual(s.T(), aid, uuid.Nil)

	table, err := s.dataStore.ActiveAuthorizationByUserAndClientID(context.Background(), "$.gotrxx", id)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), id, table.UserID)

}

func (s *DatabaseIntegrationTestSuite) TestAuthRevokeAuthorization() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	confirmToken := "token"
	id, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, &confirmToken)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), id)

	aid, err := s.dataStore.GrantAuthorization(context.Background(), 1, id, make(tables.MapStructure))
	assert.NoError(s.T(), err)
	assert.NotEqual(s.T(), aid, uuid.Nil)

	table, err := s.dataStore.AuthorizationByID(context.Background(), aid)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), table)
	assert.Equal(s.T(), 1, table.ApplicationID)
	assert.NotEqual(s.T(), time.Time{}, table.CreatedAt)
	assert.Nil(s.T(), table.RevokedAt)

	_, err = s.dataStore.RevokeAuthorization(context.Background(), aid)
	assert.NoError(s.T(), err)

	table, err = s.dataStore.AuthorizationByID(context.Background(), aid)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), table)
	assert.NotNil(s.T(), table.RevokedAt)
}

// Invite part

func (s *DatabaseIntegrationTestSuite) TestInviteUser() {
	email := "blub@gotrxx.local"
	expires := time.Now().Add(time.Minute * 5)
	code := "code"
	roles := []string{}
	apps := []int{1}
	err := s.dataStore.InviteUser(
		context.Background(),
		expires,
		&email,
		code,
		roles,
		apps...)
	assert.NoError(s.T(), err)
}

func (s *DatabaseIntegrationTestSuite) TestInviteIsInviteable() {
	email := "blub@gotrxx.local"
	expires := time.Now().Add(time.Minute * 5)
	code := "code"
	roles := []string{}
	apps := []int{1}
	err := s.dataStore.InviteUser(
		context.Background(),
		expires,
		&email,
		code,
		roles,
		apps...)
	assert.NoError(s.T(), err)

	y, err := s.dataStore.IsInviteable(context.Background(), email)
	assert.NoError(s.T(), err)
	assert.False(s.T(), y)
}

func (s *DatabaseIntegrationTestSuite) TestInviteIsInviteableExpired() {
	email := "blub@gotrxx.local"
	expires := time.Now().Add(time.Hour * -12)
	code := "code"
	roles := []string{}
	apps := []int{1}
	err := s.dataStore.InviteUser(
		context.Background(),
		expires,
		&email,
		code,
		roles,
		apps...)
	assert.NoError(s.T(), err)

	y, err := s.dataStore.IsInviteable(context.Background(), email)
	assert.NoError(s.T(), err)
	assert.True(s.T(), y)
}

func (s *DatabaseIntegrationTestSuite) TestInviteIsInviteableNotInvited() {
	email := "blub@gotrxx.local"
	y, err := s.dataStore.IsInviteable(context.Background(), email)
	assert.NoError(s.T(), err)
	assert.True(s.T(), y)
}

func (s *DatabaseIntegrationTestSuite) TestInviteIsInviteableUserExists() {
	email := "blub@gotrxx.local"
	_, err := s.dataStore.InsertUser(context.Background(), email, "wolo", nil, nil)
	assert.NoError(s.T(), err)
	y, err := s.dataStore.IsInviteable(context.Background(), email)
	assert.NoError(s.T(), err)
	assert.False(s.T(), y)
}

func (s *DatabaseIntegrationTestSuite) TestInvitInviteCodeExists() {
	email := "blub@gotrxx.local"
	expires := time.Now().Add(time.Minute * 5)
	code := "code"
	roles := []string{}
	apps := []int{1}
	err := s.dataStore.InviteUser(
		context.Background(),
		expires,
		&email,
		code,
		roles,
		apps...)
	assert.NoError(s.T(), err)

	y, err := s.dataStore.InviteCodeExists(context.Background(), code)
	assert.NoError(s.T(), err)
	assert.True(s.T(), y)
}

func (s *DatabaseIntegrationTestSuite) TestInviteSetInviteSent() {
	email := "blub@gotrxx.local"
	expires := time.Now().Add(time.Minute * 5)
	code := "code"
	roles := []string{}
	apps := []int{1}
	err := s.dataStore.InviteUser(
		context.Background(),
		expires,
		&email,
		code,
		roles,
		apps...)
	assert.NoError(s.T(), err)
	err = s.dataStore.SetInviteSent(context.Background(), email, code)
	assert.NoError(s.T(), err)
}

func (s *DatabaseIntegrationTestSuite) TestInviteInviteDataNotFound() {
	data, err := s.dataStore.InviteData(context.Background(), "code")
	assert.Error(s.T(), err)
	assert.Nil(s.T(), data)
}

func (s *DatabaseIntegrationTestSuite) TestInviteInviteData() {
	email := "blub@gotrxx.local"
	expires := time.Now().Add(time.Minute * 5)
	code := "code"
	roles := []string{"inviter"}
	apps := []int{1}
	err := s.dataStore.InviteUser(
		context.Background(),
		expires,
		&email,
		code,
		roles,
		apps...)
	assert.NoError(s.T(), err)
	data, err := s.dataStore.InviteData(context.Background(), code)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), data)

	assert.Equal(s.T(), expires.Local(), data.Expires.Local())
	assert.Equal(s.T(), data.PreApplicationAuthorization[0].ApplicationID, apps[0])
	assert.Contains(s.T(), data.Roles, roles[0])
}

func (s *DatabaseIntegrationTestSuite) TestConsumeInvite() {
	email := "blub@gotrxx.local"
	expires := time.Now().Add(time.Minute * 5)
	code := "code"
	roles := []string{}
	apps := []int{1}
	err := s.dataStore.InviteUser(
		context.Background(),
		expires,
		&email,
		code,
		roles,
		apps...)
	assert.NoError(s.T(), err)
	err = s.dataStore.ConsumeInvite(context.Background(), code)
	assert.NoError(s.T(), err)
}

// Tokens part

func (s *DatabaseIntegrationTestSuite) TestAuthActiveAuthorizationByCommonToken() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	confirmToken := "token"
	id, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, &confirmToken)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), id)

	aid, err := s.dataStore.GrantAuthorization(context.Background(), 1, id, make(tables.MapStructure))
	assert.NoError(s.T(), err)
	assert.NotEqual(s.T(), aid, uuid.Nil)

	tokenType := "dream.token"
	token := "i.am.something.else"
	expires := time.Now().Add(time.Hour * 5)
	tid, err := s.dataStore.InsertCommonToken(context.Background(), aid, tokenType, token, expires, make(tables.MapStructure))
	assert.NoError(s.T(), err)
	assert.NotEqual(s.T(), 0, tid)

	table, err := s.dataStore.ActiveAuthorizationByCommonToken(context.Background(), tokenType, token)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), table)
	assert.Equal(s.T(), 1, table.ApplicationID)
	assert.Equal(s.T(), id, table.UserID)
	assert.Equal(s.T(), aid, table.ID)
}

func (s *DatabaseIntegrationTestSuite) TestTokenInsertCommonTokenPositive() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	confirmToken := "token"
	id, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, &confirmToken)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), id)

	aid, err := s.dataStore.GrantAuthorization(context.Background(), 1, id, make(tables.MapStructure))
	assert.NoError(s.T(), err)
	assert.NotEqual(s.T(), aid, uuid.Nil)

	tokenType := "dream.token"
	token := "i.am.something.else"
	expires := time.Now().Add(time.Hour * 5)
	tid, err := s.dataStore.InsertCommonToken(context.Background(), aid, tokenType, token, expires, make(tables.MapStructure))
	assert.NoError(s.T(), err)
	assert.NotEqual(s.T(), 0, tid)
}

func (s *DatabaseIntegrationTestSuite) TestTokenInsertCommonTokenNegativeDuplicate() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	confirmToken := "token"
	id, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, &confirmToken)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), id)

	aid, err := s.dataStore.GrantAuthorization(context.Background(), 1, id, make(tables.MapStructure))
	assert.NoError(s.T(), err)
	assert.NotEqual(s.T(), aid, uuid.Nil)

	tokenType := "dream.token"
	token := "i.am.something.else"
	expires := time.Now().Add(time.Hour * 5)
	tid, err := s.dataStore.InsertCommonToken(context.Background(), aid, tokenType, token, expires, make(tables.MapStructure))
	assert.NoError(s.T(), err)
	assert.NotEqual(s.T(), 0, tid)

	tid, err = s.dataStore.InsertCommonToken(context.Background(), aid, tokenType, token, expires, make(tables.MapStructure))
	assert.Error(s.T(), err)
	assert.ErrorIs(s.T(), ErrAlreadyExists, err)
	assert.Equal(s.T(), 0, tid)
}

func (s *DatabaseIntegrationTestSuite) TestTokenRevokeCommonTokensForAuthorization() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	confirmToken := "token"
	id, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, &confirmToken)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), id)

	aid, err := s.dataStore.GrantAuthorization(context.Background(), 1, id, make(tables.MapStructure))
	assert.NoError(s.T(), err)
	assert.NotEqual(s.T(), aid, uuid.Nil)

	tokenType := "dream.token"
	token := "i.am.something.else"
	expires := time.Now().Add(time.Hour * 5)
	tid, err := s.dataStore.InsertCommonToken(context.Background(), aid, tokenType, token, expires, make(tables.MapStructure))
	assert.NoError(s.T(), err)
	assert.NotEqual(s.T(), 0, tid)

	tcount, err := s.dataStore.RevokeCommonTokensForAuthorization(context.Background(), aid)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), 1, tcount)

	details, err := s.dataStore.CommonTokenDetails(context.Background(), tokenType, token)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), details)
	assert.Equal(s.T(), id, details.UserID)
	assert.Equal(s.T(), aid, details.AuthorizationId)
	assert.Equal(s.T(), "$.gotrxx", details.ClientID)
	assert.Equal(s.T(), details.ExpiresAt.Local(), details.ExpiresAt.Local())
	assert.Equal(s.T(), tid, details.ID)
	assert.Equal(s.T(), token, details.Token)
	assert.Equal(s.T(), tokenType, details.TokenType)
	assert.NotNil(s.T(), details.RevokedAt)
}

func (s *DatabaseIntegrationTestSuite) TestTokenRevokeCommonToken() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	confirmToken := "token"
	id, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, &confirmToken)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), id)

	aid, err := s.dataStore.GrantAuthorization(context.Background(), 1, id, make(tables.MapStructure))
	assert.NoError(s.T(), err)
	assert.NotEqual(s.T(), aid, uuid.Nil)

	tokenType := "dream.token"
	token := "i.am.something.else"
	expires := time.Now().Add(time.Hour * 5)
	tid, err := s.dataStore.InsertCommonToken(context.Background(), aid, tokenType, token, expires, make(tables.MapStructure))
	assert.NoError(s.T(), err)
	assert.NotEqual(s.T(), 0, tid)

	err = s.dataStore.RevokeCommonToken(context.Background(), tokenType, token)
	assert.NoError(s.T(), err)

	details, err := s.dataStore.CommonTokenDetails(context.Background(), tokenType, token)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), details)
	assert.Equal(s.T(), id, details.UserID)
	assert.Equal(s.T(), aid, details.AuthorizationId)
	assert.Equal(s.T(), "$.gotrxx", details.ClientID)
	assert.Equal(s.T(), details.ExpiresAt.Local(), details.ExpiresAt.Local())
	assert.Equal(s.T(), tid, details.ID)
	assert.Equal(s.T(), token, details.Token)
	assert.Equal(s.T(), tokenType, details.TokenType)
	assert.NotNil(s.T(), details.RevokedAt)
}

func (s *DatabaseIntegrationTestSuite) TestTokenCommonTokenDetails() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	confirmToken := "token"
	id, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, &confirmToken)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), id)

	aid, err := s.dataStore.GrantAuthorization(context.Background(), 1, id, make(tables.MapStructure))
	assert.NoError(s.T(), err)
	assert.NotEqual(s.T(), aid, uuid.Nil)

	tokenType := "dream.token"
	token := "i.am.something.else"
	expires := time.Now().Add(time.Hour * 5)
	m := make(tables.MapStructure)
	m["property"] = "value"

	tid, err := s.dataStore.InsertCommonToken(context.Background(), aid, tokenType, token, expires, m)
	assert.NoError(s.T(), err)
	assert.NotEqual(s.T(), 0, tid)

	details, err := s.dataStore.CommonTokenDetails(context.Background(), tokenType, token)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), details)
	assert.Equal(s.T(), id, details.UserID)
	assert.Equal(s.T(), aid, details.AuthorizationId)
	assert.Equal(s.T(), "$.gotrxx", details.ClientID)
	assert.Equal(s.T(), details.ExpiresAt.Local(), details.ExpiresAt.Local())
	assert.Equal(s.T(), tid, details.ID)
	assert.Equal(s.T(), token, details.Token)
	assert.Equal(s.T(), tokenType, details.TokenType)
	assert.Nil(s.T(), details.RedeemedAt)
	assert.Nil(s.T(), details.RevokedAt)
	assert.Contains(s.T(), details.Properties, "property")
}

func (s *DatabaseIntegrationTestSuite) TestTokenRedeemCommonToken() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	confirmToken := "token"
	id, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, &confirmToken)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), id)

	aid, err := s.dataStore.GrantAuthorization(context.Background(), 1, id, make(tables.MapStructure))
	assert.NoError(s.T(), err)
	assert.NotEqual(s.T(), aid, uuid.Nil)

	tokenType := "dream.token"
	token := "i.am.something.else"
	expires := time.Now().Add(time.Hour * 5)
	tid, err := s.dataStore.InsertCommonToken(context.Background(), aid, tokenType, token, expires, make(tables.MapStructure))
	assert.NoError(s.T(), err)
	assert.NotEqual(s.T(), 0, tid)

	err = s.dataStore.RedeemCommonToken(context.Background(), tokenType, token)
	assert.NoError(s.T(), err)

	details, err := s.dataStore.CommonTokenDetails(context.Background(), tokenType, token)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), details)
	assert.Equal(s.T(), id, details.UserID)
	assert.Equal(s.T(), aid, details.AuthorizationId)
	assert.Equal(s.T(), "$.gotrxx", details.ClientID)
	assert.Equal(s.T(), details.ExpiresAt.Local(), details.ExpiresAt.Local())
	assert.Equal(s.T(), tid, details.ID)
	assert.Equal(s.T(), token, details.Token)
	assert.Equal(s.T(), tokenType, details.TokenType)
	assert.NotNil(s.T(), details.RedeemedAt)
}

// User part

func (s *DatabaseIntegrationTestSuite) TestUserCreation() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	confirmToken := "token"
	id, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, &confirmToken)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), id)

	data, err := s.dataStore.UserById(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.Nil(s.T(), data.EmailConfirmed)
	assert.Equal(s.T(), email, data.Email)
	assert.Equal(s.T(), id, data.ID)
	assert.Equal(s.T(), []byte(pwd), data.PasswordHash)
}

func (s *DatabaseIntegrationTestSuite) TestUserCreationWithPhone() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	confirmToken := "token"
	phone := "+430105050505"
	id, err := s.dataStore.InsertUser(context.Background(), email, pwd, &phone, &confirmToken)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), id)

	data, err := s.dataStore.UserById(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.Nil(s.T(), data.EmailConfirmed)
	assert.Equal(s.T(), email, data.Email)
	assert.Equal(s.T(), phone, *data.Phone)
	assert.Equal(s.T(), id, data.ID)
	assert.Equal(s.T(), []byte(pwd), data.PasswordHash)
	assert.Equal(s.T(), 0, data.CurrentFailureCount)
}

func (s *DatabaseIntegrationTestSuite) TestUserCreationAndConfirm() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	confirmToken := "token"
	id, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, &confirmToken)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), id)

	y, uid, err := s.dataStore.ConfirmUser(context.Background(), confirmToken)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), id, uid)
	assert.True(s.T(), y)

	data, err := s.dataStore.UserById(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), data.EmailConfirmed)
}

func (s *DatabaseIntegrationTestSuite) TestUserConfirmNonExistent() {
	confirmToken := "token"
	y, _, err := s.dataStore.ConfirmUser(context.Background(), confirmToken)
	assert.NoError(s.T(), err)
	assert.False(s.T(), y)
}

func (s *DatabaseIntegrationTestSuite) TestUserConfirmEmptyToken() {
	_, _, err := s.dataStore.ConfirmUser(context.Background(), "")
	assert.Error(s.T(), err)
}

func (s *DatabaseIntegrationTestSuite) TestUserCreationAndDoubleConfirm() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	confirmToken := "token"
	id, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, &confirmToken)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), id)

	data, err := s.dataStore.UserById(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.Nil(s.T(), data.EmailConfirmed)

	y, uid, err := s.dataStore.ConfirmUser(context.Background(), confirmToken)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), id, uid)
	assert.True(s.T(), y)

	data, err = s.dataStore.UserById(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), data.EmailConfirmed)

	y, uid, err = s.dataStore.ConfirmUser(context.Background(), confirmToken)
	assert.NoError(s.T(), err)
	assert.False(s.T(), y)
}

func (s *DatabaseIntegrationTestSuite) TestUserCreationAndManualConfirm() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	id, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, nil)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), id)

	err = s.dataStore.ManualConfirmUser(context.Background(), id)
	assert.NoError(s.T(), err)

	data, err := s.dataStore.UserById(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), data.EmailConfirmed)
}

func (s *DatabaseIntegrationTestSuite) TestUserCreationAndBanUnban() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	confirmToken := "token"
	id, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, &confirmToken)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), id)

	err = s.dataStore.BanUser(context.Background(), id)
	assert.NoError(s.T(), err)

	data, err := s.dataStore.UserById(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), data)
	assert.NotNil(s.T(), data.BannedOn)

	err = s.dataStore.UnbanUser(context.Background(), id)
	assert.NoError(s.T(), err)

	data, err = s.dataStore.UserById(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), data)
	assert.Nil(s.T(), data.BannedOn)

}

func (s *DatabaseIntegrationTestSuite) TestUserCreationEnableMFADisableMFA() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	secret := "secret"
	recovery := "recovery"
	id, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, nil)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), id)

	b, err := s.dataStore.EnableMFA(context.Background(), id, secret, recovery)
	assert.NoError(s.T(), err)
	assert.True(s.T(), b)

	data, err := s.dataStore.UserById(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), data)
	assert.True(s.T(), data.TwoFactor)
	assert.Equal(s.T(), secret, data.TwoFactorSecret)

	b, err = s.dataStore.DisableMFA(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.True(s.T(), b)

	data, err = s.dataStore.UserById(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), data)
	assert.False(s.T(), data.TwoFactor)
	assert.Empty(s.T(), data.TwoFactorSecret)

}

func (s *DatabaseIntegrationTestSuite) TestUserCreationRoles() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	id, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, nil)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), id)

	err = s.dataStore.AddUserToRole(context.Background(), id, "inviter")
	assert.NoError(s.T(), err)

	data, err := s.dataStore.UserById(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), data)
	assert.Contains(s.T(), data.Roles, "inviter")

	err = s.dataStore.RemoveUserFromRole(context.Background(), id, "inviter")
	assert.NoError(s.T(), err)

	data, err = s.dataStore.UserById(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), data)
	assert.NotContains(s.T(), data.Roles, "inviter")
}

func (s *DatabaseIntegrationTestSuite) TestUserIsRegistredPositive() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	_, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, nil)
	assert.NoError(s.T(), err)
	b, err := s.dataStore.IsRegistred(context.Background(), "blub@gotrxx.local")
	assert.NoError(s.T(), err)
	assert.True(s.T(), b)
}

func (s *DatabaseIntegrationTestSuite) TestUserIsRegistredNegative() {
	b, err := s.dataStore.IsRegistred(context.Background(), "blub@gotrxx.local")
	assert.NoError(s.T(), err)
	assert.False(s.T(), b)
}

func (s *DatabaseIntegrationTestSuite) TestUserLockUserUnlockUser() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	id, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, nil)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), id)

	data, err := s.dataStore.UserById(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), data)
	assert.Nil(s.T(), data.LockoutTill)

	lockTime := time.Now()
	b, err := s.dataStore.LockUser(context.Background(), id, lockTime)
	assert.NoError(s.T(), err)
	assert.True(s.T(), b)

	b, err = s.dataStore.LockUser(context.Background(), id, lockTime)
	assert.NoError(s.T(), err)
	assert.False(s.T(), b)

	data, err = s.dataStore.UserById(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), data)
	assert.Equal(s.T(), lockTime.Local(), (*data.LockoutTill).Local())

	b, err = s.dataStore.UnlockUser(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.True(s.T(), b)

	data, err = s.dataStore.UserById(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), data)
	assert.Nil(s.T(), data.LockoutTill)

	b, err = s.dataStore.UnlockUser(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.False(s.T(), b)

}

func (s *DatabaseIntegrationTestSuite) TestUserIdFromEmailNegative() {
	b, id, err := s.dataStore.IdFromEmail(context.Background(), "nope@gotrxx.local")
	assert.NoError(s.T(), err)
	assert.False(s.T(), b)
	assert.Equal(s.T(), id, uuid.Nil)
}

func (s *DatabaseIntegrationTestSuite) TestUserIdFromEmailPositive() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	id, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, nil)
	assert.NoError(s.T(), err)
	b, uid, err := s.dataStore.IdFromEmail(context.Background(), email)
	assert.NoError(s.T(), err)
	assert.True(s.T(), b)
	assert.Equal(s.T(), id, uid)
}

func (s *DatabaseIntegrationTestSuite) TestUserSetPassword() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	id, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, nil)
	assert.NoError(s.T(), err)
	b, err := s.dataStore.SetPassword(context.Background(), id, "wala")
	assert.NoError(s.T(), err)
	assert.True(s.T(), b)

	data, err := s.dataStore.UserById(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), data)
	assert.Equal(s.T(), []byte("wala"), data.PasswordHash)
}

func (s *DatabaseIntegrationTestSuite) TestUserSetAndConsumeRecoveryToken() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	id, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, nil)
	assert.NoError(s.T(), err)

	b, err := s.dataStore.SetRecoveryToken(context.Background(), id, "wala")
	assert.NoError(s.T(), err)
	assert.True(s.T(), b)

	b, err = s.dataStore.ConsumeRecoveryToken(context.Background(), id, "wala")
	assert.NoError(s.T(), err)
	assert.True(s.T(), b)
}

func (s *DatabaseIntegrationTestSuite) TestUserSetEmail() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	id, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, nil)
	assert.NoError(s.T(), err)
	b, err := s.dataStore.SetEmail(context.Background(), id, "blah@gotrxx.local")
	assert.NoError(s.T(), err)
	assert.True(s.T(), b)

	data, err := s.dataStore.UserById(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), data)
	assert.Equal(s.T(), "blah@gotrxx.local", data.Email)
}

func (s *DatabaseIntegrationTestSuite) TestUserConfirmTokenExistsPositive() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	confirm := "token"
	_, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, &confirm)
	assert.NoError(s.T(), err)
	b, err := s.dataStore.IsRegistred(context.Background(), "blub@gotrxx.local")
	assert.NoError(s.T(), err)
	assert.True(s.T(), b)
}

func (s *DatabaseIntegrationTestSuite) TestUserConfirmTokenExistsNegative() {
	b, err := s.dataStore.ConfirmTokenExists(context.Background(), "token")
	assert.NoError(s.T(), err)
	assert.False(s.T(), b)
}

func (s *DatabaseIntegrationTestSuite) TestUserSetFailureCount() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	confirm := "token"
	id, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, &confirm)
	assert.NoError(s.T(), err)

	data, err := s.dataStore.UserById(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), data)
	assert.Equal(s.T(), 0, data.CurrentFailureCount)

	err = s.dataStore.SetFailureCount(context.Background(), id, 1)
	assert.NoError(s.T(), err)

	data, err = s.dataStore.UserById(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), data)
	assert.Equal(s.T(), 1, data.CurrentFailureCount)

	err = s.dataStore.SetFailureCount(context.Background(), id, 99)
	assert.NoError(s.T(), err)

	data, err = s.dataStore.UserById(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), data)
	assert.Equal(s.T(), 99, data.CurrentFailureCount)

	err = s.dataStore.SetFailureCount(context.Background(), id, 0)
	assert.NoError(s.T(), err)

	data, err = s.dataStore.UserById(context.Background(), id)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), data)
	assert.Equal(s.T(), 0, data.CurrentFailureCount)

}

func (s *DatabaseIntegrationTestSuite) TestUserSetOTPPending() {
	email := "blub@gotrxx.local"
	pwd := "wolo"
	confirm := "token"
	id, err := s.dataStore.InsertUser(context.Background(), email, pwd, nil, &confirm)
	assert.NoError(s.T(), err)

	err = s.dataStore.SetOTPPending(context.Background(), id, true)
	assert.NoError(s.T(), err)
}

func (s *DatabaseIntegrationTestSuite) TestUserInRoleNoUser() {
	is, err := s.dataStore.IsUserInRole(context.Background(), uuid.New(), "inviter")
	assert.NoError(s.T(), err)
	assert.False(s.T(), is)
}

func (s *DatabaseIntegrationTestSuite) TestUserByEmailNotFound() {
	_, err := s.dataStore.UserByEmail(context.Background(), "nope@example.com")
	assert.ErrorIs(s.T(), ErrNotFound, err)
}

func (s *DatabaseIntegrationTestSuite) TestUserByIdNotFound() {
	_, err := s.dataStore.UserById(context.Background(), uuid.New())
	assert.ErrorIs(s.T(), ErrNotFound, err)
}

func TestDatabaseSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests")
	}
	s := &DatabaseIntegrationTestSuite{}
	logger := zaptest.NewLogger(t)
	dbType := os.Getenv("INTEGRATION_TEST_DB_TYPE")
	dsn := os.Getenv("INTEGRATION_TEST_DB_DSN")
	switch dbType {
	case "sqlite":
		dataStore, err := NewSqliteStore(logger, &config.DatabaseConfiguration{
			Type: dbType,
			DSN:  dsn,
		})
		if err != nil {
			log.Fatal("error creating database store")
		}
		s.dataStore = dataStore
		break
	case "mysql":
		dataStore, err := NewMysqlStore(logger, &config.DatabaseConfiguration{
			Type: dbType,
			DSN:  dsn,
		})
		if err != nil {
			log.Fatal("error creating database store")
		}
		s.dataStore = dataStore
		break
	case "pg":
		dataStore, err := NewPostgrestore(logger, &config.DatabaseConfiguration{
			Type: dbType,
			DSN:  dsn,
		})
		if err != nil {
			log.Fatal("error creating database store")
		}
		s.dataStore = dataStore
		break
	default:
		dataStore, err := NewSqliteStore(logger, &config.DatabaseConfiguration{
			Type: dbType,
			DSN:  dsn,
		})
		if err != nil {
			log.Fatal("error creating database store")
		}
		s.dataStore = dataStore
		break
	}
	s.dbType = dbType
	s.dsn = dsn
	suite.Run(t, s)
}
