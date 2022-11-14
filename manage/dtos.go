package manage

import (
	"net/http"
	"strings"
	"time"

	"github.com/eisenwinter/gotrxx/application"
	"github.com/eisenwinter/gotrxx/db"
	"github.com/eisenwinter/gotrxx/db/tables"
	"github.com/google/uuid"
)

type ApplicationDTO struct {
	ID              int      `json:"id"`
	ClientID        string   `json:"client_id"`
	Type            string   `json:"type"`
	Name            string   `json:"name"`
	Status          string   `json:"status"`
	Confidentiality string   `json:"confidentiality"`
	HasSecret       bool     `json:"has_secret"`
	PKCE            bool     `json:"pkce"`
	Flows           []string `json:"flows"`
	Scope           string   `json:"scope"`
	RedirectURIs    []string `json:"redirect_uris"`
	LogoutURIs      []string `json:"logout_uris"`
}

func (a *ApplicationDTO) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func applicationDTOfromDB(t *tables.ApplicationTable) *ApplicationDTO {
	app := application.ApplicationFromDbType(t)
	dto := &ApplicationDTO{
		ID:              t.ID,
		Name:            t.Name,
		ClientID:        t.ClientID,
		Confidentiality: t.Confidentiality,
		HasSecret:       t.ClientSecret != nil,
		PKCE:            app.Properties().PKCE(),
		RedirectURIs:    app.Properties().RedirectURIs(),
		LogoutURIs:      app.Properties().LogoutURIs(),
	}
	dto.Scope = strings.Join(app.Properties().Scopes(), " ")
	dto.Flows = make([]string, len(app.Properties().AllowedFlows()))
	for i, v := range app.Properties().AllowedFlows() {
		dto.Flows[i] = string(v)
	}
	switch app.Type() {
	case 1:
		dto.Type = "implicit_granted"
	case 2:
		dto.Type = "explicit_granted"
	}
	if app.IsRetired() {
		dto.Status = "retired"
	} else {
		dto.Status = "active"
	}
	return dto
}

type UserDTO struct {
	ID                   uuid.UUID  `json:"id,omitempty"`
	Email                string     `json:"email"`
	EmailConfirmed       *time.Time `json:"email_confirmed"`
	Phone                *string    `json:"phone"`
	PhoneConfirmed       *time.Time `json:"phone_confirmed"`
	Mfa                  bool       `json:"mfa"`
	LockoutTill          *time.Time `json:"lockout_till"`
	BannedOn             *time.Time `json:"banned_on"`
	CurrentFailureCount  int        `json:"current_failure_count"`
	RecoveryTokenCreated *time.Time `json:"recovery_token_created,omitempty"`
	ConfirmToken         *string    `json:"confirm_token"`
	ConfirmTokenCreated  *time.Time `json:"confirm_token_created,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            *time.Time `json:"updated_at,omitempty"`
	Roles                []string   `json:"roles"`
}

func userDTOfromDB(t *tables.UserTable, r []*tables.RoleTable) *UserDTO {
	dto := &UserDTO{
		ID:                   t.ID,
		Email:                t.Email,
		EmailConfirmed:       t.EmailConfirmed,
		Phone:                t.Phone,
		PhoneConfirmed:       t.PhoneConfirmed,
		Mfa:                  t.Mfa,
		LockoutTill:          t.LockoutTill,
		BannedOn:             t.BannedOn,
		CurrentFailureCount:  t.CurrentFailureCount,
		RecoveryTokenCreated: t.RecoveryTokenCreated,
		ConfirmToken:         t.ConfirmToken,
		ConfirmTokenCreated:  t.ConfirmTokenCreated,
		CreatedAt:            t.CreatedAt,
		UpdatedAt:            t.UpdatedAt,
		Roles:                make([]string, 0),
	}
	for _, v := range r {
		dto.Roles = append(dto.Roles, v.Name)
	}
	return dto
}

type RoleDTO struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func roleDTOfromDB(t *tables.RoleTable) *RoleDTO {
	return &RoleDTO{
		ID:   t.ID,
		Name: t.Name,
	}
}

type InviteApplicationDTO struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
}

type InviteDTO struct {
	ID           int                    `json:"id"`
	Email        *string                `json:"email"`
	Code         string                 `json:"code"`
	SentAt       *time.Time             `json:"sent_at"`
	ConsumedAt   *time.Time             `json:"consumed_at"`
	ExpiresAt    time.Time              `json:"expires_at"`
	CreatedAt    time.Time              `json:"created_at"`
	Roles        []string               `json:"roles"`
	Applications []InviteApplicationDTO `json:"applications"`
}

func inviteDTOfromDB(t *tables.UserInviteTable,
	data *db.UserInviteData) *InviteDTO {
	dto := &InviteDTO{
		ID:           t.ID,
		Email:        t.Email,
		Code:         t.Code,
		SentAt:       t.SentAt,
		ConsumedAt:   t.ConsumedAt,
		ExpiresAt:    t.ExpiresAt,
		CreatedAt:    t.CreatedAt,
		Roles:        data.Roles,
		Applications: make([]InviteApplicationDTO, 0),
	}
	for _, v := range data.PreApplicationAuthorization {
		app := InviteApplicationDTO{Scope: v.Scopes, ID: v.ApplicationID}

		dto.Applications = append(dto.Applications, app)
	}
	return dto
}

type AuthorizationUserDTO struct {
	ID uuid.UUID `json:"id"`
}

type AuthorizationApplicationDTO struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	ClientID string `json:"client_id"`
}

type AuthorizationDTO struct {
	ID          uuid.UUID                   `json:"id"`
	User        AuthorizationUserDTO        `json:"user"`
	Application AuthorizationApplicationDTO `json:"application"`
	Properties  map[string]interface{}      `json:"properties"`
	RevokedAt   *time.Time                  `json:"revoked_at"`
	CreatedAt   time.Time                   `json:"created_at"`
	UpdatedAt   *time.Time                  `json:"updated_at"`
}

func authorizationDTOfromDB(t *tables.AuthorizationTable) *AuthorizationDTO {
	return &AuthorizationDTO{
		ID:          t.ID,
		Properties:  t.Properties,
		RevokedAt:   t.RevokedAt,
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   t.UpdatedAt,
		User:        AuthorizationUserDTO{ID: t.UserID},
		Application: AuthorizationApplicationDTO{ID: t.ApplicationID},
	}
}
