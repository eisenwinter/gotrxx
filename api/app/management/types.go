package management

import (
	"net/http"

	"github.com/go-chi/render"
	"github.com/google/uuid"
)

type genericSuccessResponse struct {
	Success bool    `json:"success"`
	Message string  `json:"message"`
	ID      *string `json:"id,omitempty"`
}

func (g *genericSuccessResponse) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func createError(err string, status int) *genericErrorResponse {
	return &genericErrorResponse{
		Error:      err,
		StatusCode: status,
	}
}

type genericErrorResponse struct {
	Error      string `json:"error,omitempty"`
	ErrorURI   string `json:"error_uri,omitempty"`
	StatusCode int    `json:"-"`
}

func (e *genericErrorResponse) Render(w http.ResponseWriter, r *http.Request) error {
	render.Status(r, e.StatusCode)
	return nil
}

type clientIDRequest struct {
	ID string `json:"client_id"`
}

type userIDRequest struct {
	ID uuid.UUID `json:"id"`
}

type clientIdAndUserIdRequest struct {
	ClientID string    `json:"client_id"`
	UserID   uuid.UUID `json:"user_id"`
}

type userIDRoleRequest struct {
	ID   uuid.UUID `json:"id"`
	Role string    `json:"role"`
}

type createInviteRequest struct {
	Email        *string  `json:"email"`
	Roles        []string `json:"roles"`
	Applications []int    `json:"applications"`
}

type createApplicationRequest struct {
	Name            string   `json:"name"`
	Type            string   `json:"type"`
	Confidentiality string   `json:"confidentiality"`
	PKCE            bool     `json:"pkce"`
	Scopes          string   `json:"scopes"`
	LogoutURIs      []string `json:"logout_uris"`
	RedirectURIs    []string `json:"redirect_uris"`
	ClientID        string   `json:"client_id"`
	ClientSecret    string   `json:"client_secret"`
	Flows           []string `json:"flows"`
}

type clientIdAndUriRequest struct {
	ID  string `json:"client_id"`
	URI string `json:"uri"`
}

type clientIdAndFlowRequest struct {
	ID   string `json:"client_id"`
	Flow string `json:"flow"`
}

type setApplicationSecretRequest struct {
	ID     string `json:"client_id"`
	Secret string `json:"secret"`
}

type clientIDuserIDscopeRequest struct {
	UserID   uuid.UUID `json:"user_id"`
	ClientID string    `json:"client_id"`
	Scope    string    `json:"scope"`
}
