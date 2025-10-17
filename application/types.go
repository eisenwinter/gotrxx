package application

import (
	"strings"
	"time"

	"github.com/eisenwinter/gotrxx/db/tables"
	"golang.org/x/crypto/bcrypt"
)

type Type int

const ImplicitGrantedApplication Type = 1
const ExplicitGrantedApplication Type = 2

type Confidentiality string

const PublicConfidentiality Confidentiality = "public"
const PrivateConfidentiality Confidentiality = "private"

type FlowType string

const AuthorizationCodeFlow FlowType = "authorization_code"
const PasswordFlow FlowType = "password"
const ClientCredentialsFlow FlowType = "client_credentials"
const RefreshTokenFlow FlowType = "refresh_token"

func ApplicationFromDbType(table *tables.ApplicationTable) *Application {
	return &Application{
		id:              table.ID,
		clientID:        table.ClientID,
		clientSecret:    table.ClientSecret,
		confidentiality: Confidentiality(table.Confidentiality),
		name:            table.Name,
		appType:         Type(table.ApplicationType),
		properties:      table.Properties,
		retiredOn:       table.RetiredOn,
	}
}

type Application struct {
	id              int
	clientID        string
	clientSecret    *string
	name            string
	confidentiality Confidentiality
	appType         Type
	properties      map[string]interface{}
	retiredOn       *time.Time
}

func (a *Application) ID() int {
	return a.id
}

func (a *Application) Name() string {
	return a.name
}

func (a *Application) Confidentiality() Confidentiality {
	return a.confidentiality
}

func (a *Application) Type() Type {
	return a.appType
}

func (a *Application) IsRetired() bool {
	return a.retiredOn != nil
}

func (a *Application) IsFlowAllowed(flow FlowType) bool {
	for _, v := range a.Properties().AllowedFlows() {
		if v == flow {
			return true
		}
	}
	return false
}

func (a *Application) IsAllowedRedirectURI(uri string) bool {
	for _, v := range a.Properties().RedirectURIs() {
		if v == uri {
			return true
		}
	}
	return false
}

func (a *Application) IsAllowedLogoutURI(uri string) bool {
	for _, v := range a.Properties().LogoutURIs() {
		if v == uri {
			return true
		}
	}
	return false
}

func (a *Application) AreScopesCoveredByApplication(scopes string) bool {
	trim := strings.TrimSpace(scopes)
	s := strings.Split(trim, " ")
	if trim != "" && len(s) > 0 {
		appScopes := a.Properties().Scopes()
		for _, v := range s {
			contained := false
			for _, k := range appScopes {
				if k == v {
					contained = true
					break
				}
			}
			if !contained {
				return false
			}
		}
	}
	return true
}

func (a *Application) ClientID() string {
	return a.clientID
}

func (a *Application) HasSecret() bool {
	return a.clientSecret != nil
}

func (a *Application) ValidateClientSecret(input string) bool {
	//no secret set
	if a.clientSecret == nil {
		return true
	}
	sec := *a.clientSecret
	res := bcrypt.CompareHashAndPassword([]byte(sec), []byte(input))
	return res == nil
}

func (a *Application) Properties() *ApplicationProperties {
	return &ApplicationProperties{
		properties: a.properties,
	}
}

type ApplicationProperties struct {
	properties map[string]interface{}
}

func (a *ApplicationProperties) AllowedFlows() []FlowType {
	if val, ok := a.properties["allowed_flows"]; ok {
		arr := val.([]interface{})
		if len(arr) == 0 {
			return []FlowType{}
		}
		flows := make([]FlowType, len(arr))
		for i, v := range arr {

			flows[i] = FlowType(v.(string))
		}
		return flows
	}
	return []FlowType{}
}

func (a *ApplicationProperties) PKCE() bool {
	if val, ok := a.properties["pkce"]; ok {
		return val.(bool)
	}
	return false
}

func (a *ApplicationProperties) Scopes() []string {
	if val, ok := a.properties["scopes"]; ok {
		arr := val.([]interface{})
		if len(arr) == 0 {
			return []string{}
		}
		res := make([]string, len(arr))
		for i, v := range arr {
			res[i] = v.(string)
		}
		return res
	}
	return []string{}
}

func (a *ApplicationProperties) RedirectURIs() []string {
	if val, ok := a.properties["redirect_uris"]; ok {
		arr := val.([]interface{})
		if len(arr) == 0 {
			return []string{}
		}
		res := make([]string, len(arr))
		for i, v := range arr {
			res[i] = v.(string)
		}
		return res
	}
	return []string{}
}

func (a *ApplicationProperties) LogoutURIs() []string {
	if val, ok := a.properties["logout_uris"]; ok {
		arr := val.([]interface{})
		if len(arr) == 0 {
			return []string{}
		}
		res := make([]string, len(arr))
		for i, v := range arr {
			res[i] = v.(string)
		}
		return res
	}
	return []string{}
}
