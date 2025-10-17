package authorization

import (
	"time"

	"github.com/eisenwinter/gotrxx/application"
	"github.com/google/uuid"
)

type Authorization struct {
	id         uuid.UUID
	userID     uuid.UUID
	properties map[string]interface{}
	app        *application.Application
	revokedAt  *time.Time
}

func (a *Authorization) Properties() *AuthorizationProperties {
	return &AuthorizationProperties{
		properties: a.properties,
	}
}

type AuthorizationProperties struct {
	properties map[string]interface{}
}

func (a *Authorization) ID() uuid.UUID {
	return a.id
}

func (a *Authorization) UserID() uuid.UUID {
	return a.userID
}

func (a *Authorization) Application() *application.Application {
	return a.app
}

func (a *Authorization) Scopes() []string {
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

func (a *Authorization) IsRevoked() bool {
	if a == nil {
		return true
	}
	return a.revokedAt != nil
}
