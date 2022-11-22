package meta

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/eisenwinter/gotrxx/config"
	"github.com/eisenwinter/gotrxx/tokens"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/go-chi/render"
	"go.uber.org/zap"
)

// MetaRessource contains the .well-known endpoints
type MetaRessource struct {
	log    *zap.Logger
	cfg    *config.BehaviourConfiguration
	issuer *tokens.TokenIssuer
}

func (m *MetaRessource) Router() *chi.Mux {
	r := chi.NewRouter()

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	r.Get("/openid-configuration", m.openidConfiguration)
	r.Get("/jwks", m.jwks)
	return r
}

func (m *MetaRessource) jwks(w http.ResponseWriter, _ *http.Request) {
	switch m.issuer.Alg() {
	case "HS256", "HS384", "HS512", "RS256", "RS384", "RS512":
		jwk, err := m.issuer.AsPublicOnlyJWKSet()
		if err != nil {
			w.WriteHeader(500)
			return
		}

		b, err := json.Marshal(jwk)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		_, _ = w.Write(b)
		return

	default:
		w.WriteHeader(500)
	}

}

// this ensures enough compatbility to easily use oidc-client - sorry not sorry
// and once again - this server does not support openidconnect
func (m *MetaRessource) openidConfiguration(w http.ResponseWriter, r *http.Request) {
	oidc := &openIdMetaData{
		Issuer:                 m.issuer.Issuer(),
		AuthorizationEndpoint:  fmt.Sprintf("%s/connect/authorize", m.cfg.ServiceDomain),
		JWKSUri:                fmt.Sprintf("%s/.well-known/jwks", m.cfg.ServiceDomain),
		ResponseTypesSupported: []string{"code", "token"},
		SubjectTypesSupported:  []string{"public"},
		TokenEndpoint:          fmt.Sprintf("%s/connect/token", m.cfg.ServiceDomain),
		IntrospectionEndpoint:  fmt.Sprintf("%s/connect/introspect", m.cfg.ServiceDomain),
		RevocationEndpoint:     fmt.Sprintf("%s/connect/revoke", m.cfg.ServiceDomain),
		//this is not a openid comptabile server and doesnt issue idtokens ... hence none
		IDTokenSinginAlg: []string{
			// m.issuer.Alg()
		},
		RequestParameterSupported: true,
	}
	err := render.Render(w, r, oidc)
	if err != nil {
		m.log.Error("unable to render response", zap.Error(err))
	}
}

func NewMetaRessource(
	log *zap.Logger,
	cfg *config.BehaviourConfiguration,
	issuer *tokens.TokenIssuer,
) *MetaRessource {
	return &MetaRessource{log: log, cfg: cfg, issuer: issuer}
}
