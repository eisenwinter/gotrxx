package meta

import (
	"net/http"
	"testing"

	"github.com/eisenwinter/gotrxx/config"
	"github.com/eisenwinter/gotrxx/tokens"
	"github.com/steinfletcher/apitest"
	"go.uber.org/zap"
)

func TestDiscoveryEndpoint(t *testing.T) {
	bcfg := &config.BehaviourConfiguration{
		ServiceDomain: "http://example.com",
	}
	tcfg := &config.JWTConfiguration{
		Issuer:         "example",
		Algorithm:      "HS512",
		HMACSigningKey: "ABCDEF",
	}
	issuer := tokens.NewIssuer(zap.NewNop(), tcfg, nil)
	m := NewMetaRessource(zap.NewNop(), bcfg, issuer)
	apitest.New(). // configuration
			HandlerFunc(m.openidConfiguration).
			Get("/openid-configuration"). // request
			Expect(t).                    // expectations
			Body(`{"issuer":"example","authorization_endpoint":"http://example.com/connect/authorize","jwks_uri":"http://example.com/.well-known/jwks","response_types_supported":["code","token"],"subject_types_supported":["public"],"token_endpoint":"http://example.com/connect/token","introspection_endpoint":"http://example.com/connect/introspect","revocation_endpoint":"http://example.com/connect/revoke","id_token_signing_alg_values_supported":[],"request_parameter_supported":true}`).
			Status(http.StatusOK).
			End()
}
