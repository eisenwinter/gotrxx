package meta

import "net/http"

// notice: this server is NOT openid capable, it does NOT issue any id tokens nor implements the spec
type openIdMetaData struct {
	Issuer                 string   `json:"issuer"`
	AuthorizationEndpoint  string   `json:"authorization_endpoint"`
	JWKSUri                string   `json:"jwks_uri"`
	ResponseTypesSupported []string `json:"response_types_supported"`
	SubjectTypesSupported  []string `json:"subject_types_supported"`
	TokenEndpoint          string   `json:"token_endpoint"`
	IntrospectionEndpoint  string   `json:"introspection_endpoint"`
	RevocationEndpoint     string   `json:"revocation_endpoint"`
	//it doesnt issue id token hence it will always be empty
	IDTokenSinginAlg          []string `json:"id_token_signing_alg_values_supported"`
	RequestParameterSupported bool     `json:"request_parameter_supported"`
}

func (*openIdMetaData) Render(_ http.ResponseWriter, _ *http.Request) error {
	return nil
}
