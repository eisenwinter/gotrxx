package meta

import "github.com/lestrrat-go/jwx/v2/jwk"

type JwkSupplier interface {
	AsPublicOnlyJWKSet() (jwk.Set, error)
	Alg() string
	Issuer() string
}
