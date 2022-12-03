package generator

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"strings"
)

type RandomTokenType string

func tokenTypeFromString(token string) RandomTokenType {
	if token == "" {
		panic("zero length token issued, this is probably the only reason to ever panic")
	}
	return RandomTokenType(token)

}

type RandomTokenGenerator struct{}

func (*RandomTokenGenerator) CreatePINLikeToken() RandomTokenType {
	num := genRandNum(0, 99999999)
	return tokenTypeFromString(fmt.Sprintf("%08d", num))
}

// thanks for the gotrue authors for this, i just bluntly took it (https://github.com/netlify/gotrue/blob/master/crypto/crypto.go)
// although we are using 32 here

func (*RandomTokenGenerator) CreateSecureToken() RandomTokenType {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err.Error()) // rand should never fail
	}
	return tokenTypeFromString(removePadding(base64.URLEncoding.EncodeToString(b)))
}

func (*RandomTokenGenerator) CreateSecureTokenWithSize(size int) RandomTokenType {
	b := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err.Error()) // rand should never fail
	}
	return tokenTypeFromString(removePadding(base64.URLEncoding.EncodeToString(b)))
}

func removePadding(token string) string {
	return strings.TrimRight(token, "=")
}

func genRandNum(min, max int64) int64 {
	bg := big.NewInt(max - min)
	n, err := rand.Int(rand.Reader, bg)
	if err != nil {
		panic(err)
	}
	return n.Int64() + min
}

func New() *RandomTokenGenerator {
	return &RandomTokenGenerator{}
}
