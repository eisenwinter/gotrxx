package tokens

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"strings"
	"time"

	"github.com/eisenwinter/gotrxx/config"
	"github.com/eisenwinter/gotrxx/db/tables"
	"github.com/eisenwinter/gotrxx/generator"
	"github.com/eisenwinter/gotrxx/pkg/logging"
	"github.com/eisenwinter/gotrxx/user"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	//ClaimEmail is the claim storing the email
	ClaimEmail = "email"
	//ClaimRoles is the claim storing the roles
	ClaimRoles = "roles" //this works out of the box with aspnet core
	//ClaimClientID is the claim storing the application client_id
	ClaimClientID = "client_id"
	//ClaimAuthorization is the claim storing the authorization
	ClaimAuthorization = "aut"
	//ClaimScope is the claim storing the scopes
	ClaimScope = "scope"

	//ClaimNetlifyAppMetaData represents the app_metadata claim used in netlifys token
	ClaimNetlifyAppMetaData = "app_metadata"

	//ClaimNetlifyUserMetaData represents the user_metadata claim used in netlifys token
	ClaimNetlifyUserMetaData = "user_metadata"

	algHS256 = "HS256"
	algHS384 = "HS384"
	algHS512 = "HS512"

	algRS256 = "RS256"
	algRS384 = "RS384"
	algRS512 = "RS512"
)

type CommonTokenInserter interface {
	InsertCommonToken(
		ctx context.Context,
		authorizationID uuid.UUID,
		tokenType string,
		token string,
		expires time.Time,
		properties tables.MapStructure,
	) (int, error)
}

type TokenIssuer struct {
	log                logging.Logger
	privateKey         jwk.Key
	publicKey          jwk.Key
	alg                jwa.SignatureAlgorithm
	aud                []string
	expiry             time.Duration
	iss                string
	noRoles            bool
	refreshTokenExpiry time.Duration
	tokenStorage       CommonTokenInserter
	parseOptions       []jwt.ParseOption
	rememberMeDuration time.Duration
	kid                string
}

func checkForWeakHMAC(log logging.Logger, alg string, key string) {
	if alg == algHS256 && len(key) <= 31 {
		log.Warn("weak secret, consider chossing another secret")
	}
	if alg == algHS384 && len(key) <= 39 {
		log.Warn("weak secret, consider chossing another secret")
	}
	if alg == algHS512 && len(key) <= 57 {
		log.Warn("weak secret, consider chossing another secret")
	}
}

func parseRSAPrivateKey(key []byte) (*rsa.PrivateKey, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("supplied private key is empty")
	}
	pemLoaded, _ := pem.Decode(key)
	if pemLoaded.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("supplied private key is not a private key, got %s", pemLoaded.Type)
	}
	var err error
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(pemLoaded.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(pemLoaded.Bytes); err != nil {
			return nil, errors.New("could not parse RSA private key")
		}
	}

	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("could not parse RSA private key")
	}
	return privateKey, nil
}

func parseRSAPublicKey(key []byte) (*rsa.PublicKey, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("supplied public key is empty")
	}
	pemLoaded, _ := pem.Decode(key)
	if pemLoaded == nil {
		return nil, errors.New("could not parse RSA public key")
	}
	if pemLoaded.Type == "RSA PUBLIC KEY" {
		var err error
		var parsedKey interface{}
		if parsedKey, err = x509.ParsePKCS1PublicKey(pemLoaded.Bytes); err != nil {
			fmt.Print(err)
			return nil, errors.New("could not parse RSA public key")
		}
		var ok bool
		var pubKey *rsa.PublicKey
		if pubKey, ok = parsedKey.(*rsa.PublicKey); !ok {
			return nil, errors.New("could not parse RSA public key")
		}
		return pubKey, nil
	}
	if pemLoaded.Type == "PUBLIC KEY" {
		var err error
		var parsedKey interface{}
		if parsedKey, err = x509.ParsePKIXPublicKey(pemLoaded.Bytes); err != nil {
			fmt.Print(err)
			return nil, errors.New("could not parse RSA public key")
		}
		var ok bool
		var pubKey *rsa.PublicKey
		if pubKey, ok = parsedKey.(*rsa.PublicKey); !ok {
			return nil, errors.New("could not parse RSA public key")
		}
		return pubKey, nil
	}
	return nil, fmt.Errorf("supplied public key is not a public key, got %s", pemLoaded.Type)
}

func NewIssuer(
	log logging.Logger,
	cfg *config.JWTConfiguration,
	storage CommonTokenInserter,
) *TokenIssuer {

	var privateKeyJwk jwk.Key
	var publicKeyJwk jwk.Key
	kid := ""
	options := make([]jwt.ParseOption, 0)
	options = append(options, jwt.WithValidate(true))
	//okay this is probably the only reason and place to panic...
	switch cfg.Algorithm {
	case algHS256, algHS384, algHS512:
		privateKeyJwk, options = loadHMACKey(cfg, log, options)
	case algRS256, algRS384, algRS512:
		var err error
		var privateKey *rsa.PrivateKey
		var pubParsed *rsa.PublicKey
		kid, privateKey, pubParsed = loadRSAKeys(cfg, log)
		privateKeyJwk, err = jwk.FromRaw(privateKey)
		if err != nil {
			log.Error("unable to process private key")
			panic("unable to process private key")
		}
		publicKeyJwk, err = jwk.FromRaw(pubParsed)
		if err != nil {
			log.Error("unable to process public key")
			panic("unable to process public key")
		}
		_ = publicKeyJwk.Set("alg", cfg.Algorithm)
		_ = publicKeyJwk.Set("use", "sig")
		_ = publicKeyJwk.Set("kid", kid)
		_ = privateKeyJwk.Set("kid", kid)
		sha, err := publicKeyJwk.Thumbprint(crypto.SHA1)
		if err == nil {
			_ = publicKeyJwk.Set("x5t", b64.StdEncoding.EncodeToString(sha))
		}

		options = append(options, jwt.WithKey(jwa.SignatureAlgorithm(cfg.Algorithm), publicKeyJwk))

	default:
		log.Error("invalid jwt.alg defined. Possible values: HS256,HS384,HS512,RS256,RS384,RS512")
		panic("invalid jwt.alg defined. Possible values: HS256,HS384,HS512,RS256,RS384,RS512")
	}
	_ = privateKeyJwk.Set("alg", cfg.Algorithm)
	_ = privateKeyJwk.Set("use", "sig")
	sha, err := privateKeyJwk.Thumbprint(crypto.SHA1)
	if err == nil {
		_ = privateKeyJwk.Set("x5t", b64.StdEncoding.EncodeToString(sha))
	}
	return &TokenIssuer{
		log:                log,
		alg:                jwa.SignatureAlgorithm(cfg.Algorithm),
		privateKey:         privateKeyJwk,
		aud:                cfg.Audience,
		expiry:             cfg.Expiry,
		iss:                cfg.Issuer,
		noRoles:            cfg.NoRolesClaim,
		refreshTokenExpiry: cfg.RefreshTokenExpiry,
		rememberMeDuration: cfg.RememberMeDuration,
		tokenStorage:       storage,
		parseOptions:       options,
		publicKey:          publicKeyJwk,
		kid:                kid,
	}
}

func loadRSAKeys(
	cfg *config.JWTConfiguration,
	log logging.Logger,
) (string, *rsa.PrivateKey, *rsa.PublicKey) {
	var privateKey interface{}
	var publicKey interface{}
	if len(cfg.RSAPrivateKey) > 0 {
		privateKey = []byte(cfg.RSAPrivateKey)
	} else if len(cfg.RSAPRivateKeyFile) > 0 {
		content, err := os.ReadFile(cfg.RSAPRivateKeyFile)
		if err != nil {
			log.Error("could not load key file", "file", cfg.RSAPRivateKeyFile, "err", err)
			panic("could not load key file")
		}
		if len(content) == 0 {
			log.Error("read empty private key file", "file", cfg.RSAPRivateKeyFile, "err", err)
			panic("read empty private key file")
		}
		privateKey = content
	} else {
		log.Error("no RSA private key defined, either set jwt.rsa-private-key or jwt.rsa-private-key-file")
		panic("no RSA private key defined")
	}
	var err error
	privateKey, err = parseRSAPrivateKey(privateKey.([]byte))
	if err != nil {
		log.Error("unable to process suplied private key", "err", err)
		panic("unable to process suplied private key")
	}
	if len(cfg.RSAPublicKey) > 0 {
		publicKey = []byte(cfg.RSAPublicKey)
	} else if len(cfg.RSAPRivateKeyFile) > 0 {
		content, err := os.ReadFile(cfg.RSAPublicKeyFile)
		if err != nil {
			log.Error("could not load key file", "file", cfg.RSAPublicKeyFile, "err", err)
			panic("could not load key file")
		}
		publicKey = content
	} else {
		log.Error("no RSA private key defined, either set jwt.rsa-public-key or jwt.rsa-public-key-file")
		panic("no RSA private key defined")
	}
	kid := fmt.Sprintf("%x", crc32.Checksum(publicKey.([]byte), crc32.IEEETable))
	pubParsed, err := parseRSAPublicKey(publicKey.([]byte))
	if err != nil {
		log.Error("unable to process supllied public key", "err", err)
		panic("invalid public key")
	}
	priv := privateKey.(*rsa.PrivateKey)
	priv.PublicKey = *pubParsed
	return kid, priv, pubParsed
}

func loadHMACKey(
	cfg *config.JWTConfiguration,
	log logging.Logger,
	options []jwt.ParseOption) (jwk.Key, []jwt.ParseOption) {
	var privateKey interface{}
	//direct key takes precende
	if len(cfg.HMACSigningKey) > 0 {
		checkForWeakHMAC(log, cfg.Algorithm, cfg.HMACSigningKey)
		privateKey = []byte(cfg.HMACSigningKey)
	} else if len(cfg.HMACSigningKeyFile) > 0 {
		content, err := os.ReadFile(cfg.HMACSigningKeyFile)
		if err != nil {
			log.Error("could not load key file", "file", cfg.HMACSigningKeyFile, "err", err)
			panic("could not load key file")
		}
		checkForWeakHMAC(log, cfg.Algorithm, string(content))
		privateKey = content

	} else {
		log.Error("no HMAC key defined, either set jwt.hmac-signing-key or jwt.hmac-signing-key-file")
		panic("no HMAC key defined")
	}
	if len(privateKey.([]byte)) > 0 {
		var err error
		privateKeyJwk, err := jwk.FromRaw(privateKey)
		if err != nil {
			log.Error("unable to process symetric key", "err", err)
			panic("unable to process symetric key")
		}
		options = append(
			options,
			jwt.WithKey(jwa.SignatureAlgorithm(cfg.Algorithm), privateKeyJwk),
		)
		return privateKeyJwk, options
	}
	log.Error("no HMAC key defined, either set jwt.hmac-signing-key or jwt.hmac-signing-key-file")
	panic("no valid key found")
}

func (t *TokenIssuer) Audience() []string {
	return t.aud
}

func (t *TokenIssuer) Issuer() string {
	return t.iss
}

func (t *TokenIssuer) RememberMeDuration() time.Duration {
	return t.rememberMeDuration
}

func (t *TokenIssuer) IssueRememberMeToken(
	ctx context.Context,
	authorizationID uuid.UUID,
) (string, error) {
	gen := generator.New()
	token := gen.CreateSecureTokenWithSize(64)
	_, err := t.tokenStorage.InsertCommonToken(
		ctx,
		authorizationID,
		string(RememberMeTokenType),
		string(token),
		time.Now().Add(t.rememberMeDuration),
		tables.MapStructure{},
	)
	if err != nil {
		return "", err
	}
	return string(token), nil
}

func (t *TokenIssuer) IssueRefreshToken(
	ctx context.Context,
	authorizationID uuid.UUID,
) (string, error) {
	gen := generator.New()
	token := gen.CreateSecureToken()
	_, err := t.tokenStorage.InsertCommonToken(
		ctx,
		authorizationID,
		string(RefreshTokenType),
		string(token),
		time.Now().Add(t.refreshTokenExpiry),
		tables.MapStructure{},
	)
	if err != nil {
		return "", err
	}
	return string(token), nil
}

func (t *TokenIssuer) IssueAuthorizationCode(
	ctx context.Context,
	authorizationID uuid.UUID,
	codeChallenge string,
	codeChallengeMethod string,
) (string, error) {
	gen := generator.New()
	token := gen.CreateSecureToken()
	_, err := t.tokenStorage.InsertCommonToken(
		ctx,
		authorizationID,
		string(AuthorizationCodeType),
		string(token),
		time.Now().Add(t.refreshTokenExpiry),
		tables.MapStructure{
			"code_challenge":        codeChallenge,
			"code_challenge_method": codeChallengeMethod,
		},
	)
	if err != nil {
		return "", err
	}
	return string(token), nil
}

func (t *TokenIssuer) IssueAccessTokenForMachineClient(
	clientID string,
	scopes []string,
) (jwt.Token, error) {
	tokenBuilder := jwt.NewBuilder()
	scope := strings.Join(scopes, " ")
	tokenBuilder.
		Audience(t.aud).
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().UTC().Add(t.expiry)).
		Issuer(t.iss).
		Claim(ClaimScope, scope).
		Claim(ClaimClientID, clientID)
	return tokenBuilder.Build()
}

// IssueAccessTokenForUser issues a standard access token for a user
func (t *TokenIssuer) IssueAccessTokenForUser(
	user *user.SignedInUser,
	authorizationID uuid.UUID,
	clientID string,
	scopes []string,
) (jwt.Token, error) {
	tokenBuilder := jwt.NewBuilder()
	scope := strings.Join(scopes, " ")
	tokenBuilder.
		Audience(t.aud).
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().UTC().Add(t.expiry)).
		Subject(user.UserID.String()).
		Issuer(t.iss).
		Claim(ClaimScope, scope).
		Claim(ClaimEmail, user.Email).
		Claim(ClaimAuthorization, authorizationID).
		Claim(ClaimClientID, clientID)
	if !t.noRoles {
		tokenBuilder.Claim(ClaimRoles, user.Roles)
	}
	return tokenBuilder.Build()
}

// IssueNetlifyAccessTokenForUser differs from the standard access token, it has the app_metadata and user_metadata claims
func (t *TokenIssuer) IssueNetlifyAccessTokenForUser(
	user *user.SignedInUser,
	authorizationID uuid.UUID,
	clientID string,
	scopes []string,
) (jwt.Token, error) {
	tokenBuilder := jwt.NewBuilder()
	scope := strings.Join(scopes, " ")
	tokenBuilder.
		Audience(t.aud).
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().UTC().Add(t.expiry)).
		Subject(user.UserID.String()).
		Issuer(t.iss).
		Claim(ClaimScope, scope).
		Claim(ClaimEmail, user.Email).
		Claim(ClaimAuthorization, authorizationID).
		Claim(ClaimClientID, clientID).
		Claim(ClaimNetlifyAppMetaData, map[string][]string{
			"roles": user.Roles,
		}).
		Claim(ClaimNetlifyUserMetaData, map[string][]string{})
	if !t.noRoles {
		tokenBuilder.Claim(ClaimRoles, user.Roles)
	}
	return tokenBuilder.Build()
}

func (t *TokenIssuer) Sign(token jwt.Token) ([]byte, error) {
	return jwt.Sign(token, jwt.WithKey(t.alg, t.privateKey))
}

func (t *TokenIssuer) Alg() string {
	return string(t.alg)
}

func (t *TokenIssuer) PrivateKey() jwk.Key {
	return t.privateKey
}

func (t *TokenIssuer) PublicKey() jwk.Key {
	return t.publicKey
}

func (t *TokenIssuer) KeyID() string {
	return t.kid
}

func (t *TokenIssuer) AsJWKSet() (jwk.Set, error) {
	switch t.Alg() {
	case algHS256, algHS384, algHS512:
		set := jwk.NewSet()
		_ = set.AddKey(t.PrivateKey())
		return set, nil
	case algRS256, algRS384, algRS512:
		set := jwk.NewSet()
		_ = set.AddKey(t.PrivateKey())
		_ = set.AddKey(t.PublicKey())
		return set, nil
	}
	return nil, errors.New("unknown algorithm")
}

func (t *TokenIssuer) AsPublicOnlyJWKSet() (jwk.Set, error) {
	switch t.Alg() {
	case algHS256, algHS384, algHS512:
		set := jwk.NewSet()

		return set, nil
	case algRS256, algRS384, algRS512:
		set := jwk.NewSet()
		key, err := t.PublicKey().PublicKey()
		if err != nil {
			return nil, err
		}
		_ = set.AddKey(key)
		return set, nil
	}
	return nil, errors.New("unknown algorithm")
}
