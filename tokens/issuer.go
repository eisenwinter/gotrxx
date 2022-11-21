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
	"github.com/eisenwinter/gotrxx/user"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"go.uber.org/zap"
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
)

type CommonTokenInserter interface {
	InsertCommonToken(ctx context.Context, authorizationID uuid.UUID, tokenType string, token string, expires time.Time, properties tables.MapStructure) (int, error)
}

type TokenIssuer struct {
	log                *zap.Logger
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

func checkForWeakHMAC(log *zap.Logger, alg string, key string) {
	if alg == "HS256" && len(key) <= 31 {
		log.Warn("Weak secret, consider chossing another secret")
	}
	if alg == "HS384" && len(key) <= 39 {
		log.Warn("Weak secret, consider chossing another secret")
	}
	if alg == "HS512" && len(key) <= 57 {
		log.Warn("Weak secret, consider chossing another secret")
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

func NewIssuer(log *zap.Logger, cfg *config.JWTConfiguration, storage CommonTokenInserter) *TokenIssuer {
	var privateKey interface{}
	var publicKey interface{}

	var privateKeyJwk jwk.Key
	var publicKeyJwk jwk.Key
	kid := ""
	options := make([]jwt.ParseOption, 0)
	options = append(options, jwt.WithValidate(true))
	//okay this is probably the only reason and place to panic...
	switch cfg.Algorithm {
	case "HS256", "HS384", "HS512":
		//direct key takes precende
		if len(cfg.HMACSigningKey) > 0 {
			checkForWeakHMAC(log, cfg.Algorithm, cfg.HMACSigningKey)
			privateKey = []byte(cfg.HMACSigningKey)
		} else if len(cfg.HMACSigningKeyFile) > 0 {
			content, err := os.ReadFile(cfg.HMACSigningKeyFile)
			if err != nil {
				log.Fatal("Could not load key file", zap.String("file", cfg.HMACSigningKeyFile), zap.Error(err))
			}
			checkForWeakHMAC(log, cfg.Algorithm, string(content))

		} else {
			log.Fatal("No HMAC key defined, either set jwt.hmac-signing-key or jwt.hmac-signing-key-file")
		}
		if len(privateKey.([]byte)) > 0 {
			var err error
			privateKeyJwk, err = jwk.FromRaw(privateKey)
			if err != nil {
				log.Fatal("Unable to process symetric key")
			}
			options = append(options, jwt.WithKey(jwa.SignatureAlgorithm(cfg.Algorithm), privateKeyJwk))
		}
	case "RS256", "RS384", "RS512":
		if len(cfg.RSAPrivateKey) > 0 {
			privateKey = []byte(cfg.RSAPrivateKey)
		} else if len(cfg.RSAPRivateKeyFile) > 0 {
			content, err := os.ReadFile(cfg.RSAPRivateKeyFile)
			if err != nil {
				log.Fatal("Could not load key file", zap.String("file", cfg.RSAPRivateKeyFile), zap.Error(err))
			}
			if len(content) == 0 {
				log.Fatal("Read empty private key file", zap.String("file", cfg.RSAPRivateKeyFile), zap.Error(err))
			}
			privateKey = content
		} else {
			log.Fatal("No RSA private key defined, either set jwt.rsa-private-key or jwt.rsa-private-key-file")
		}
		var err error
		privateKey, err = parseRSAPrivateKey(privateKey.([]byte))
		if err != nil {
			log.Fatal("Unable to process suplied private key", zap.Error(err))
		}
		if len(cfg.RSAPublicKey) > 0 {
			publicKey = []byte(cfg.RSAPublicKey)
		} else if len(cfg.RSAPRivateKeyFile) > 0 {
			content, err := os.ReadFile(cfg.RSAPublicKeyFile)
			if err != nil {
				log.Fatal("Could not load key file", zap.String("file", cfg.RSAPublicKeyFile), zap.Error(err))
			}
			publicKey = content
		} else {
			log.Fatal("No RSA private key defined, either set jwt.rsa-public-key or jwt.rsa-public-key-file")
		}
		kid = fmt.Sprintf("%x", crc32.Checksum(publicKey.([]byte), crc32.IEEETable))
		pubParsed, err := parseRSAPublicKey(publicKey.([]byte))
		if err != nil {
			log.Fatal("Unable to process supllied public key", zap.Error(err))
		}
		privateKey.(*rsa.PrivateKey).PublicKey = *pubParsed
		privateKeyJwk, err = jwk.FromRaw(privateKey)
		if err != nil {
			log.Fatal("Unable to process private key")
		}
		publicKeyJwk, err = jwk.FromRaw(pubParsed)
		if err != nil {
			log.Fatal("Unable to process public key")
		}
		publicKeyJwk.Set("alg", cfg.Algorithm)
		publicKeyJwk.Set("use", "sig")
		publicKeyJwk.Set("kid", kid)
		privateKeyJwk.Set("kid", kid)
		sha, err := publicKeyJwk.Thumbprint(crypto.SHA1)
		if err == nil {
			publicKeyJwk.Set("x5t", b64.StdEncoding.EncodeToString(sha))
		}

		options = append(options, jwt.WithKey(jwa.SignatureAlgorithm(cfg.Algorithm), publicKeyJwk))

	default:
		log.Fatal("Invalid jwt.alg defined. Possible values: HS256,HS384,HS512,RS256,RS384,RS512")
	}
	privateKeyJwk.Set("alg", cfg.Algorithm)
	privateKeyJwk.Set("use", "sig")
	sha, err := privateKeyJwk.Thumbprint(crypto.SHA1)
	if err == nil {
		privateKeyJwk.Set("x5t", b64.StdEncoding.EncodeToString(sha))
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

func (t *TokenIssuer) Audience() []string {
	return t.aud
}

func (t *TokenIssuer) Issuer() string {
	return t.iss
}

func (t *TokenIssuer) RememberMeDuration() time.Duration {
	return t.rememberMeDuration
}

func (t *TokenIssuer) IssueRememberMeToken(ctx context.Context, authorizationID uuid.UUID) (string, error) {
	gen := generator.New()
	token := gen.CreateSecureTokenWithSize(64)
	_, err := t.tokenStorage.InsertCommonToken(ctx, authorizationID, string(RememberMeTokenType), string(token), time.Now().Add(t.rememberMeDuration), tables.MapStructure{})
	if err != nil {
		return "", err
	}
	return string(token), nil
}

func (t *TokenIssuer) IssueRefreshToken(ctx context.Context, authorizationID uuid.UUID) (string, error) {
	gen := generator.New()
	token := gen.CreateSecureToken()
	_, err := t.tokenStorage.InsertCommonToken(ctx, authorizationID, string(RefreshTokenType), string(token), time.Now().Add(t.refreshTokenExpiry), tables.MapStructure{})
	if err != nil {
		return "", err
	}
	return string(token), nil
}

func (t *TokenIssuer) IssueAuthorizationCode(ctx context.Context, authorizationID uuid.UUID, codeChallenge string, codeChallengeMethod string) (string, error) {
	gen := generator.New()
	token := gen.CreateSecureToken()
	_, err := t.tokenStorage.InsertCommonToken(ctx,
		authorizationID,
		string(AuthorizationCodeType),
		string(token),
		time.Now().Add(t.refreshTokenExpiry),
		tables.MapStructure{"code_challenge": codeChallenge, "code_challenge_method": codeChallengeMethod})
	if err != nil {
		return "", err
	}
	return string(token), nil
}

func (t *TokenIssuer) IssueAccessTokenForMachineClient(clientID string, scopes []string) (jwt.Token, error) {
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
func (t *TokenIssuer) IssueAccessTokenForUser(user *user.SignedInUser, authorizationID uuid.UUID, clientID string, scopes []string) (jwt.Token, error) {
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
func (t *TokenIssuer) IssueNetlifyAccessTokenForUser(user *user.SignedInUser, authorizationID uuid.UUID, clientID string, scopes []string) (jwt.Token, error) {
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
	case "HS256", "HS384", "HS512":
		set := jwk.NewSet()
		set.AddKey(t.PrivateKey())
		return set, nil
	case "RS256", "RS384", "RS512":
		set := jwk.NewSet()
		set.AddKey(t.PrivateKey())
		set.AddKey(t.PublicKey())
		return set, nil
	}
	return nil, errors.New("unknown algorithm")
}

func (t *TokenIssuer) AsPublicOnlyJWKSet() (jwk.Set, error) {
	switch t.Alg() {
	case "HS256", "HS384", "HS512":
		set := jwk.NewSet()

		return set, nil
	case "RS256", "RS384", "RS512":
		set := jwk.NewSet()
		key, err := t.PublicKey().PublicKey()
		if err != nil {
			return nil, err
		}
		set.AddKey(key)
		return set, nil
	}
	return nil, errors.New("unknown algorithm")
}
