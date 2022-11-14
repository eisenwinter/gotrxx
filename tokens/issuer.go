package tokens

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/eisenwinter/gotrxx/config"
	"github.com/eisenwinter/gotrxx/db/tables"
	"github.com/eisenwinter/gotrxx/generator"
	"github.com/eisenwinter/gotrxx/user"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
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
)

type CommonTokenInserter interface {
	InsertCommonToken(ctx context.Context, authorizationID uuid.UUID, tokenType string, token string, expires time.Time, properties tables.MapStructure) (int, error)
}

type TokenIssuer struct {
	log                *zap.Logger
	privateKey         interface{}
	publicKey          interface{}
	alg                jwa.SignatureAlgorithm
	aud                []string
	expiry             time.Duration
	iss                string
	noRoles            bool
	refreshTokenExpiry time.Duration
	tokenStorage       CommonTokenInserter
	parseOptions       []jwt.ParseOption
	rememberMeDuration time.Duration
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
			privateKey = content
		} else {
			log.Fatal("No HMAC key defined, either set jwt.hmac-signing-key or jwt.hmac-signing-key-file")
		}
		if len(privateKey.([]byte)) > 0 {
			options = append(options, jwt.WithVerify(jwa.SignatureAlgorithm(cfg.Algorithm), privateKey))
		}
	case "RS256", "RS384", "RS512":
		if len(cfg.RSAPrivateKey) > 0 {
			privateKey = []byte(cfg.RSAPrivateKey)
		} else if len(cfg.RSAPRivateKeyFile) > 0 {
			content, err := os.ReadFile(cfg.RSAPRivateKeyFile)
			if err != nil {
				log.Fatal("Could not load key file", zap.String("file", cfg.RSAPRivateKeyFile), zap.Error(err))
			}
			privateKey = content
		} else {
			log.Fatal("No RSA private key defined, either set jwt.rsa-private-key or jwt.rsa-private-key-file")
		}
		var err error
		privateKey, err = parseRSAPrivateKey(privateKey.([]byte))
		if err != nil {
			log.Fatal("Unable to process supllied private key", zap.Error(err))
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
		pubParsed, err := parseRSAPublicKey(publicKey.([]byte))
		if err != nil {
			log.Fatal("Unable to process supllied public key", zap.Error(err))
		}
		privateKey.(*rsa.PrivateKey).PublicKey = *pubParsed
		publicKey = pubParsed
		options = append(options, jwt.WithVerify(jwa.SignatureAlgorithm(cfg.Algorithm), pubParsed))

	default:
		log.Fatal("Invalid jwt.alg defined. Possible values: HS256,HS384,HS512,RS256,RS384,RS512")
	}

	return &TokenIssuer{
		log:                log,
		alg:                jwa.SignatureAlgorithm(cfg.Algorithm),
		privateKey:         privateKey,
		aud:                cfg.Audience,
		expiry:             cfg.Expiry,
		iss:                cfg.Issuer,
		noRoles:            cfg.NoRolesClaim,
		refreshTokenExpiry: cfg.RefreshTokenExpiry,
		rememberMeDuration: cfg.RememberMeDuration,
		tokenStorage:       storage,
		parseOptions:       options,
		publicKey:          publicKey,
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

func (t *TokenIssuer) Sign(token jwt.Token) ([]byte, error) {
	return jwt.Sign(token, t.alg, t.privateKey)
}

func (t *TokenIssuer) Alg() string {
	return string(t.alg)
}

func (t *TokenIssuer) PrivateKey() interface{} {
	return t.privateKey
}

func (t *TokenIssuer) PublicKey() interface{} {
	return t.publicKey
}

func (t *TokenIssuer) AsJWKSet() (jwk.Set, error) {
	switch t.Alg() {
	case "HS256", "HS384", "HS512":
		set := jwk.NewSet()
		priv, err := jwk.New(t.PrivateKey())
		if err != nil {
			return nil, err
		}
		set.Add(priv)
		return set, nil
	case "RS256", "RS384", "RS512":
		set := jwk.NewSet()
		priv, err := jwk.New(t.PrivateKey())
		if err != nil {
			return nil, err
		}
		set.Add(priv)
		pub, err := jwk.New(t.PublicKey())
		if err != nil {
			return nil, err
		}
		set.Add(pub)
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
		pub, err := jwk.New(t.PublicKey())
		if err != nil {
			return nil, err
		}
		set.Add(pub)
		return set, nil
	}
	return nil, errors.New("unknown algorithm")
}
