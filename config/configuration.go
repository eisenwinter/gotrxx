package config

import (
	"errors"
	"io/fs"
	"os"
	"time"

	"github.com/google/safehtml/template"
)

// ServerConfiguration contains the server settings
type ServerConfiguration struct {
	Port               int
	Address            string
	CSRFToken          string `mapstructure:"csrf-token"           json:"-"`
	LoadTemplateFolder bool   `mapstructure:"load-template-folder"`
}

// SMTPConfiguration contains the email settings
type SMTPConfiguration struct {
	Enabled  bool
	Host     string
	Port     int
	Username string
	Password string `json:"-"`
	// DisplayName will be displayed as email sender
	DisplayName string `         mapstructure:"display-name"`
	// Address is the sender address
	Address string
}

// DatabaseConfiguration contains the settings required to connect to a database
type DatabaseConfiguration struct {
	Type string
	DSN  string `json:"-"`
}

// BehaviourConfiguration configures hwo the service will behave
type BehaviourConfiguration struct {
	Name                string
	Site                string
	InviteOnly          bool          `mapstructure:"invite-only"`
	InviteRole          *string       `mapstructure:"invite-role"`
	InviteExpiry        time.Duration `mapstructure:"invite-expiry"`
	AutoConfirmUsers    bool          `mapstructure:"auto-confirm-users"`
	DefaultLocale       string        `mapstructure:"default-locale"`
	AutoLockoutCount    int           `mapstructure:"auto-lockout-count"`
	AutoLockoutDuration time.Duration `mapstructure:"auto-lockout-duration"`
	PasswordMinLength   int           `mapstructure:"password-min-length"`
	ServiceDomain       string        `mapstructure:"service-domain"`
}

// JWTConfiguration habours all JWT and refresh token settings
type JWTConfiguration struct {
	FlattenAudience    bool          `mapstructure:"flatten-audience"`
	Algorithm          string        `mapstructure:"alg"`
	Issuer             string        `mapstructure:"iss"`
	Audience           []string      `mapstructure:"aud"`
	Expiry             time.Duration `mapstructure:"exp"`
	NoRolesClaim       bool          `mapstructure:"no-roles-claim"`
	HMACSigningKey     string        `mapstructure:"hmac-signing-key"      json:"-"`
	HMACSigningKeyFile string        `mapstructure:"hmac-signing-key-file"`

	RSAPrivateKey string `mapstructure:"rsa-private-key" json:"-"`
	RSAPublicKey  string `mapstructure:"rsa-public-key"  json:"-"`

	RSAPRivateKeyFile string `mapstructure:"rsa-private-key-file"`
	RSAPublicKeyFile  string `mapstructure:"rsa-public-key-file"`

	RefreshTokenExpiry time.Duration `mapstructure:"refresh-token-expiry"`
	RememberMeDuration time.Duration `mapstructure:"remember-me-duration"`
}

// FileSystems contains the used file systems
type FileSystems struct {
	StaticFolder fs.FS
	I18n         fs.FS
	Email        fs.FS
	Pages        template.TrustedFS
}

// CORSConfiguration very basic cors configuration
type CORSConfiguration struct {
	AllowCredentials bool     `mapstructure:"allow-credentials"`
	AllowedMethods   []string `mapstructure:"allowed-methods"`
	AllowedOrigins   []string `mapstructure:"allowed-origins"`
}

// ManageEndpointConfirugation habours the manage endpoitn configuration
type ManageEndpointConfirugation struct {
	Enable bool
	CORS   *CORSConfiguration
}

// Configuration habours the entire gotrxx configuration
type Configuration struct {
	Server         *ServerConfiguration         `mapstructure:"server"`
	SMTP           *SMTPConfiguration           `mapstructure:"smtp"`
	Database       *DatabaseConfiguration       `mapstructure:"database"`
	Behaviour      *BehaviourConfiguration      `mapstructure:"behaviour"`
	JWT            *JWTConfiguration            `mapstructure:"jwt"`
	ManageEndpoint *ManageEndpointConfirugation `mapstructure:"manage-endpoint"`
}

// Validate does some basic validation of the config file and tries to be helpful on missconfiguration
func (c *Configuration) Validate() error {
	if c.Database == nil {
		return errors.New("no database configuration found")
	}
	if c.SMTP == nil {
		return errors.New("no SMTP configuration found")
	}
	if c.Behaviour == nil {
		return errors.New("no behaviour configuration found")
	}
	if c.JWT == nil {
		return errors.New("no JWT configuration found")
	}
	switch c.JWT.Algorithm {
	case "HS256", "HS384", "HS512":
		if c.JWT.HMACSigningKey == "" && c.JWT.HMACSigningKeyFile == "" {
			return errors.New(
				"when using jwt.alg HS256, HS384, HS512 you need to define either hmac-signing-key or hmac-signing-key-file",
			)
		}

	case "RS256", "RS384", "RS512":
		if c.JWT.RSAPublicKey == "" && c.JWT.RSAPublicKeyFile == "" {
			return errors.New(
				"when using jwt.alg RS256, RS384, RS512 you need to define either rsa-public-key or rsa-public-key-file",
			)
		}
		if c.JWT.RSAPrivateKey == "" && c.JWT.RSAPRivateKeyFile == "" {
			return errors.New(
				"when using jwt.alg RS256, RS384, RS512 you need to define either rsa-private-key or rsa-private-key-file",
			)
		}

	}
	if c.Server == nil {
		return errors.New("no server configuration found")
	}
	if c.ManageEndpoint != nil {
		if c.ManageEndpoint.Enable && c.ManageEndpoint.CORS == nil {
			return errors.New("manage endpoint has no cors settings")
		}
	}
	if c.Server.LoadTemplateFolder {
		if _, err := os.Stat("templates"); os.IsNotExist(err) {
			return errors.New(
				"you enabled server.load-template-folder, you need to put the templates folder into your current working directory",
			)
		}
	}
	return nil
}

// DebugMode returns true if the DEBUG_MODE variable is set
func (*Configuration) DebugMode() bool {
	if r := os.Getenv("TRXX_DEBUG_MODE"); r == "true" {
		return true
	}
	return false
}
