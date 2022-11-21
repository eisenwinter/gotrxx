package main

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"os"

	"github.com/eisenwinter/gotrxx/cmd"
	"github.com/eisenwinter/gotrxx/config"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v4"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

//go:embed templates/static
//go:embed templates/email/template.html
//go:embed templates/i18n
//go:embed templates/404.html
//go:embed templates/change_email.html
//go:embed templates/change_password.html
//go:embed templates/change_mfa.html
//go:embed templates/provision_mfa.html
//go:embed templates/confirm.html
//go:embed templates/error.html
//go:embed templates/recover_password.html
//go:embed templates/request_password_recovery.html
//go:embed templates/signin.html
//go:embed templates/signup.html
//go:embed templates/user.html
//go:embed templates/invite.html
var templates embed.FS

var (
	Version   = "?"
	BuildTime = "?"
	GitCommit = "-"
	GitRef    = "-"
)

func main() {
	//version info
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("gotrxx %s, built %s from %s (%s)", Version, BuildTime, GitCommit, GitRef)
		return
	}
	logger := bootstrap()
	defer func() {
		_ = logger.Sync()

	}()
	cmd.TopLevelLogger = logger
	cmd.Execute()
}

func bootstrap() *zap.Logger {
	if _, err := os.Stat(".env"); err == nil {
		err := godotenv.Load()
		if err != nil {
			log.Fatal("Error loading .env file")
		}
	}
	cfg := zap.NewProductionConfig()
	if r := os.Getenv("DEBUG_LOG"); r == "true" {
		cfg = zap.NewDevelopmentConfig()
	}
	logger, err := cfg.Build(zap.AddStacktrace(zap.ErrorLevel))
	if err != nil {
		log.Fatal(err)
	}
	cobra.OnInitialize(func() { initConfig(logger) })
	return logger
}

func setDefaults() {
	viper.SetDefault("server.load-template-folder", false)
	viper.SetDefault("smtp.enable", false)
	viper.SetDefault("behaviour.invite-role", "inviter")
	viper.SetDefault("behaviour.invite-expiry", "36h")
	viper.SetDefault("behaviour.default-locale", "en")
	viper.SetDefault("behaviour.auto-confirm-users", false)
	viper.SetDefault("behaviour.auto-lockout-count", 5)
	viper.SetDefault("behaviour.auto-lockout-duration", "10m")
	viper.SetDefault("behaviour.password-min-length", 6)
	viper.SetDefault("jwt.remember-me-duration", "168h")
	viper.SetDefault("jwt.flatten-audience", false)
	viper.SetDefault("jwt.exp", "900s")
	viper.SetDefault("jwt.refresh-token-expiry", "3600s")
	viper.SetDefault("jwt.jwt.no-roles-claim", true)
	viper.SetDefault("manage-endpoint.enable", false)
}

func initConfig(logger *zap.Logger) {
	bind := func(from string, to string) {
		err := viper.BindEnv(to, from)
		if err != nil {
			logger.Error("unable to bindenv", zap.String("from", from), zap.String(to, to), zap.Error(err))
		}

	}
	setDefaults()
	bind("PORT", "server.port")
	bind("ADDRESS", "server.address")

	bind("TRXX_PORT", "server.port")
	bind("TRXX_ADDRESS", "server.address")

	bind("TRXX_SERVER_CSRF_TOKEN", "server.csrf-token")
	bind("TRXX_SERVER_LOAD_TEMPLATE_FOLDER", "server.load-template-folder")

	bind("TRXX_SMTP_ENABLE", "smtp.enable")
	bind("TRXX_SMTP_HOST", "smtp.host")
	bind("TRXX_SMTP_PORT", "smtp.port")
	bind("TRXX_SMTP_USERNAME", "smtp.username")
	bind("TRXX_SMTP_PASSWORD", "smtp.password")
	bind("TRXX_SMTP_DISPLAYNAME", "smtp.display-name")
	bind("TRXX_SMTP_ADDRESS", "smtp.address")

	bind("TRXX_DATABASE_TYPE", "database.type")
	bind("TRXX_DATABASE_DSN", "database.dsn")

	bind("TRXX_BEHAVIOUR_NAME", "behaviour.name")
	bind("TRXX_BEHAVIOUR_SITE", "behaviour.site")
	bind("TRXX_BEHAVIOUR_SERVICE_DOMAIN", "behaviour.service-domain")
	bind("TRXX_BEHAVIOUR_INVITE_ONLY", "behaviour.invite-only")
	bind("TRXX_BEHAVIOUR_INVITE_ROLE", "behaviour.invite-role")
	bind("TRXX_BEHAVIOUR_INVITE_EXPIRY", "behaviour.invite-expiry")
	bind("TRXX_BEHAVIOUR_AUTO_CONFIRM_USERS", "behaviour.auto-confirm-users")
	bind("TRXX_BEHAVIOUR_DEFAULT_LOCALE", "behaviour.default-locale")
	bind("TRXX_BEHAVIOUR_AUTO_LOCKOUT_COUNT", "behaviour.auto-lockout-count")
	bind("TRXX_BEHAVIOUR_AUTO_LOCKOUT_DURATION", "behaviour.auto-lockout-duration")
	bind("TRXX_BEHAVIOUR_PASSWORD_MIN_LENGTH", "behaviour.password-min-length")

	bind("TRXX_JWT_FLATTEN_AUDIENCE", "jwt.flatten-audience")
	bind("TRXX_JWT_AUDIENCE", "jwt.aud")
	bind("TRXX_JWT_ISSUER", "jwt.iss")
	bind("TRXX_JWT_ALG", "jwt.alg")
	bind("TRXX_JWT_EXP", "jwt.exp")
	bind("TRXX_JWT_NO_ROLES_CLAIM", "jwt.no-roles-claim")
	bind("TRXX_JWT_REFRESH_EXP", "jwt.refresh-token-expiry")

	bind("TRXX_JWT_HMAC_SIGNING_KEY", "jwt.hmac-signing-key")
	bind("TRXX_JWT_HMAC_SIGNING_KEY_FILE", "jwt.hmac-signing-key-file")

	bind("TRXX_JWT_RSA_PRIVATE_KEY", "jwt.rsa-private-key")
	bind("TRXX_JWT_RSA_PRIVATE_KEY_FILE", "jwt.rsa-private-key-file")

	bind("TRXX_JWT_RSA_PUBLIC_KEY", "jwt.rsa-public-key")
	bind("TRXX_JWT_RSA_PUBLIC_KEY_FILE", "jwt.rsa-public-key-file")

	bind("TRXX_JWT_REMEMBER_ME_DURATION", "jwt.remember-me-duration")

	bind("TRXX_MANAGE_ENDPOINT_ENABLE", "manage-endpoint.enable")
	bind("TRXX_MANAGE_ENDPOINT_CORS_ALLOWED_ORIGINS", "manage-endpoint.cors.allowed-origins")
	bind("TRXX_MANAGE_ENDPOINT_CORS_ALLOWED_METHODS", "manage-endpoint.cors.allowed-methods")
	bind("TRXX_MANAGE_ENDPOINT_CORS_ALLOW_CREDENTIALS", "manage-endpoint.cors.allow-credentials")

	if cmd.ConfigFileLocation != "" {
		logger.Debug("Using supplied config file", zap.String("file", string(cmd.ConfigFileLocation)))
		viper.SetConfigFile(string(cmd.ConfigFileLocation))
	} else {
		path, err := os.Getwd()
		if err != nil {
			logger.Warn("Unable to get current working dir", zap.Error(err))
		}
		cobra.CheckErr(err)
		viper.AddConfigPath(path)
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		logger.Debug("Looking for default config file")
	}
	//precedence: environment overwrites yml
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		logger.Debug("No confg file loaded")
	} else {
		logger.Debug("Config file loaded", zap.String("file", viper.ConfigFileUsed()))
	}

	conf := &config.Configuration{}
	err := viper.Unmarshal(conf)
	if err != nil {
		logger.Fatal("Unable to unmarshall config", zap.Error(err))
	}
	logger.Debug("Config loaded", zap.Any("config", conf))
	logger.Debug("Validating final config")
	if err = conf.Validate(); err != nil {
		logger.Fatal("Invalid configuration", zap.Error(err))
	}
	cmd.LoadedConfig = conf

	if cmd.LoadedConfig.Server.LoadTemplateFolder {
		if _, err := os.Stat("/templates"); os.IsNotExist(err) {
			logger.Fatal("You need to add the templates folder when using  `server.load-template-folder:true`")
		}
		templates := os.DirFS("templates")
		statics, err := fs.Sub(templates, "static")
		if err != nil {
			logger.Fatal("Unable to open templates/static folder")
		}
		cmd.FileSystemsConfig = &config.FileSystems{
			StaticFolder: statics,
			Templates:    templates,
		}
	} else {
		statics, err := fs.Sub(templates, "templates/static")
		if err != nil {
			logger.Fatal("Unable to open templates/static folder")
		}
		cmd.FileSystemsConfig = &config.FileSystems{
			StaticFolder: statics,
			Templates:    templates,
		}
	}

}
