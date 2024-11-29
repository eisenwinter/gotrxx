package main

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"os"

	"log/slog"

	"github.com/eisenwinter/gotrxx/cmd"
	"github.com/eisenwinter/gotrxx/config"
	"github.com/eisenwinter/gotrxx/pkg/logging"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/safehtml/template"
	_ "github.com/jackc/pgx/v4"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

//go:embed templates/static
//go:embed templates/i18n
//go:embed templates/email/template.html
var templateContent embed.FS

//go:embed templates/pages/404.html
//go:embed templates/pages/change_email.html
//go:embed templates/pages/change_password.html
//go:embed templates/pages/change_mfa.html
//go:embed templates/pages/provision_mfa.html
//go:embed templates/pages/confirm.html
//go:embed templates/pages/error.html
//go:embed templates/pages/recover_password.html
//go:embed templates/pages/request_password_recovery.html
//go:embed templates/pages/signin.html
//go:embed templates/pages/signup.html
//go:embed templates/pages/user.html
//go:embed templates/pages/invite.html
var templatePages embed.FS

var (
	// Version holds the version injected by ldflags
	Version = "?"
	// BuildTime is the build time injected by ldflags
	BuildTime = "?"
	// GitCommit is the commit sha injected by ldflags
	GitCommit = "-"
	// GitRef is the git reference injected by ldflags
	GitRef = "-"
)

func main() {
	// version info - do not bootstrap whole application
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("gotrxx %s, built %s from %s (%s)", Version, BuildTime, GitCommit, GitRef)
		return
	}
	logger := bootstrap()
	cmd.TopLevelLogger = logger
	cmd.Execute()
}

func bootstrap() logging.Logger {
	if _, err := os.Stat(".env"); err == nil {
		err := godotenv.Load()
		if err != nil {
			log.Fatal("Error loading .env file")
		}
	}

	opts := &slog.HandlerOptions{}
	if r := os.Getenv("DEBUG_LOG"); r == "true" {
		// non versioned are assumed to be debug builds
		opts.Level = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, opts))
	slog.SetDefault(logger)
	if opts.Level == slog.LevelDebug {
		logger.Debug("debug logging enabled")
	}
	wrapped := logging.NewFromSlog(logger)
	cobra.OnInitialize(func() { initConfig(logger) })
	return wrapped
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

func initConfig(logger *slog.Logger) {
	bind := func(from string, to string) {
		err := viper.BindEnv(to, from)
		if err != nil {
			logger.Error(
				"unable to bindenv",
				"from", from,
				"to", to,
				"err", err,
			)
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
		logger.Debug(
			"using supplied config file",
			"file", string(cmd.ConfigFileLocation),
		)
		viper.SetConfigFile(string(cmd.ConfigFileLocation))
	} else {
		path, err := os.Getwd()
		if err != nil {
			logger.Warn("unable to get current working dir", "err", err)
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
		logger.Debug("no confg file loaded")
	} else {
		logger.Debug("config file loaded", "file", viper.ConfigFileUsed())
	}

	conf := &config.Configuration{}
	err := viper.Unmarshal(conf)
	if err != nil {
		logger.Error("unable to unmarshal config", "err", err)
		panic("unable to unmarshal config")
	}
	logger.Debug("config loaded", "config", conf)
	logger.Debug("validating final config")
	if err = conf.Validate(); err != nil {
		logger.Error("invalid configuration", "err", err)
		panic("invalid configuration")
	}
	cmd.LoadedConfig = conf

	if cmd.LoadedConfig.Server.LoadTemplateFolder {
		if _, err := os.Stat("templates"); os.IsNotExist(err) {
			logger.Error(
				"you need to add the templates folder when using `server.load-template-folder:true`",
			)
			panic("`server.load-template-folder:true` without template folder")
		}
		templates := os.DirFS("templates")
		statics, err := fs.Sub(templates, "static")
		if err != nil {
			logger.Error("unable to open templates/static folder")
			panic("unable to open templates/static")
		}
		i18n, err := fs.Sub(templates, "i18n")
		if err != nil {
			logger.Error("unable to open templates/i18n folder")
			panic("unable to open templates/i18n")
		}
		email, err := fs.Sub(templates, "email")
		if err != nil {
			logger.Error("unable to open templates/email folder")
			panic("unable to open templates/email")
		}

		src, err := template.TrustedSourceFromConstantDir(
			`templates`,
			template.TrustedSourceFromConstant(`pages`),
			``,
		)
		if err != nil {
			logger.Error("unable to open templates/pages folder")
			panic("unable to open templates/pages")
		}

		trustfs := template.TrustedFSFromTrustedSource(src)
		cmd.FileSystemsConfig = &config.FileSystems{
			StaticFolder: statics,
			I18n:         i18n,
			Email:        email,
			Pages:        trustfs,
		}
	} else {

		statics, err := fs.Sub(templateContent, "templates/static")
		if err != nil {
			logger.Error("unable to open templates/static folder")
			panic("unable to open templates/static")
		}
		i18n, err := fs.Sub(templateContent, "templates/i18n")
		if err != nil {
			logger.Error("unable to open templates/i18n folder")
			panic("unable to open templates/i18n")
		}
		email, err := fs.Sub(templateContent, "templates/email")
		if err != nil {
			logger.Error("unable to open templates/email folder")
			panic("unable to open templates/email")
		}
		pages, err := template.TrustedFSFromEmbed(templatePages).Sub(template.TrustedSourceFromConstant(`templates/pages`))
		if err != nil {
			logger.Error("unable to open templates/pages folder")
			panic("unable to open templates/pages")
		}
		cmd.FileSystemsConfig = &config.FileSystems{
			StaticFolder: statics,
			I18n:         i18n,
			Email:        email,
			Pages:        pages,
		}
	}

}
