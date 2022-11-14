package cmd

import (
	"github.com/eisenwinter/gotrxx/api"
	"github.com/eisenwinter/gotrxx/application"
	"github.com/eisenwinter/gotrxx/authorization"
	"github.com/eisenwinter/gotrxx/manage"
	"github.com/eisenwinter/gotrxx/tokens"
	"github.com/eisenwinter/gotrxx/user"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var serveCommand = cobra.Command{
	Use:   "serve",
	Short: "starts the http server",
	Long:  `Starts a http server and serves the service`,
	Run: func(cmd *cobra.Command, args []string) {
		//this is our composite root - might wanan shift that sommewhere else later

		//setup datastore
		dataStore := mustResolveUsableDataStore()
		//load translations
		registry := mustResolveTranslationRegistry()

		//setup token issuer
		issuer := tokens.NewIssuer(TopLevelLogger.Named("token_issuer"), LoadedConfig.JWT, dataStore)

		//setup mailer
		mailer := mustResolveMailer(registry)

		//events dispatcher
		dispatcher := bootstrapDispatcher(dataStore.Auditor())

		//setup management services
		userManager := manage.NewUserService(dataStore, TopLevelLogger.Named("user_manager"), LoadedConfig, mailer, dispatcher)
		authanager := manage.NewAuthorizationService(dataStore, TopLevelLogger.Named("authorization_manager"), LoadedConfig, dispatcher)
		appManager := manage.NewApplicationSevice(dataStore, TopLevelLogger.Named("application_manager"), LoadedConfig, dispatcher)
		inviteManager := manage.NewInviteService(dataStore, TopLevelLogger.Named("invite_manager"), dispatcher)
		roleManager := manage.NewRoleService(dataStore, TopLevelLogger.Named("role_manager"), dispatcher)
		//setup business services
		signInService := user.NewSignInService(dataStore, TopLevelLogger.Named("signin_service"), LoadedConfig.Behaviour, dispatcher, userManager)
		userService := user.New(dataStore, TopLevelLogger.Named("user_service"), LoadedConfig, mailer, dispatcher, userManager)

		//setup token rotator
		rotator := tokens.NewRotator(dataStore, dispatcher, TopLevelLogger.Named("token_rotator"))

		appService := application.NewApplicationSevice(TopLevelLogger.Named("application_service"), dataStore)

		authService := authorization.NewAuthorizationService(TopLevelLogger.Named("authorization_service"), dataStore, dispatcher, appService)

		//setup token verifier
		verifier := tokens.NewTokenVerifier(TopLevelLogger.Named("token_verifier"), issuer, dataStore, authService)

		server, err := api.NewServer(LoadedConfig, TopLevelLogger.Named("server"),
			issuer,
			rotator,
			signInService,
			userService,
			authService,
			appService,
			registry,
			FileSystemsConfig,
			verifier,
			userManager,
			authanager,
			appManager,
			roleManager,
			inviteManager,
		)
		if err != nil {
			TopLevelLogger.Fatal("Failed to create server", zap.Error(err))
		}
		server.Start()
		TopLevelLogger.Info("Shutdown complete")
	},
}

func init() {
	viper.SetDefault("port", "3000")
	viper.SetDefault("log_level", "debug")
}
