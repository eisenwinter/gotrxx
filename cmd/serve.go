package cmd

import (
	"context"
	"os"

	"github.com/eisenwinter/gotrxx/api"
	"github.com/eisenwinter/gotrxx/application"
	"github.com/eisenwinter/gotrxx/authorization"
	"github.com/eisenwinter/gotrxx/manage"
	"github.com/eisenwinter/gotrxx/tokens"
	"github.com/eisenwinter/gotrxx/user"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var autoSeedAdminInvite string

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
		issuer := tokens.NewIssuer(
			TopLevelLogger.WithGroup("token_issuer"),
			LoadedConfig.JWT,
			dataStore,
		)

		//setup mailer
		mailer := mustResolveMailer(registry)

		//events dispatcher
		dispatcher := bootstrapDispatcher(dataStore.Auditor())

		//setup management services
		userManager := manage.NewUserService(
			dataStore,
			TopLevelLogger.WithGroup("user_manager"),
			LoadedConfig,
			mailer,
			dispatcher,
		)

		//check if auto invite seed is configured
		if autoSeedAdminInvite != "" {
			roles := make([]string, 0)
			roles = append(roles, "admin")
			if LoadedConfig.Behaviour.InviteOnly && *LoadedConfig.Behaviour.InviteRole != "" {
				roles = append(roles, *LoadedConfig.Behaviour.InviteRole)
			}
			err := userManager.InitialUserInvite(
				context.Background(),
				autoSeedAdminInvite,
				roles,
				[]int{},
			)
			if err != nil {
				TopLevelLogger.Error("unable to seed initial admin invite", "err", err)
			}
		}

		authanager := manage.NewAuthorizationService(
			dataStore,
			TopLevelLogger.WithGroup("authorization_manager"),
			LoadedConfig,
			dispatcher,
		)
		appManager := manage.NewApplicationSevice(
			dataStore,
			TopLevelLogger.WithGroup("application_manager"),
			LoadedConfig,
			dispatcher,
		)
		inviteManager := manage.NewInviteService(
			dataStore,
			TopLevelLogger.WithGroup("invite_manager"),
			dispatcher,
		)
		roleManager := manage.NewRoleService(
			dataStore,
			TopLevelLogger.WithGroup("role_manager"),
			dispatcher,
		)
		//setup business services
		signInService := user.NewSignInService(
			dataStore,
			TopLevelLogger.WithGroup("signin_service"),
			LoadedConfig.Behaviour,
			dispatcher,
			userManager,
		)
		userService := user.New(
			dataStore,
			TopLevelLogger.WithGroup("user_service"),
			LoadedConfig,
			mailer,
			dispatcher,
			userManager,
		)

		//setup token rotator
		rotator := tokens.NewRotator(dataStore, dispatcher, TopLevelLogger.WithGroup("token_rotator"))

		appService := application.NewApplicationSevice(
			TopLevelLogger.WithGroup("application_service"),
			dataStore,
		)

		authService := authorization.NewAuthorizationService(
			TopLevelLogger.WithGroup("authorization_service"),
			dataStore,
			dispatcher,
			appService,
		)

		//setup token verifier
		verifier := tokens.NewTokenVerifier(
			TopLevelLogger.WithGroup("token_verifier"),
			issuer,
			dataStore,
			authService,
		)

		server, err := api.NewServer(LoadedConfig, TopLevelLogger.WithGroup("server"),
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
			TopLevelLogger.Error("failed to create server", "err", err)
			panic("failed to create server")
		}
		server.Start()
		TopLevelLogger.Info("shutdown complete")
	},
}

func init() {
	viper.SetDefault("port", "3000")
	viper.SetDefault("log_level", "debug")

	serveCommand.Flags().
		StringVar(&autoSeedAdminInvite, "auto-seed-invite", "", "if defined seeds the given invite code for an admin account")
	if autoSeedAdminInvite == "" {
		// check for container specific env variable
		if r := os.Getenv("TRXX_AUTO_SEED_INVITE"); r != "" {
			autoSeedAdminInvite = r
		}
	}
}
