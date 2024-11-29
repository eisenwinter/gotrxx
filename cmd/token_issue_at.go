package cmd

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/eisenwinter/gotrxx/application"
	"github.com/eisenwinter/gotrxx/authorization"
	"github.com/eisenwinter/gotrxx/db"
	"github.com/eisenwinter/gotrxx/manage"
	"github.com/eisenwinter/gotrxx/tokens"
	"github.com/eisenwinter/gotrxx/user"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var tokenIssueAccessTokenCommand = cobra.Command{
	Use:   "access-token",
	Short: "issues a access token (jwt) for user [client_id] [user]",
	Long:  `this command can be used to issue a new access token for a given user and a given application`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		dataStore := mustResolveUsableDataStore()

		ud, err := dataStore.UserByEmail(cmd.Context(), args[1])
		if err != nil {
			if errors.Is(db.ErrNotFound, err) {
				fmt.Printf("User not found: %s\r\n", args[1])
				return
			}
			fmt.Printf("Unable to retrive user: %s\r\n", err)
			return
		}

		dispatcher := bootstrapDispatcher(dataStore.Auditor())
		appService := application.NewApplicationSevice(
			TopLevelLogger.WithGroup("application_service"),
			dataStore,
		)
		service := authorization.NewAuthorizationService(
			TopLevelLogger.WithGroup("authorization_service"),
			dataStore,
			dispatcher,
			appService,
		)
		registry := mustResolveTranslationRegistry()
		mailer := mustResolveMailer(registry)
		userManager := manage.NewUserService(
			dataStore,
			TopLevelLogger.WithGroup("user_manager"),
			LoadedConfig,
			mailer,
			dispatcher,
		)
		signInService := user.NewSignInService(
			dataStore,
			TopLevelLogger.WithGroup("signin_service"),
			LoadedConfig.Behaviour,
			dispatcher,
			userManager,
		)

		pwd := []byte{}
		for len(pwd) == 0 {
			fmt.Println("password?")
			pwd, err = term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				fmt.Printf("Unable to read password: %s", err)
				os.Exit(1)
				return
			}
		}

		signedIn, err := signInService.SignIn(cmd.Context(), ud.Email, string(pwd))
		if err != nil {
			fmt.Printf("Unable to sign user in: %s", err)
			os.Exit(1)
			return
		}
		auth, err := service.VerifyUserAuthorization(cmd.Context(), signedIn.UserID, args[0])
		if err != nil {
			if errors.Is(authorization.ErrUngrantedImplicitAutoGrant, err) {
				auth, err = service.ImplicitAuthorization(cmd.Context(), ud.ID, args[0], "")
				if err != nil {
					fmt.Printf("Grantig implicit authorization failed: %v\r\n", err)
					return
				}
			} else {
				fmt.Printf("Could not verify user authorization: %s\r\n", err)
				return
			}
		}

		issuer := tokens.NewIssuer(
			TopLevelLogger.WithGroup("token_issuer"),
			LoadedConfig.JWT,
			dataStore,
		)
		token, err := issuer.IssueAccessTokenForUser(&user.SignedInUser{
			UserID: ud.ID,
			Email:  ud.Email,
			Roles:  ud.Roles,
		}, auth.ID(), auth.Application().ClientID(), auth.Scopes())
		if err != nil {
			fmt.Printf("Could not create new token: %s\r\n", err)
			return
		}
		signed, err := issuer.Sign(token)
		if err != nil {
			fmt.Printf("Could not sign new token: %s\r\n", err)
			return
		}

		fmt.Printf("Created new access token: %v\r\n", string(signed))
	},
}

func init() {

}
