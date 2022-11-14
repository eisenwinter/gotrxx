package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/eisenwinter/gotrxx/manage"
	"github.com/spf13/cobra"
)

var authorizationGrantScope string

var grantAuthorizationCommand = cobra.Command{
	Use:   "grant",
	Short: "Grats a application authorization to a user",
	Long:  `This command will grant an authorization to a user to use an application.`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 || args[0] == "" {
			return errors.New("auth grant (client_id) (email) - requires an application client_id and a user email")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		dataStore := mustResolveUsableDataStore()
		dispatcher := bootstrapDispatcher(dataStore.Auditor())
		service := manage.NewAuthorizationService(
			dataStore,
			TopLevelLogger.Named("manage_authorization_service"),
			LoadedConfig,
			dispatcher)
		userManager := manage.NewUserService(dataStore, TopLevelLogger.Named("user_manager"), LoadedConfig, nil, dispatcher)

		id, err := userManager.EmailToId(cmd.Context(), args[1])
		if err != nil {
			fmt.Printf("Unable to load user: %s", err)
			os.Exit(1)
			return
		}
		err = service.GrantAuthorization(cmd.Context(), id, args[0], authorizationGrantScope)
		if err != nil {
			fmt.Printf("Unable to create authorization: %s", err)
			os.Exit(1)
			return
		}
		fmt.Printf("Authorization created for user %s to use application %s with scope %s", args[1], args[0], authorizationGrantScope)
	},
}

func init() {
	grantAuthorizationCommand.Flags().StringVarP(&authorizationGrantScope, "scope", "o", "", "authorization scopes separated by spaces")
}
