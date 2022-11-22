package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/eisenwinter/gotrxx/manage"
	"github.com/spf13/cobra"
)

var revokeAuthorizationCommand = cobra.Command{
	Use:   "revoke",
	Short: "Revokes a application authorization from user",
	Long:  `This command will revoke an authorization for a user to use an application.`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 || args[0] == "" {
			return errors.New(
				"auth revoke (client_id) (email) - requires an application client_id and email",
			)
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

		err := service.RevokeAuthorizationClientIDAndEmail(cmd.Context(), args[0], args[1])
		if err != nil {
			fmt.Printf("Unable to revoke authorization: %s", err)
			os.Exit(1)
			return
		}
		fmt.Printf(
			"Authorization revoekd for user %s to use application %s with scope %s",
			args[1],
			args[0],
			authorizationGrantScope,
		)
	},
}
