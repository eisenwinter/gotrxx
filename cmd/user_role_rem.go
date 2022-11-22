package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/eisenwinter/gotrxx/manage"
	"github.com/spf13/cobra"
)

var removeRoleCommand = cobra.Command{
	Use:   "remove",
	Short: "Removes a user from the supplied role",
	Long:  `This command removes a user from the supplied role`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 {
			return errors.New("user role remove (email) (role) - requires email and role")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		dataStore := mustResolveUsableDataStore()
		dispatcher := bootstrapDispatcher(dataStore.Auditor())
		registry := mustResolveTranslationRegistry()
		mailer := mustResolveMailer(registry)
		userManager := manage.NewUserService(
			dataStore,
			TopLevelLogger.Named("user_manager"),
			LoadedConfig,
			mailer,
			dispatcher,
		)
		id, err := userManager.EmailToID(cmd.Context(), args[0])
		if err != nil {
			fmt.Printf("Unable to remove user %s from role %s: %s", args[0], args[1], err)
			os.Exit(1)
			return
		}
		err = userManager.RemoveUserFromRole(cmd.Context(), id, args[1])
		if err != nil {
			fmt.Printf("Unable to remove user %s from role %s: %s", args[0], args[1], err)
			os.Exit(1)
			return
		}
		fmt.Printf("User %s removed from role %s", args[0], args[1])
	},
}
