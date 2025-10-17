package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/eisenwinter/gotrxx/manage"
	"github.com/spf13/cobra"
)

var addRoleCommand = cobra.Command{
	Use:   "add",
	Short: "Adds a user to the supplied role",
	Long:  `This command adds a user to the supplied role`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 {
			return errors.New("user role add (email) (role) - requires email and role")
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
			TopLevelLogger.WithGroup("user_manager"),
			LoadedConfig,
			mailer,
			dispatcher,
		)
		id, err := userManager.EmailToID(cmd.Context(), args[0])
		if err != nil {
			fmt.Printf("Unable to add user %s to role %s: %s", args[0], args[1], err)
			os.Exit(1)
			return
		}
		err = userManager.AddUserToRole(cmd.Context(), id, args[1])
		if err != nil {
			fmt.Printf("Unable to add user %s to role %s: %s", args[0], args[1], err)
			os.Exit(1)
			return
		}
		fmt.Printf("User %s added to role %s", args[0], args[1])
	},
}
