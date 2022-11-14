package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/eisenwinter/gotrxx/manage"
	"github.com/spf13/cobra"
)

var confirmUserCommand = cobra.Command{
	Use:   "confirm",
	Short: "sets a user to confirmed",
	Long:  `This command sets a user account to confirmed regardless of their confirmation status`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 || args[0] == "" {
			return errors.New("user confirm (email) - requires a email")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		dataStore := mustResolveUsableDataStore()
		dispatcher := bootstrapDispatcher(dataStore.Auditor())
		registry := mustResolveTranslationRegistry()
		mailer := mustResolveMailer(registry)
		userManager := manage.NewUserService(dataStore, TopLevelLogger.Named("user_manager"), LoadedConfig, mailer, dispatcher)
		id, err := userManager.EmailToId(cmd.Context(), args[0])
		if err != nil {
			fmt.Printf("Unable to confirm user %s: %s", args[0], err)
			os.Exit(1)
			return
		}
		err = userManager.ConfirmUser(cmd.Context(), id)
		if err != nil {
			fmt.Printf("Unable to confirm user %s: %s", args[0], err)
			os.Exit(1)
			return
		}
		fmt.Printf("User %s has been confirmed", args[0])
	},
}
