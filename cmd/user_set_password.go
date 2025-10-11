package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/eisenwinter/gotrxx/manage"
	"github.com/spf13/cobra"
)

var setUserPasswordCommand = cobra.Command{
	Use:   "set-password",
	Short: "Sets the password for a designated user, only works if enabled in config",
	Long:  `Sets the password for a designated user`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 {
			return errors.New("user set-password (email) (password) - requires email and password")
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
		if !LoadedConfig.ManageEndpoint.AdminPasswordResetEnabled {
			fmt.Printf("Manual password sets are disabled")
			os.Exit(1)
			return
		}
		id, err := userManager.EmailToID(cmd.Context(), args[0])
		if err != nil {
			fmt.Printf("Unable to set user %s password: %s", args[0], err)
			os.Exit(1)
			return
		}
		err = userManager.SetPassword(cmd.Context(), id, args[1])
		if err != nil {
			fmt.Printf("Unable to set user %s password: %s", args[0], err)
			os.Exit(1)
			return
		}
		fmt.Printf("User %s password has been set", args[0])
	},
}
