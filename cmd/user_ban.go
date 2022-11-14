package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/eisenwinter/gotrxx/manage"
	"github.com/spf13/cobra"
)

var banUserCommand = cobra.Command{
	Use:   "ban",
	Short: "bans a user",
	Long:  `Bans a user, the specified user is prohibited from any further logins`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 || args[0] == "" {
			return errors.New("user ban (email) - requires a email")
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
			fmt.Printf("Unable to ban user: %s", err)
			os.Exit(1)
			return
		}
		err = userManager.BanUser(cmd.Context(), id)
		if err != nil {
			fmt.Printf("Unable to ban user: %s", err)
			os.Exit(1)
			return
		}
		fmt.Println("Banned user")
	},
}
