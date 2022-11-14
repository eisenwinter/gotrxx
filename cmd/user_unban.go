package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/eisenwinter/gotrxx/manage"
	"github.com/spf13/cobra"
)

var unbanUserCommand = cobra.Command{
	Use:   "unban",
	Short: "unbans a user",
	Long:  `Lifts an user ban`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 || args[0] == "" {
			return errors.New("user unban (email) - requires a email")
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
			fmt.Printf("Unable to unban user: %s", err)
			os.Exit(1)
			return
		}
		err = userManager.UnbanUser(cmd.Context(), id)
		if err != nil {
			fmt.Printf("Unable to unban user: %s", err)
			os.Exit(1)
			return
		}
		fmt.Println("Unbanned user")
	},
}
