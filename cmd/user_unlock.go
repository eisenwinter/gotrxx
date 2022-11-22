package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/eisenwinter/gotrxx/manage"
	"github.com/spf13/cobra"
)

var unlockUserCommand = cobra.Command{
	Use:   "unlock",
	Short: "unlocks a user",
	Long:  `Lifts temporary anti-bruteforce lock for the user`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 || args[0] == "" {
			return errors.New("unlock ban (email) - requires a email")
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
			fmt.Printf("Unable to unlock user: %s", err)
			os.Exit(1)
			return
		}
		err = userManager.UnlockUser(cmd.Context(), id)
		if err != nil {
			fmt.Printf("Unable to unlock user: %s", err)
			os.Exit(1)
			return
		}
		fmt.Println("Unlocked user")
	},
}
