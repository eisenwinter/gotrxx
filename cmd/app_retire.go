package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/eisenwinter/gotrxx/manage"
	"github.com/spf13/cobra"
)

var retireApplicationCommand = cobra.Command{
	Use:   "retire",
	Short: "Retires an application (no one will be able to login from that application anymore)",
	Long:  `This command retires a oauth application, this means that the application will be unusable and all authorizations and tokens will be invalidated.`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 || args[0] == "" {
			return errors.New("app retire (client_id) - requires a client_id")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		dataStore := mustResolveUsableDataStore()
		dispatcher := bootstrapDispatcher(dataStore.Auditor())
		service := manage.NewApplicationSevice(
			dataStore,
			TopLevelLogger.WithGroup("manage_application_service"),
			LoadedConfig,
			dispatcher)
		err := service.RetireApplication(cmd.Context(), args[0])
		if err != nil {
			fmt.Printf("Unable to retire application: %s", err)
			os.Exit(1)
			return
		}
		fmt.Printf("Application %s has been retired", args[0])
	},
}
