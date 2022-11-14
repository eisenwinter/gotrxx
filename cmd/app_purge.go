package cmd

import (
	"fmt"
	"os"

	"github.com/eisenwinter/gotrxx/manage"
	"github.com/spf13/cobra"
)

var purgeApplicationCommand = cobra.Command{
	Use:   "purge",
	Short: "Purge removes all retired application data",
	Long:  `This will remove all application data of retired applications - everything besides audit logs`,
	Run: func(cmd *cobra.Command, args []string) {
		dataStore := mustResolveUsableDataStore()
		dispatcher := bootstrapDispatcher(dataStore.Auditor())
		service := manage.NewApplicationSevice(
			dataStore,
			TopLevelLogger.Named("manage_application_service"),
			LoadedConfig,
			dispatcher)
		err := service.PurgeRetiredApplications(cmd.Context())
		if err != nil {
			fmt.Printf("Unable to purge retired application: %s", err)
			os.Exit(1)
			return
		}
		fmt.Println("Retired applications have been purged")
	},
}
