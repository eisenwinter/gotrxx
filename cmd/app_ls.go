package cmd

import (
	"context"
	"fmt"
	"math"
	"os"
	"text/tabwriter"

	"github.com/eisenwinter/gotrxx/manage"
	"github.com/spf13/cobra"
)

var listApplicationsCommand = cobra.Command{
	Use:   "ls",
	Short: "Lists all applications",
	Long:  `This will list all applications`,
	Run: func(cmd *cobra.Command, args []string) {
		dataStore := mustResolveUsableDataStore()
		dispatcher := bootstrapDispatcher(dataStore.Auditor())
		service := manage.NewApplicationSevice(
			dataStore,
			TopLevelLogger.Named("manage_application_service"),
			LoadedConfig,
			dispatcher)
		lst, err := service.List(context.Background(), 1, math.MaxInt, "", "")
		if err != nil {
			fmt.Printf("Unable to load applications: %s", err)
			os.Exit(1)
			return
		}
		w := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
		fmt.Fprintf(
			w,
			"%s\t%s\t%s\t%v\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s \r\n",
			"ID",
			"ClientID",
			"Name",
			"Confidentiality",
			"Type",
			"Status",
			"Scope",
			"Flows",
			"RedirectURIs",
			"LogoutURIs",
			"PKCE",
			"HasSecret",
		)
		for _, v := range lst.Entries.([]*manage.ApplicationDTO) {
			fmt.Fprintf(
				w,
				"%d\t%s\t%s\t%v\t%s\t%s\t%s\t%v\t%v\t%v\t%v\t%v \r\n",
				v.ID,
				v.ClientID,
				v.Name,
				v.Confidentiality,
				v.Type,
				v.Status,
				v.Scope,
				v.Flows,
				v.RedirectURIs,
				v.LogoutURIs,
				v.PKCE,
				v.HasSecret,
			)
		}

		fmt.Fprintf(w, "------------------------------------------------- \r\n")
		fmt.Fprintf(w, "%d entries loaded", lst.Total)
		w.Flush()
	},
}
