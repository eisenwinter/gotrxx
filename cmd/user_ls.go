package cmd

import (
	"context"
	"fmt"
	"math"
	"os"
	"text/tabwriter"

	"github.com/eisenwinter/gotrxx/mailing"
	"github.com/eisenwinter/gotrxx/manage"
	"github.com/spf13/cobra"
)

var listUsersCommand = cobra.Command{
	Use:   "ls",
	Short: "Lists all users",
	Long:  `This will list all users`,
	Run: func(cmd *cobra.Command, args []string) {
		dataStore := mustResolveUsableDataStore()
		dispatcher := bootstrapDispatcher(dataStore.Auditor())
		mailer := mailing.NewNoOpMailer()
		service := manage.NewUserService(
			dataStore,
			TopLevelLogger.WithGroup("manage_application_service"),
			LoadedConfig,
			mailer,
			dispatcher)
		lst, err := service.List(context.Background(), 1, math.MaxInt, "", "")
		if err != nil {
			fmt.Printf("Unable to load users: %s", err)
			os.Exit(1)
			return
		}
		w := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
		_, _ = fmt.Fprintf(
			w,
			"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\r\n",
			"ID",
			"Email",
			"EmailConfirmed",
			"Phone",
			"PhoneConfirmed",
			"LockoutTill",
			"BannedOn",
			"Mfa",
		)
		for _, v := range lst.Entries.([]*manage.UserDTO) {
			_, _ = fmt.Fprintf(
				w,
				"%s\t%s\t%s\t%v\t%s\t%s\t%s\t%v \r\n",
				v.ID,
				v.Email,
				v.EmailConfirmed,
				v.Phone,
				v.PhoneConfirmed,
				v.LockoutTill,
				v.BannedOn,
				v.Mfa,
			)
		}

		_, _ = fmt.Fprintf(w, "------------------------------------------------- \r\n")
		_, _ = fmt.Fprintf(w, "%d entries loaded", lst.Total)
		_ = w.Flush()
	},
}
