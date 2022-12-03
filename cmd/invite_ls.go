package cmd

import (
	"context"
	"fmt"
	"math"
	"os"
	"text/tabwriter"
	"time"

	"github.com/eisenwinter/gotrxx/db"
	"github.com/spf13/cobra"
)

var listInvitesCommand = cobra.Command{
	Use:   "ls",
	Short: "Lists all invites",
	Long:  `This will list all invites`,
	Run: func(cmd *cobra.Command, args []string) {
		//setup datastore
		dataStore := mustResolveUsableDataStore()
		entries, total, err := dataStore.Invites(context.Background(), db.ListOptions{
			Page:     1,
			PageSize: math.MaxInt,
		})
		if err != nil {
			fmt.Printf("Unable to load invites: %s", err)
			os.Exit(1)
			return
		}
		w := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s \r\n", "ID", "Email", "Code", "ConsumedAt", "CreatedAt", "ExpiresAt", "SentAt")
		formatDt := func(t *time.Time) string {
			if t != nil {
				return t.Format("2006-02-01")
			}
			return "-"
		}
		for _, v := range entries {
			e := ""
			if v.Email != nil {
				e = *v.Email
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s \r\n", v.ID, e, v.Code, formatDt(v.ConsumedAt), formatDt(&v.CreatedAt), formatDt(&v.ExpiresAt), formatDt(v.SentAt))
		}
		fmt.Fprintf(w, "------------------------------------------------- \r\n")
		fmt.Fprintf(w, "%d entries loaded", total)
		w.Flush()
	},
}
