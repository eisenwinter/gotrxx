package cmd

import (
	"github.com/spf13/cobra"
)

var tokenIssueCommand = cobra.Command{
	Use:   "issue",
	Short: "issues a token to the command line, mainly used for testing",
	Long:  `issues a token to the command line, mainly used for testing`,
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}

func init() {

}
