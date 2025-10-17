package cmd

import (
	"github.com/spf13/cobra"
)

var verifyCommand = cobra.Command{
	Use:   "verify",
	Short: "verification commands",
	Long:  `this section harbors the verification commands`,
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}
