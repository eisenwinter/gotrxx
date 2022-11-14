package cmd

import (
	"github.com/spf13/cobra"
)

var tokenCommand = cobra.Command{
	Use:   "token",
	Short: "token commands",
	Long:  `this section harbors the token commands`,
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}
