package cmd

import (
	"github.com/spf13/cobra"
)

var userCommand = cobra.Command{
	Use:   "user",
	Short: "user commands",
	Long:  `this section harbors the user commands`,
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}
