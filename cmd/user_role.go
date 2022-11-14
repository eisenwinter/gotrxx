package cmd

import (
	"github.com/spf13/cobra"
)

var roleCommand = cobra.Command{
	Use:   "role",
	Short: "user role commands",
	Long:  `this section harbors the user role commands`,

	Run: func(cmd *cobra.Command, args []string) {

		_ = cmd.Help()
	},
}
