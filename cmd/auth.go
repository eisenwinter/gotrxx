package cmd

import (
	"github.com/spf13/cobra"
)

var authorizationCommand = cobra.Command{
	Use:   "auth",
	Short: "authorization commands",
	Long:  `this section harbors the authorization commands`,
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}
