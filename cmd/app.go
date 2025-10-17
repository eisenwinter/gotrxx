package cmd

import (
	"github.com/spf13/cobra"
)

var applicationCommand = cobra.Command{
	Use:   "app",
	Short: "application commands",
	Long:  `this section harbors the application commands`,
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}
