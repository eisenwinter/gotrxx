package cmd

import (
	"github.com/spf13/cobra"
)

var inviteCommand = cobra.Command{
	Use:   "invite",
	Short: "user invite commands",
	Long:  `this section harbors the invite commands`,
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}
