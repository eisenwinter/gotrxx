package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

var sendTestMailCommand = cobra.Command{
	Use:   "send-test-email",
	Short: "sends a test email to verify email settings",
	Long:  `this comamnd can be used to send a test email and verify the current email setup`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("requires a receiver email addresss")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {

		//load translations
		registry := mustResolveTranslationRegistry()
		//create mailer
		mailer := mustResolveMailer(registry)
		err := mailer.SendTestEmail(args[0])
		if err != nil {
			fmt.Printf("Email sent NOT to %s because %s\r\n", args[0], err)
			return
		}
		fmt.Printf("Email sent to %s\r\n", args[0])
	},
}
