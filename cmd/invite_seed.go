package cmd

import (
	"context"
	"fmt"
	"log"

	"github.com/eisenwinter/gotrxx/manage"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var roles []string

var seedInviteCommand = cobra.Command{
	Use:   "seed",
	Short: "generates a invite code for a user",
	Long:  `this can and may be used to seed a initial invite code for a user`,
	Run: func(cmd *cobra.Command, args []string) {
		//this is our composite root - might wanan shift that sommewhere else later

		//setup datastore
		dataStore := mustResolveUsableDataStore()
		//load translations
		registry := mustResolveTranslationRegistry()
		//setup mailer
		mailer := mustResolveMailer(registry)
		//events dispatcher
		dispatcher := bootstrapDispatcher(dataStore.Auditor())

		//setup base service
		baseService := manage.NewUserService(
			dataStore,
			TopLevelLogger.Named("gotrxx"),
			LoadedConfig,
			mailer,
			dispatcher,
		)
		inviteToken, err := baseService.InviteUser(context.Background(), nil, roles, []int{1})
		if err != nil {
			log.Fatal("could not generate invite", zap.Error(err))
		}
		fmt.Printf("Your new invite token is %s", inviteToken)
	},
}

func init() {
	seedInviteCommand.Flags().
		StringSliceVar(&roles, "role", []string{}, "append --role for each role you want to add (for example --role admin --role inviter)")
}
