package cmd

import (
	"fmt"
	"os"

	"github.com/eisenwinter/gotrxx/config"
	"github.com/eisenwinter/gotrxx/pkg/logging"
	"github.com/spf13/cobra"
)

// ConfigFileLocation is of the config to load
var ConfigFileLocation string

// TopLevelLogger is the logger all loggers come from
var TopLevelLogger logging.Logger

// LoadedConfig is the currently loaded configuration after initial bootstrapping
var LoadedConfig *config.Configuration

// FileSystemsConfig consists of the filesystems to use (either local or embed)
var FileSystemsConfig *config.FileSystems

var rootCommand = cobra.Command{
	Use:   "gotrxx",
	Short: "gotrxx a JWT token service",
	Long: `gotrxx is a gotrue api-compatible jwt token service,
	For more information visit https://github.com/eisenwinter/gotrxx`,
	Run: func(cmd *cobra.Command, args []string) {
		serveCommand.Run(cmd, args)
	},
}

func Execute() {
	if err := rootCommand.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {

	rootCommand.PersistentFlags().
		StringVar(&ConfigFileLocation, "config", "", "config file to be used")

	verifyCommand.AddCommand(&sendTestMailCommand)

	applicationCommand.AddCommand(&createApplicationCommand)
	applicationCommand.AddCommand(&retireApplicationCommand)
	applicationCommand.AddCommand(&purgeApplicationCommand)
	applicationCommand.AddCommand(&listApplicationsCommand)

	authorizationCommand.AddCommand(&grantAuthorizationCommand)
	authorizationCommand.AddCommand(&revokeAuthorizationCommand)

	roleCommand.AddCommand(&addRoleCommand)
	roleCommand.AddCommand(&removeRoleCommand)

	userCommand.AddCommand(&roleCommand)
	userCommand.AddCommand(&confirmUserCommand)
	userCommand.AddCommand(&banUserCommand)
	userCommand.AddCommand(&unbanUserCommand)
	userCommand.AddCommand(&unlockUserCommand)
	userCommand.AddCommand(&userCreateCommand)

	inviteCommand.AddCommand(&seedInviteCommand)
	inviteCommand.AddCommand(&listInvitesCommand)

	tokenIssueCommand.AddCommand(&tokenIssueAccessTokenCommand)
	tokenCommand.AddCommand(&tokenIssueCommand)

	rootCommand.AddCommand(&verifyCommand)
	rootCommand.AddCommand(&inviteCommand)
	rootCommand.AddCommand(&userCommand)
	rootCommand.AddCommand(&authorizationCommand)
	rootCommand.AddCommand(&applicationCommand)
	rootCommand.AddCommand(&serveCommand)
	rootCommand.AddCommand(&keyCommand)
	rootCommand.AddCommand(&tokenCommand)
}
