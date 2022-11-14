package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/eisenwinter/gotrxx/manage"
	"github.com/spf13/cobra"
)

var applicationCreateClientSecret string
var applicationCreateName string
var applicationCreateType string
var applicationCreateConfidentiality string
var applicationCreateFlows []string
var applicationCreateScopes string
var applicationCreatePKCE bool
var applicationCreateRedirectUris []string
var applicationCreateLogoutUris []string
var applicationCrateSkipIfExists bool

var createApplicationCommand = cobra.Command{
	Use:   "create",
	Short: "Creates a new oauth application",
	Long:  `this command can be used to create a new oauth application`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 || args[0] == "" {
			return errors.New("app create (client_id) - requires a client_id")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		dataStore := mustResolveUsableDataStore()
		dispatcher := bootstrapDispatcher(dataStore.Auditor())
		service := manage.NewApplicationSevice(
			dataStore,
			TopLevelLogger.Named("manage_application_service"),
			LoadedConfig,
			dispatcher)
		fmt.Printf("Creating applicatio with client_id: %s\r\n", args[0])
		t := 0
		switch applicationCreateType {
		case "implicit_granted":
			t = 1
		case "explicit_granted":
			t = 2
		default:
			fmt.Println("invalid application type")
			return
		}

		id, err := service.CreateApplication(cmd.Context(),
			args[0],
			applicationCreateClientSecret,
			applicationCreateName,
			applicationCreateFlows,
			applicationCreateRedirectUris,
			applicationCreateLogoutUris,
			applicationCreateConfidentiality,
			applicationCreateScopes,
			t,
			applicationCreatePKCE)
		if err != nil {
			fmt.Printf("Could not create new application: %s\r\n", err)
			if applicationCrateSkipIfExists && errors.Is(manage.ErrApplicationClientIDExists, err) {
				return
			}
			os.Exit(1)
			return
		}
		fmt.Printf("Created new application with internal id: %d\r\n", id)
	},
}

func init() {
	createApplicationCommand.Flags().StringVarP(&applicationCreateClientSecret, "secret", "s", "", "the client secret for the application")
	createApplicationCommand.Flags().StringSliceVarP(&applicationCreateFlows, "flow", "f", []string{}, "the allowed grant flows for the application (authorization_code,password,client_credentials,refresh_token)")
	createApplicationCommand.Flags().StringVarP(&applicationCreateName, "name", "n", "", "the name of the application")
	createApplicationCommand.Flags().StringVarP(&applicationCreateType, "type", "t", "implicit_granted", "application type,may be either implicit_granted or explicit_granted")
	createApplicationCommand.Flags().StringVarP(&applicationCreateConfidentiality, "con", "c", "public", "application confidentiality may be public or private depending on the kind of application")
	createApplicationCommand.Flags().StringVarP(&applicationCreateScopes, "scope", "o", "", "application scopes separated by spaces")

	createApplicationCommand.Flags().StringSliceVarP(&applicationCreateRedirectUris, "redirect-url", "r", []string{}, "allowed redirect uris")
	createApplicationCommand.Flags().StringSliceVarP(&applicationCreateLogoutUris, "logout-url", "l", []string{}, "allowed logout uris")
	createApplicationCommand.Flags().BoolVarP(&applicationCreatePKCE, "pkce", "p", false, "enables proof key of exchange")
	createApplicationCommand.Flags().BoolVarP(&applicationCrateSkipIfExists, "skip-if-exists", "k", false, "skips creation if client_id already exists and returns no error code")
	//createApplicationCommand.MarkFlagRequired("type")
}
