package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/eisenwinter/gotrxx/manage"
	"github.com/eisenwinter/gotrxx/user"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var userCreateCommand = cobra.Command{
	Use:   "create",
	Short: "launches a on terminal user creation dialog",
	Long:  `this command may be used to create a user account from command line`,
	Run: func(cmd *cobra.Command, args []string) {
		dataStore := mustResolveUsableDataStore()
		dispatcher := bootstrapDispatcher(dataStore.Auditor())
		registry := mustResolveTranslationRegistry()
		mailer := mustResolveMailer(registry)
		userManager := manage.NewUserService(
			dataStore,
			TopLevelLogger.Named("user_manager"),
			LoadedConfig,
			mailer,
			dispatcher,
		)
		reader := bufio.NewReader(os.Stdin)

		trimmed := ""
		if trimmed == "" {
			fmt.Println("email?")
			email, err := reader.ReadString('\n')
			if err != nil {
				fmt.Printf("Unable to read email: %s", err)
				os.Exit(1)
				return
			}
			trimmed = strings.Trim(email, " \t\r\n")
		}

		fmt.Println("password?")
		pwd, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Printf("Unable to read password: %s", err)
			os.Exit(1)
			return
		}
		for len(pwd) < LoadedConfig.Behaviour.PasswordMinLength {
			fmt.Printf(
				"password needs to be at least %d long.\r\n",
				LoadedConfig.Behaviour.PasswordMinLength,
			)
			fmt.Println("password?")
			pwd, err = term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				fmt.Printf("Unable to read password: %s", err)
				os.Exit(1)
				return
			}
		}
		//allow to register regardless of settings
		LoadedConfig.Behaviour.InviteOnly = false
		//auto confirm CLI users
		LoadedConfig.Behaviour.AutoConfirmUsers = true
		us := user.New(
			dataStore,
			TopLevelLogger.Named("user_service"),
			LoadedConfig,
			mailer,
			dispatcher,
			userManager,
		)
		id, err := us.RegisterUser(cmd.Context(), trimmed, string(pwd), nil)
		if err != nil {
			fmt.Printf("Unable to create user: %s \r\n", err)
			os.Exit(1)
			return
		}
		fmt.Printf("Created user for email %s with id: %v", trimmed, id)
	},
}
