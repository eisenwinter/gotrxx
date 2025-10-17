package cmd

import (
	"fmt"

	"github.com/eisenwinter/gotrxx/generator"
	"github.com/spf13/cobra"
)

var keySize int32 = 32

var keyCommand = cobra.Command{
	Use:   "random-key",
	Short: "generates a random key",
	Long:  `generates a cryptographic secure random key`,
	Run: func(cmd *cobra.Command, args []string) {
		key := generator.New().CreateSecureTokenWithSize(int(keySize))
		fmt.Println(key)
	},
}

func init() {
	keyCommand.Flags().Int32VarP(&keySize, "size", "s", 64, "sets key size")
}
