package cmd

import (
	"fmt"
	"otc-cli/services/cce"
	"github.com/spf13/cobra"
)

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config <cluster-name>",
	Args:  cobra.ExactArgs(1),
	Short: "Print a kubeconfig for a CCE cluster",
	Run: func(cmd *cobra.Command, args []string) {
		commonConfig, err := ParseGlobalFlags()

		if err != nil {
			fmt.Printf("Error parsing global flags: %s\n", err)
			return
		}
		if err := cce.Config(commonConfig, args[0]); err != nil {
			fmt.Printf("Error printing kubeconfig for CCE cluster '%s': %s\n", args[0], err)
		}
	},
}

func init() {
	cceCmd.AddCommand(configCmd)
}
