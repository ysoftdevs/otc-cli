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
		cceConfigArgs.ClusterName = args[0]

		if err := cce.Config(cceConfigArgs); err != nil {
			fmt.Printf("Error printing kubeconfig for CCE cluster '%s': %s\n", args[0], err)
		}
	},
}

var cceConfigArgs = cce.ConfigArgs{
	OutputPath:   "",
	CommonConfig: commonConfig,
}

func init() {
	cceCmd.AddCommand(configCmd)
	configCmd.Flags().StringVar(&cceConfigArgs.OutputPath, "output", cceConfigArgs.OutputPath, "Path to write the kubeconfig file. If not specified, prints to stdout.")
}
