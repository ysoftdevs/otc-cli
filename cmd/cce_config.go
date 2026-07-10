package cmd

import (
	"fmt"

	"github.com/ysoftdevs/otc-cli/services/cce"

	"github.com/spf13/cobra"
)

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config <cluster-name>",
	Args:  cobra.ExactArgs(1),
	Short: "Print a kubeconfig for a CCE cluster",
	RunE: func(cmd *cobra.Command, args []string) error {
		cceConfigArgs.ClusterName = args[0]

		if err := cce.Config(cceConfigArgs); err != nil {
			return fmt.Errorf("printing kubeconfig for CCE cluster '%s': %w", args[0], err)
		}
		return nil
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
