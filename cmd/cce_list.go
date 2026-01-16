package cmd

import (
	"fmt"

	"otc-cli/services/cce"
	"github.com/spf13/cobra"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List CCE clusters",
	Long: `List all Cloud Container Engine (CCE) clusters in the specified region and project.`,
	Run: func(cmd *cobra.Command, args []string) {
		commonConfig, err := ParseGlobalFlags()

		if err != nil {
			fmt.Printf("Error parsing global flags: %s\n", err)
			return
		}
		if err := cce.List(commonConfig); err != nil {
			fmt.Printf("Error listing CCE clusters: %s\n", err)
		}
	},
}

func init() {
	cceCmd.AddCommand(listCmd)
}
