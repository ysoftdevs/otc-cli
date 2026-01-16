package cmd

import (
	"fmt"

	"otc-cli/services/ecs"

	"github.com/spf13/cobra"
)

// listCmd represents the list command
var ecsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List ECS servers",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		commonConfig, err := ParseGlobalFlags()
		if err != nil {
			return fmt.Errorf("error parsing global flags: %w", err)
		}
		ecsListArgs.CommonConfig = commonConfig
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return ecs.List(ecsListArgs)
	},
}

var ecsListArgs	= ecs.ListArgs{
	Filter: "",
	Limit:  0,
}

func init() {
	ecsCmd.AddCommand(ecsListCmd)

	ecsListCmd.Flags().StringVar(&ecsListArgs.Filter, "filter", ecsListArgs.Filter, "Filter servers by name")
	ecsListCmd.Flags().IntVar(&ecsListArgs.Limit, "limit", ecsListArgs.Limit, "Limit the number of servers listed")
}