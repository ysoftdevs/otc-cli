package cmd

import (
	"otc-cli/services/ecs"

	"github.com/spf13/cobra"
)

// listCmd represents the list command
var startEcsCommand = &cobra.Command{
	Use:   "start <name>",
	Args:  cobra.ExactArgs(1),
	Short: "Start ECS server",
	RunE: func(cmd *cobra.Command, args []string) error {
		return ecs.StartServer(args[0], ecsListArgs.CommonConfig)
	},
}

var stopEcsCommand = &cobra.Command{
	Use:   "stop <name>",
	Args:  cobra.ExactArgs(1),
	Short: "Stop ECS server",
	RunE: func(cmd *cobra.Command, args []string) error {
		return ecs.StopServer(args[0], ecsListArgs.CommonConfig)
	},
}

func init() {
	ecsCmd.AddCommand(stopEcsCommand)
	ecsCmd.AddCommand(startEcsCommand)
}
