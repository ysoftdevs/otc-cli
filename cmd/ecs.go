package cmd

import (
	"github.com/spf13/cobra"
)

// ecsCmd represents the ecs command
var ecsCmd = &cobra.Command{
	Use:   "ecs",
	Short: "Elastic Cloud Server (ECS) management",
}

func init() {
	rootCmd.AddCommand(ecsCmd)
}
