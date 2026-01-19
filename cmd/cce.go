package cmd

import (
	"github.com/spf13/cobra"
)

// cceCmd represents the cce command
var cceCmd = &cobra.Command{
	Use:   "cce",
	Short: "Cloud Container Engine (CCE) management",
}

func init() {
	rootCmd.AddCommand(cceCmd)
}
