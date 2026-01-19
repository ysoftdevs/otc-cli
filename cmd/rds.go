package cmd

import (
	"github.com/spf13/cobra"
)

// rdsCmd represents the rds command
var rdsCmd = &cobra.Command{
	Use:   "rds",
	Short: "Manage RDS-related operations",
}

func init() {
	rootCmd.AddCommand(rdsCmd)
}
