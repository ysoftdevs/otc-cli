package cmd

import (
	"github.com/spf13/cobra"
)

// cceCmd represents the cce command
var cceCmd = &cobra.Command{
	Use:   "cce",
	Short: "Cloud Container Engine (CCE) management",
	Long: ``,
}

func init() {
	rootCmd.AddCommand(cceCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// cceCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// cceCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
