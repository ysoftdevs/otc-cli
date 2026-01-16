package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List CCE clusters",
	Long: `List all Cloud Container Engine (CCE) clusters in the specified region.`,
	Run: func(cmd *cobra.Command, args []string) {
		commonConfig, err := ParseGlobalFlags()
		
		if err != nil {
			fmt.Printf("Error parsing global flags: %s\n", err)
			return
		}
		if err := runCCEList(&commonConfig, args); err != nil {
			fmt.Printf("Error listing CCE clusters: %s\n", err)
		}
	},
}

func init() {
	cceCmd.AddCommand(listCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// listCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// listCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
