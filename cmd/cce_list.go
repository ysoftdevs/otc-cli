package cmd

import (
	"fmt"

	"github.com/ysoftdevs/otc-cli/formats"
	"github.com/ysoftdevs/otc-cli/services/cce"

	"github.com/spf13/cobra"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List CCE clusters",
	Long:  `List all Cloud Container Engine (CCE) clusters in the specified region and project.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		clusters, err := cce.List(commonConfig)
		if err != nil {
			fmt.Printf("Error listing CCE clusters: %s\n", err)
			return err
		}

		return formats.PrintFormatted(format, clusters, clustersTableView())
	},
}

func init() {
	cceCmd.AddCommand(listCmd)
	initFlagFormat(listCmd)
}

func clustersTableView() formats.View[cce.Cluster] {
	return formats.View[cce.Cluster]{
		Columns: []formats.Column[cce.Cluster]{
			formats.Col("ID", func(c cce.Cluster) string {
				return c.Metadata.Id
			}),
			formats.Col("Name", func(c cce.Cluster) string {
				return c.Metadata.Name
			}),
			formats.Col("Status", func(c cce.Cluster) string {
				return c.Status.Phase
			}),
			formats.Col("Version", func(c cce.Cluster) string {
				return c.Spec.Version
			}),
			formats.Col("API Endpoint", func(c cce.Cluster) string {
				return c.APIEndpoint
			}),
		},
	}
}
