package cmd

import (
	"fmt"

	"otc-cli/formats"
	"otc-cli/services/cce"

	"github.com/opentelekomcloud/gophertelekomcloud/openstack/cce/v3/clusters"
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

func clustersTableView() formats.View[clusters.Clusters] {
	return formats.View[clusters.Clusters]{
		Columns: []formats.Column[clusters.Clusters]{
			formats.Col("ID", func(c clusters.Clusters) string {
				return c.Metadata.Id
			}),
			formats.Col("Name", func(c clusters.Clusters) string {
				return c.Metadata.Name
			}),
			formats.Col("Status", func(c clusters.Clusters) string {
				return c.Status.Phase
			}),
			formats.Col("Version", func(c clusters.Clusters) string {
				return c.Spec.Version
			}),
		},
	}
}
