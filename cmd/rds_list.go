package cmd

import (
	"otc-cli/formats"
	"otc-cli/services/rds"

	"github.com/opentelekomcloud/gophertelekomcloud/openstack/rds/v3/instances"
	"github.com/spf13/cobra"
)

var rdsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List RDS instances",
	RunE: func(cmd *cobra.Command, args []string) error {
		servers, err := rds.List(&rdsListArgs)
		if err != nil {
			return err
		}
		return formats.PrintFormatted(format, servers, rdsInstancesTableView())
	},
}

var rdsListArgs = rds.ListArgs{
	Opts:         &instances.ListOpts{},
	CommonConfig: commonConfig,
}

func init() {
	rdsCmd.AddCommand(rdsListCmd)

	rdsListCmd.Flags().StringVar(&rdsListArgs.Opts.Name, "filter", ecsListArgs.Filter, "Filter instances by name")
	rdsListCmd.Flags().IntVar(&rdsListArgs.Opts.Limit, "limit", ecsListArgs.Limit, "Limit the number of instances listed")
	initFlagFormat(rdsListCmd)
}

func rdsInstancesTableView() formats.View[instances.InstanceResponse] {
	return formats.View[instances.InstanceResponse]{
		Columns: []formats.Column[instances.InstanceResponse]{
			formats.Col("ID", func(i instances.InstanceResponse) string {
				return i.Id
			}),
			formats.Col("Name", func(i instances.InstanceResponse) string {
				return i.Name
			}),
			formats.Col("Status", func(i instances.InstanceResponse) string {
				return i.Status
			}),
			formats.Col("Datastore Type", func(i instances.InstanceResponse) string {
				return i.DataStore.Type
			}),
			formats.Col("Datastore Version", func(i instances.InstanceResponse) string {
				return i.DataStore.Version
			}),
		},
	}
}
