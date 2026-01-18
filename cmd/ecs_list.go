package cmd

import (
	"fmt"
	"time"

	"otc-cli/formats"
	"otc-cli/services/ecs"

	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/servers"
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
		servers, err := ecs.List(ecsListArgs)
		if err != nil {
			return err
		}
		return formats.PrintFormatted(format, servers, serversTableView())
	},
}

var ecsListArgs = ecs.ListArgs{
	Filter: "",
	Limit:  0,
}

func init() {
	ecsCmd.AddCommand(ecsListCmd)

	ecsListCmd.Flags().StringVar(&ecsListArgs.Filter, "filter", ecsListArgs.Filter, "Filter servers by name")
	ecsListCmd.Flags().IntVar(&ecsListArgs.Limit, "limit", ecsListArgs.Limit, "Limit the number of servers listed")
	ecsListCmd.Flags().StringVar(&format, "format", "table", "Output format: table, json, yaml")
}

func serversTableView() formats.View[servers.Server] {
	return formats.View[servers.Server]{
		Columns: []formats.Column[servers.Server]{
			formats.Col("ID", func(s servers.Server) string {
				return s.ID
			}),
			formats.Col("Name", func(s servers.Server) string {
				return s.Name
			}),
			formats.Col("Status", func(s servers.Server) string {
				return s.Status
			}),
			formats.Col("Flavor", func(s servers.Server) string {
				return s.Flavor["id"].(string)
			}),
			formats.Col("Image", func(s servers.Server) string {
				return s.Image["id"].(string)
			}),
			formats.Col("Created At", func(s servers.Server) time.Time {
				return s.Created
			}, formats.Time[servers.Server](time.RFC3339)),
		},
	}
}
