package cmd

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ysoftdevs/otc-cli/formats"
	"github.com/ysoftdevs/otc-cli/services/ecs"

	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/servers"
	"github.com/spf13/cobra"
)

var ecsShowCmd = &cobra.Command{
	Use:   "show NAME",
	Short: "Show a single ECS server by name",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		server, err := ecs.Show(args[0], commonConfig)
		if err != nil {
			return err
		}
		return formats.PrintFormatted(format, []servers.Server{*server}, ecsShowTableView())
	},
}

func init() {
	ecsCmd.AddCommand(ecsShowCmd)
}

func extractAddresses(raw map[string]interface{}) string {
	// re-marshal and unmarshal into typed map to handle the interface{} values
	data, err := json.Marshal(raw)
	if err != nil {
		return ""
	}
	var typed map[string][]servers.Address
	if err := json.Unmarshal(data, &typed); err != nil {
		return ""
	}
	var parts []string
	for network, addrs := range typed {
		for _, a := range addrs {
			parts = append(parts, fmt.Sprintf("%s:%s", network, a.Address))
		}
	}
	return strings.Join(parts, ", ")
}

func ecsShowTableView() formats.View[servers.Server] {
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
				if id, ok := s.Flavor["id"].(string); ok {
					return id
				}
				return ""
			}),
			formats.Col("Key Name", func(s servers.Server) string {
				return s.KeyName
			}),
			formats.Col("Addresses", func(s servers.Server) string {
				return extractAddresses(s.Addresses)
			}),
			formats.Col("Security Groups", func(s servers.Server) string {
				names := make([]string, 0, len(s.SecurityGroups))
				for _, sg := range s.SecurityGroups {
					if name, ok := sg["name"].(string); ok {
						names = append(names, name)
					}
				}
				return strings.Join(names, ", ")
			}),
			formats.Col("Created At", func(s servers.Server) time.Time {
				return s.Created
			}, formats.Time[servers.Server](time.RFC3339)),
		},
	}
}
