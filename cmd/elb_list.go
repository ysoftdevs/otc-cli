package cmd

import (
	"github.com/ysoftdevs/otc-cli/formats"
	"github.com/ysoftdevs/otc-cli/services/elb"

	"github.com/spf13/cobra"
)

var elbListCmd = &cobra.Command{
	Use:   "list",
	Short: "List ELB load balancers",
	RunE: func(cmd *cobra.Command, args []string) error {
		lbs, err := elb.List(elbListArgs)
		if err != nil {
			return err
		}
		return formats.PrintFormatted(format, lbs, elbTableView())
	},
}

var elbListArgs = elb.ListArgs{
	CommonConfig: commonConfig,
}

func init() {
	elbCmd.AddCommand(elbListCmd)
	elbListCmd.Flags().StringVar(&elbListArgs.Filter, "filter", "", "Filter load balancers by name")
	initFlagFormat(elbListCmd)
}

func elbTableView() formats.View[elb.LoadBalancerInfo] {
	return formats.View[elb.LoadBalancerInfo]{
		Columns: []formats.Column[elb.LoadBalancerInfo]{
			formats.Col("ID", func(lb elb.LoadBalancerInfo) string {
				return lb.ID
			}),
			formats.Col("Name", func(lb elb.LoadBalancerInfo) string {
				return lb.Name
			}),
			formats.Col("Status", func(lb elb.LoadBalancerInfo) string {
				return lb.Status
			}),
			formats.Col("VIP Address", func(lb elb.LoadBalancerInfo) string {
				return lb.VipAddress
			}),
			formats.Col("Public IPs", func(lb elb.LoadBalancerInfo) string {
				return elb.PublicIPsString(lb)
			}),
		},
	}
}
