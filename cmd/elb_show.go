package cmd

import (
	"github.com/ysoftdevs/otc-cli/formats"
	"github.com/ysoftdevs/otc-cli/services/elb"

	"github.com/spf13/cobra"
)

var elbShowCmd = &cobra.Command{
	Use:   "show NAME",
	Short: "Show a single ELB load balancer by name",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		lb, err := elb.Show(args[0], commonConfig)
		if err != nil {
			return err
		}
		return formats.PrintFormatted(format, []elb.LoadBalancerInfo{*lb}, elbTableView())
	},
}

func init() {
	elbCmd.AddCommand(elbShowCmd)
}
