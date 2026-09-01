package cmd

import (
	"fmt"

	"github.com/ysoftdevs/otc-cli/formats"
	"github.com/ysoftdevs/otc-cli/services/elb"

	"github.com/spf13/cobra"
)

var elbModifyDeletionProtectionEnabled bool

var elbModifyCmd = &cobra.Command{
	Use:   "modify NAME",
	Short: "Modify attributes of an ELB load balancer",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if !cmd.Flags().Changed("deletion-protection-enabled") {
			return fmt.Errorf("specify at least one attribute to modify, e.g. --deletion-protection-enabled=false")
		}

		lb, err := elb.SetDeletionProtection(args[0], elbModifyDeletionProtectionEnabled, commonConfig)
		if err != nil {
			return err
		}
		return formats.PrintFormatted(format, []elb.LoadBalancerInfo{*lb}, elbTableView())
	},
}

func init() {
	elbCmd.AddCommand(elbModifyCmd)
	elbModifyCmd.Flags().BoolVar(&elbModifyDeletionProtectionEnabled, "deletion-protection-enabled", false, "Enable or disable deletion protection")
}
