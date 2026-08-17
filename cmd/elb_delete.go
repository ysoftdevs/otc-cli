package cmd

import (
	"fmt"

	"github.com/ysoftdevs/otc-cli/services/elb"

	"github.com/spf13/cobra"
)

var elbDeleteCmd = &cobra.Command{
	Use:   "delete NAME",
	Short: "Delete an ELB load balancer",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := elb.Delete(args[0], commonConfig); err != nil {
			return err
		}
		fmt.Printf("Load balancer %q deleted\n", args[0])
		return nil
	},
}

func init() {
	elbCmd.AddCommand(elbDeleteCmd)
}
