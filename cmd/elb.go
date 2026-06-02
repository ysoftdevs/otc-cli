package cmd

import "github.com/spf13/cobra"

var elbCmd = &cobra.Command{
	Use:   "elb",
	Short: "Elastic Load Balancer (ELB) management",
}

func init() {
	rootCmd.AddCommand(elbCmd)
}
